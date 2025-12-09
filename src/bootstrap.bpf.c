// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

#define ETH_P_IP 0x0800
#define ETH_P_8021Q 0x8100
#define IPPROTO_TCP 6
#define ETH_HLEN 14
#define VLAN_HLEN 4
#define TCPOPT_TOA 254
#define TCPOLEN_TOA 8

struct ethhdr { unsigned char h_dest[6]; unsigned char h_source[6]; __be16 h_proto; };
struct iphdr { __u8 ver_ihl; __u8 tos; __be16 tot_len; __be16 id; __be16 frag_off; __u8 ttl; __u8 protocol; __u16 check; __be32 saddr; __be32 daddr; };
struct tcphdr { __be16 source; __be16 dest; __be32 seq; __be32 ack_seq; __u8 res1_doff; __u8 flags; __be16 window; __u16 check; __u16 urg_ptr; };
struct toa_opt { __u8 kind; __u8 len; __be16 port; __be32 ip; };

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, __u16);
    __type(value, __u8);
    __uint(map_flags, 0);
} ports_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 128);
    __uint(map_flags, 0);
} log_events SEC(".maps");

SEC("tc")
int tc_toa_injector(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;

    // --- 1. 动态 VLAN 探测 (兼容 NO 和 YES) ---
    __u32 l3_offset = ETH_HLEN; // 默认 14
    
    if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
        // 如果协议号是 VLAN，检查是否被 Offload
        __u8 *next_byte = (void *)(eth + 1);
        if ((void *)(next_byte + 1) > data_end) return TC_ACT_OK;
        
        // 如果下一字节不是 IP 头(0x45)，说明存在 VLAN 标签
        if (*next_byte != 0x45) {
            l3_offset += VLAN_HLEN; // 18
        }
    } else if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    struct iphdr *iph = (void *)((char *)data + l3_offset);
    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;
    
    // 严格校验 IPv4
    if ((iph->ver_ihl & 0xF0) != 0x40) return TC_ACT_OK;
    if (iph->protocol != IPPROTO_TCP) return TC_ACT_OK;
    if ((iph->ver_ihl & 0x0F) != 5) return TC_ACT_OK;

    struct tcphdr *tcph = (void *)iph + 20;
    if ((void *)(tcph + 1) > data_end) return TC_ACT_OK;
    
    __u16 target_port = bpf_ntohs(tcph->dest);
    __u8 *val = bpf_map_lookup_elem(&ports_map, &target_port);
    if (!val || *val == 0) return TC_ACT_OK;

    // --- 2. 状态过滤 ---
    // 只有 SYN (0x02) 才注入
    // 其他包 (ACK, PSH) 直接放行，这正是你看到 flags 变来变去的原因
    if ((tcph->flags & 0x12) != 0x02) return TC_ACT_OK;

    // --- 3. 长度适配 (支持 20, 24, 28, 32, 40) ---
    __u32 doff = (tcph->res1_doff & 0xF0) >> 4;
    __u32 tcp_len = doff * 4;
    
    // 如果长度太离谱，放行
    if (tcp_len < 20 || tcp_len > 60) return TC_ACT_OK;

    __u16 old_ip_tot_len = bpf_ntohs(iph->tot_len);

    // 发送成功拦截日志
    struct log_event event;
    __builtin_memset(&event, 0, sizeof(event));
    event.src_ip = iph->saddr;
    event.dst_ip = iph->daddr;
    event.src_port = tcph->source;
    event.dst_port = tcph->dest; 
    bpf_perf_event_output(skb, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    struct toa_opt toa;
    toa.kind = TCPOPT_TOA;
    toa.len = TCPOLEN_TOA;
    toa.port = tcph->source;
    toa.ip = iph->saddr;

    // --- 4. 执行注入 ---
    if (bpf_skb_adjust_room(skb, TCPOLEN_TOA, BPF_ADJ_ROOM_NET, 0))
        return TC_ACT_SHOT;

    // 基准偏移量使用 l3_offset (动态的)
    __u32 base = l3_offset; 
    __u32 old_tcp_off = base + 20 + 8;
    __u32 new_tcp_off = base + 20;
    
    unsigned char buf[60];

    // ⚠️ 覆盖你遇到的所有长度情况
    switch (tcp_len) {
        case 20: // 标准
            if (bpf_skb_load_bytes(skb, old_tcp_off, buf, 20)) return TC_ACT_SHOT;
            buf[12] = 0x70; // 5->7
            if (bpf_skb_store_bytes(skb, new_tcp_off, buf, 20, 1)) return TC_ACT_SHOT;
            break;
        case 28: // MSS + SACK (你之前遇到的!)
            if (bpf_skb_load_bytes(skb, old_tcp_off, buf, 28)) return TC_ACT_SHOT;
            buf[12] = 0x90 | (buf[12] & 0x0F); // 7->9 (0x70 -> 0x90)
            if (bpf_skb_store_bytes(skb, new_tcp_off, buf, 28, 1)) return TC_ACT_SHOT;
            break;
        case 32: // Timestamp (你刚刚遇到的!)
            if (bpf_skb_load_bytes(skb, old_tcp_off, buf, 32)) return TC_ACT_SHOT;
            buf[12] = 0xA0 | (buf[12] & 0x0F); // 8->10 (0x80 -> 0xA0)
            if (bpf_skb_store_bytes(skb, new_tcp_off, buf, 32, 1)) return TC_ACT_SHOT;
            break;
        case 24:
            if (bpf_skb_load_bytes(skb, old_tcp_off, buf, 24)) return TC_ACT_SHOT;
            buf[12] = 0x80 | (buf[12] & 0x0F);
            if (bpf_skb_store_bytes(skb, new_tcp_off, buf, 24, 1)) return TC_ACT_SHOT;
            break;
        case 40:
            if (bpf_skb_load_bytes(skb, old_tcp_off, buf, 40)) return TC_ACT_SHOT;
            buf[12] = 0xC0 | (buf[12] & 0x0F);
            if (bpf_skb_store_bytes(skb, new_tcp_off, buf, 40, 1)) return TC_ACT_SHOT;
            break;
        case 44:
            if (bpf_skb_load_bytes(skb, old_tcp_off, buf, 44)) return TC_ACT_SHOT;
            buf[12] = 0xD0 | (buf[12] & 0x0F);
            if (bpf_skb_store_bytes(skb, new_tcp_off, buf, 44, 1)) return TC_ACT_SHOT;
            break;
        default:
            return TC_ACT_OK;
    }

    // 写入 TOA
    __u32 toa_offset = base + 20 + tcp_len;
    if (bpf_skb_store_bytes(skb, toa_offset, &toa, TCPOLEN_TOA, 1))
        return TC_ACT_SHOT;

    // 修复 IP 头
    __u16 new_len = old_ip_tot_len + 8;
    __be32 old_l = bpf_htons(old_ip_tot_len);
    __be32 new_l = bpf_htons(new_len);
    
    if (bpf_l3_csum_replace(skb, base + 10, old_l, new_l, 2)) return TC_ACT_SHOT;
    __be16 new_len_be = bpf_htons(new_len);
    if (bpf_skb_store_bytes(skb, base + 2, &new_len_be, 2, 0)) return TC_ACT_SHOT;

    // 修复 TCP 伪首部
    __u32 tcp_csum_off = base + 20 + 16; 
    __u32 old_tcp_seg = tcp_len;
    __u32 new_tcp_seg = tcp_len + 8;
    __be32 old_csum = bpf_htons(old_tcp_seg);
    __be32 new_csum = bpf_htons(new_tcp_seg);

    if (bpf_l4_csum_replace(skb, tcp_csum_off, old_csum, new_csum, BPF_F_PSEUDO_HDR))
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
