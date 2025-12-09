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
#define TCPOLEN_TOA 8
#define TCPOPT_TOA 254

// ... (结构体定义保持不变) ...
struct ethhdr { unsigned char h_dest[6]; unsigned char h_source[6]; __be16 h_proto; };
struct iphdr { __u8 ver_ihl; __u8 tos; __be16 tot_len; __be16 id; __be16 frag_off; __u8 ttl; __u8 protocol; __u16 check; __be32 saddr; __be32 daddr; };
struct tcphdr { __be16 source; __be16 dest; __be32 seq; __be32 ack_seq; __u8 res1_doff; __u8 flags; __be16 window; __u16 check; __u16 urg_ptr; };
struct toa_opt { __u8 kind; __u8 len; __be16 port; __be32 ip; };

// Map 强制 flags=0
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

    // --- VLAN 判定 (不使用指针比较，防止 rodata) ---
    __u32 l3_offset = ETH_HLEN;
    
    // 如果是 802.1Q (VLAN)
    if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
        // 读取 Offset 14 的字节 (预期是 IP 头)
        // 如果不是 0x45，那说明有 VLAN 标签
        unsigned char ip_ver_byte;
        if (bpf_skb_load_bytes(skb, 14, &ip_ver_byte, 1)) return TC_ACT_OK;
        
        if (ip_ver_byte != 0x45) {
            l3_offset = 18; // 14+4
        }
    } else if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    struct iphdr *iph = (void *)((char *)data + l3_offset);
    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;
    if (iph->protocol != IPPROTO_TCP) return TC_ACT_OK;
    if ((iph->ver_ihl & 0x0F) != 5) return TC_ACT_OK;

    struct tcphdr *tcph = (void *)iph + 20;
    if ((void *)(tcph + 1) > data_end) return TC_ACT_OK;
    
    __u16 target_port = bpf_ntohs(tcph->dest);
    __u8 *val = bpf_map_lookup_elem(&ports_map, &target_port);
    if (!val || *val == 0) return TC_ACT_OK;

    if ((tcph->flags & 0x12) != 0x02) return TC_ACT_OK;

    __u32 doff = (tcph->res1_doff & 0xF0) >> 4;
    __u32 tcp_len = doff * 4;
    
    // 范围检查
    if (tcp_len < 20 || tcp_len > 60) return TC_ACT_OK;

    __u16 old_ip_tot_len = bpf_ntohs(iph->tot_len);

    struct toa_opt toa;
    // 手动初始化，不用 memset 0，防止编译器优化成 rodata
    toa.kind = TCPOPT_TOA;
    toa.len = TCPOLEN_TOA;
    toa.port = tcph->source;
    toa.ip = iph->saddr;

    // --- 扩容 ---
    if (bpf_skb_adjust_room(skb, TCPOLEN_TOA, BPF_ADJ_ROOM_NET, 0))
        return TC_ACT_SHOT;

    // --- 搬运 TCP 头 ---
    // 改用 if-else，不用 switch，防止生成跳转表
    unsigned char buf[60];
    __u32 base = l3_offset; 
    __u32 old_tcp_off = base + 20 + 8;
    __u32 new_tcp_off = base + 20;

    // 分情况处理最常见的长度
    if (tcp_len == 20) {
        if (bpf_skb_load_bytes(skb, old_tcp_off, buf, 20)) return TC_ACT_SHOT;
        buf[12] = 0x70; 
        if (bpf_skb_store_bytes(skb, new_tcp_off, buf, 20, 1)) return TC_ACT_SHOT;
    } else if (tcp_len == 32) {
        if (bpf_skb_load_bytes(skb, old_tcp_off, buf, 32)) return TC_ACT_SHOT;
        buf[12] = 0xA0 | (buf[12] & 0x0F);
        if (bpf_skb_store_bytes(skb, new_tcp_off, buf, 32, 1)) return TC_ACT_SHOT;
    } else if (tcp_len == 28) {
        if (bpf_skb_load_bytes(skb, old_tcp_off, buf, 28)) return TC_ACT_SHOT;
        buf[12] = 0x90 | (buf[12] & 0x0F);
        if (bpf_skb_store_bytes(skb, new_tcp_off, buf, 28, 1)) return TC_ACT_SHOT;
    } else if (tcp_len == 40) {
        if (bpf_skb_load_bytes(skb, old_tcp_off, buf, 40)) return TC_ACT_SHOT;
        buf[12] = 0xC0 | (buf[12] & 0x0F);
        if (bpf_skb_store_bytes(skb, new_tcp_off, buf, 40, 1)) return TC_ACT_SHOT;
    } else {
        // 其他不常见的，放行
        return TC_ACT_OK;
    }

    // --- 写入 TOA ---
    if (bpf_skb_store_bytes(skb, base + 20 + tcp_len, &toa, 8, 1))
        return TC_ACT_SHOT;

    // --- 修复 IP 头 ---
    __u16 new_len = old_ip_tot_len + 8;
    __be32 old_l = bpf_htons(old_ip_tot_len);
    __be32 new_l = bpf_htons(new_len);
    
    if (bpf_l3_csum_replace(skb, base + 10, old_l, new_l, 2)) return TC_ACT_SHOT;
    __be16 new_len_be = bpf_htons(new_len);
    if (bpf_skb_store_bytes(skb, base + 2, &new_len_be, 2, 0)) return TC_ACT_SHOT;

    // --- 修复 TCP 校验和 ---
    __u32 tcp_csum_off = base + 20 + 16; 
    __be32 old_csum = bpf_htons(tcp_len);
    __be32 new_csum = bpf_htons(tcp_len + 8);

    if (bpf_l4_csum_replace(skb, tcp_csum_off, old_csum, new_csum, BPF_F_PSEUDO_HDR))
        return TC_ACT_SHOT;

    // --- 简单日志 ---
    struct log_event event;
    event.src_ip = toa.ip;
    event.dst_ip = 0;
    event.src_port = toa.port;
    event.dst_port = tcp_len;
    bpf_perf_event_output(skb, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
