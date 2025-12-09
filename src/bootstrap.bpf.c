// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define ETH_HLEN 14
#define TCPOLEN_TOA 8
#define TCPOPT_TOA 254

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
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    // ⚠️ 坚定不移：IP 头就在 Offset 14
    struct iphdr *iph = (void *)((char *)data + ETH_HLEN);
    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;
    
    // 再次确认：这真的是 IP 头吗？
    if ((iph->ver_ihl & 0xF0) != 0x40) return TC_ACT_OK; // 不是 IPv4，放行
    if (iph->protocol != IPPROTO_TCP) return TC_ACT_OK;
    if ((iph->ver_ihl & 0x0F) != 5) return TC_ACT_OK; // 只支持标准 IP 头

    struct tcphdr *tcph = (void *)iph + 20;
    if ((void *)(tcph + 1) > data_end) return TC_ACT_OK;
    
    __u16 target_port = bpf_ntohs(tcph->dest);
    __u8 *val = bpf_map_lookup_elem(&ports_map, &target_port);
    if (!val || *val == 0) return TC_ACT_OK;

    // 只处理 SYN
    if ((tcph->flags & 0x12) != 0x02) return TC_ACT_OK;

    __u32 doff = (tcph->res1_doff & 0xF0) >> 4;
    __u32 tcp_len = doff * 4;
    
    // 只处理我们可以安全搬运的长度
    if (tcp_len != 20 && tcp_len != 28 && tcp_len != 32 && tcp_len != 40) 
        return TC_ACT_OK;

    __u16 old_ip_tot_len = bpf_ntohs(iph->tot_len);

    // 准备日志
    struct log_event event;
    __builtin_memset(&event, 0, sizeof(event));
    event.src_ip = iph->saddr;
    event.dst_ip = iph->daddr;
    event.src_port = tcph->source;
    event.dst_port = tcp_len; // 记录 TCP 长度，方便排查
    bpf_perf_event_output(skb, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    struct toa_opt toa;
    toa.kind = TCPOPT_TOA;
    toa.len = TCPOLEN_TOA;
    toa.port = tcph->source;
    toa.ip = iph->saddr;

    // --- 1. 扩容 ---
    if (bpf_skb_adjust_room(skb, TCPOLEN_TOA, BPF_ADJ_ROOM_NET, 0))
        return TC_ACT_SHOT;

    // --- 2. 搬运 TCP 头 ---
    // 此时结构: [ETH 14] [IP 20] [GAP 8] [TCP LEN]
    // 目标:     [ETH 14] [IP 20] [TCP LEN] [GAP 8]
    // 我们要把 TCP 头搬到 IP 头紧后面
    
    __u32 base = ETH_HLEN; // 14
    __u32 old_tcp_off = base + 20 + 8;
    __u32 new_tcp_off = base + 20;
    unsigned char buf[60];

    // 分情况搬运，并在搬运时修改 Data Offset
    if (tcp_len == 20) {
        if (bpf_skb_load_bytes(skb, old_tcp_off, buf, 20)) return TC_ACT_SHOT;
        buf[12] = 0x70; // 5->7
        if (bpf_skb_store_bytes(skb, new_tcp_off, buf, 20, 1)) return TC_ACT_SHOT;
    } else if (tcp_len == 28) { // 你的情况
        if (bpf_skb_load_bytes(skb, old_tcp_off, buf, 28)) return TC_ACT_SHOT;
        buf[12] = 0x90 | (buf[12] & 0x0F); // 7->9
        if (bpf_skb_store_bytes(skb, new_tcp_off, buf, 28, 1)) return TC_ACT_SHOT;
    } else if (tcp_len == 32) {
        if (bpf_skb_load_bytes(skb, old_tcp_off, buf, 32)) return TC_ACT_SHOT;
        buf[12] = 0xA0 | (buf[12] & 0x0F); // 8->10
        if (bpf_skb_store_bytes(skb, new_tcp_off, buf, 32, 1)) return TC_ACT_SHOT;
    } else if (tcp_len == 40) {
        if (bpf_skb_load_bytes(skb, old_tcp_off, buf, 40)) return TC_ACT_SHOT;
        buf[12] = 0xC0 | (buf[12] & 0x0F); // 10->12
        if (bpf_skb_store_bytes(skb, new_tcp_off, buf, 40, 1)) return TC_ACT_SHOT;
    }

    // --- 3. 写入 TOA ---
    // 位置: 14 + 20 + tcp_len
    if (bpf_skb_store_bytes(skb, base + 20 + tcp_len, &toa, 8, 1))
        return TC_ACT_SHOT;

    // --- 4. 修复 IP 头 ---
    __u16 new_len = old_ip_tot_len + 8;
    __be32 old_l = bpf_htons(old_ip_tot_len);
    __be32 new_l = bpf_htons(new_len);
    
    if (bpf_l3_csum_replace(skb, base + 10, old_l, new_l, 2)) return TC_ACT_SHOT;
    __be16 new_len_be = bpf_htons(new_len);
    if (bpf_skb_store_bytes(skb, base + 2, &new_len_be, 2, 0)) return TC_ACT_SHOT;

    // --- 5. 修复 TCP 校验和 ---
    __u32 tcp_csum_off = base + 20 + 16; 
    __be32 old_csum = bpf_htons(tcp_len);
    __be32 new_csum = bpf_htons(tcp_len + 8);

    if (bpf_l4_csum_replace(skb, tcp_csum_off, old_csum, new_csum, BPF_F_PSEUDO_HDR))
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
