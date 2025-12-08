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

struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16 h_proto;
};

struct iphdr {
    __u8 ver_ihl;
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __u16 check;
    __be32 saddr;
    __be32 daddr;
};

struct tcphdr {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u8 res1_doff;
    __u8 flags;
    __be16 window;
    __u16 check;
    __u16 urg_ptr;
};

struct pp_v2_header {
    __u8 sig[12];
    __u8 ver_cmd;
    __u8 fam;
    __be16 len;
    union {
        struct {
            __be32 src_addr;
            __be32 dst_addr;
            __be16 src_port;
            __be16 dst_port;
        } ipv4;
    } addr;
};

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
int tc_proxy_protocol(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;
    if (iph->protocol != IPPROTO_TCP) return TC_ACT_OK;

    // 仅支持标准 20 字节 IP 头，简化逻辑
    if ((iph->ver_ihl & 0x0F) != 5) return TC_ACT_OK;

    struct tcphdr *tcph = (void *)iph + 20;
    if ((void *)(tcph + 1) > data_end) return TC_ACT_OK;
    
    __u16 target_port = bpf_ntohs(tcph->dest);
    __u8 *val = bpf_map_lookup_elem(&ports_map, &target_port);
    if (!val || *val == 0) return TC_ACT_OK;

    // 仅注入 SYN 包 (SYN=1, ACK=0)
    if ((tcph->flags & 0x12) != 0x02) return TC_ACT_OK;

    // 提取 TCP Data Offset (Header Length)
    __u32 doff = (tcph->res1_doff & 0xF0) >> 4;
    if (doff < 5 || doff > 15) return TC_ACT_OK;
    __u32 tcp_len = doff * 4;

    // 保存必要信息 (因为 adjust_room 后指针失效)
    __u16 old_ip_len = bpf_ntohs(iph->tot_len);
    __be32 saddr = iph->saddr;
    __be32 daddr = iph->daddr;
    __be16 source = tcph->source;
    __be16 dest = tcph->dest;

    // 发送日志
    struct log_event event;
    __builtin_memset(&event, 0, sizeof(event));
    event.src_ip = saddr;
    event.dst_ip = daddr;
    event.src_port = source;
    event.dst_port = dest;
    bpf_perf_event_output(skb, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    // 构造 Proxy Protocol v2 头部
    struct pp_v2_header pp_hdr;
    __builtin_memset(&pp_hdr, 0, sizeof(pp_hdr));
    pp_hdr.sig[0] = 0x0D; pp_hdr.sig[1] = 0x0A;
    pp_hdr.sig[2] = 0x0D; pp_hdr.sig[3] = 0x0A;
    pp_hdr.sig[4] = 0x00; pp_hdr.sig[5] = 0x0D;
    pp_hdr.sig[6] = 0x0A; pp_hdr.sig[7] = 0x51;
    pp_hdr.sig[8] = 0x55; pp_hdr.sig[9] = 0x49;
    pp_hdr.sig[10] = 0x54; pp_hdr.sig[11] = 0x0A;
    pp_hdr.ver_cmd = 0x21;
    pp_hdr.fam     = 0x11;
    pp_hdr.len     = bpf_htons(12);
    pp_hdr.addr.ipv4.src_addr = saddr;
    pp_hdr.addr.ipv4.dst_addr = daddr;
    pp_hdr.addr.ipv4.src_port = source;
    pp_hdr.addr.ipv4.dst_port = dest;

    // --- 1. 扩容 12 字节 (在 IP 层之后) ---
    // 此时布局: [ETH][IP][GAP 12][TCP][Payload]
    if (bpf_skb_adjust_room(skb, 12, BPF_ADJ_ROOM_NET, 0))
        return TC_ACT_SHOT;

    // --- 2. 搬运 IP 头 (把 IP 头往前移，填补 GAP 的前部) ---
    // 目标布局: [ETH][IP][TCP][GAP 12][Payload]
    // 我们需要把 TCP 头往前移。但因为 adjust_room 是在 IP 后加的 gap，
    // 所以实际上是把 IP 头保持不动（逻辑上），而是把 TCP 头往前移？
    // 不，adjust_room(NET) 实际上是在 L3 header 之后插入。
    // 所以此时: [ETH] [IP] [GAP] [TCP]
    // 我们要变成: [ETH] [IP] [TCP] [GAP]
    
    // 这意味着我们需要把 TCP 头从 GAP 后面，搬运到 GAP 的位置。
    unsigned char buf[60];
    
    // 旧 TCP 位置: ETH(14) + IP(20) + GAP(12) = 46
    // 新 TCP 位置: ETH(14) + IP(20) = 34
    __u32 old_tcp_off = 46;
    __u32 new_tcp_off = 34;

    switch (tcp_len) {
        case 20:
            if (bpf_skb_load_bytes(skb, old_tcp_off, buf, 20)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, new_tcp_off, buf, 20, 0)) return TC_ACT_SHOT;
            break;
        case 24:
            if (bpf_skb_load_bytes(skb, old_tcp_off, buf, 24)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, new_tcp_off, buf, 24, 0)) return TC_ACT_SHOT;
            break;
        case 28:
            if (bpf_skb_load_bytes(skb, old_tcp_off, buf, 28)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, new_tcp_off, buf, 28, 0)) return TC_ACT_SHOT;
            break;
        case 32:
            if (bpf_skb_load_bytes(skb, old_tcp_off, buf, 32)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, new_tcp_off, buf, 32, 0)) return TC_ACT_SHOT;
            break;
        case 36:
            if (bpf_skb_load_bytes(skb, old_tcp_off, buf, 36)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, new_tcp_off, buf, 36, 0)) return TC_ACT_SHOT;
            break;
        case 40:
            if (bpf_skb_load_bytes(skb, old_tcp_off, buf, 40)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, new_tcp_off, buf, 40, 0)) return TC_ACT_SHOT;
            break;
        case 44:
            if (bpf_skb_load_bytes(skb, old_tcp_off, buf, 44)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, new_tcp_off, buf, 44, 0)) return TC_ACT_SHOT;
            break;
        case 48:
            if (bpf_skb_load_bytes(skb, old_tcp_off, buf, 48)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, new_tcp_off, buf, 48, 0)) return TC_ACT_SHOT;
            break;
        case 52:
            if (bpf_skb_load_bytes(skb, old_tcp_off, buf, 52)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, new_tcp_off, buf, 52, 0)) return TC_ACT_SHOT;
            break;
        case 56:
            if (bpf_skb_load_bytes(skb, old_tcp_off, buf, 56)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, new_tcp_off, buf, 56, 0)) return TC_ACT_SHOT;
            break;
        case 60:
            if (bpf_skb_load_bytes(skb, old_tcp_off, buf, 60)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, new_tcp_off, buf, 60, 0)) return TC_ACT_SHOT;
            break;
        default:
            // 遇到不支持的长度，直接放弃修改，防止破坏包结构
            // 但因为 adjust_room 已经生效，不处理包就废了。
            // 这是一个极端情况，我们选择放过，让它成为一个畸形包被丢弃，总比 crash 好
            return TC_ACT_OK;
    }

    // --- 3. 写入 PP Header (填补 TCP 移走后的空隙) ---
    // 位置: 14 + 20 + tcp_len
    __u32 pp_off = 34 + tcp_len;
    // ⚠️ 关键: BPF_F_RECOMPUTE_CSUM (1) 更新 TCP 数据部分的校验和
    if (bpf_skb_store_bytes(skb, pp_off, &pp_hdr, 12, 1)) 
        return TC_ACT_SHOT;

    // --- 4. 修复 IP 头部 ---
    // adjust_room 会自动更新 skb->len，但不会更新 IP 头里的 tot_len
    __u16 new_len = old_ip_len + 12;
    __be32 old_l = bpf_htons(old_ip_len);
    __be32 new_l = bpf_htons(new_len);
    
    // 更新 IP 校验和 (增量更新)
    // offset 24 = 14 + 10 (check)
    if (bpf_l3_csum_replace(skb, 24, old_l, new_l, 2))
        return TC_ACT_SHOT;

    // 更新 IP 长度
    // offset 16 = 14 + 2 (tot_len)
    __be16 new_len_be = bpf_htons(new_len);
    if (bpf_skb_store_bytes(skb, 16, &new_len_be, 2, 0))
        return TC_ACT_SHOT;

    // --- 5. 修复 TCP 伪首部校验和 ---
    // 这是导致丢包的关键！因为 IP 长度变了，TCP 伪首部校验和必须更新
    // TCP Checksum 位于 TCP 头偏移 16 字节处
    __u32 tcp_csum_off = 34 + 16; 
    
    __u32 old_tcp_seg_len = old_ip_len - 20;
    __u32 new_tcp_seg_len = old_tcp_seg_len + 12;

    __be32 old_csum_val = bpf_htons(old_tcp_seg_len);
    __be32 new_csum_val = bpf_htons(new_tcp_seg_len);

    // 更新 TCP 校验和
    if (bpf_l4_csum_replace(skb, tcp_csum_off, old_csum_val, new_csum_val, BPF_F_PSEUDO_HDR))
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
