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

    __u32 ihl = iph->ver_ihl & 0x0F;
    if (ihl < 5 || ihl > 15) return TC_ACT_OK;

    struct tcphdr *tcph = (void *)iph + (ihl * 4);
    if ((void *)(tcph + 1) > data_end) return TC_ACT_OK;
    
    __u16 target_port = bpf_ntohs(tcph->dest);
    __u8 *val = bpf_map_lookup_elem(&ports_map, &target_port);
    if (!val || *val == 0) return TC_ACT_OK;

    if ((tcph->flags & 0x12) != 0x02) return TC_ACT_OK;

    __u32 doff = (tcph->res1_doff & 0xF0) >> 4;
    if (doff < 5 || doff > 15) return TC_ACT_OK;
    __u32 tcp_len = doff * 4;

    // --- 保存原始信息 ---
    struct log_event event;
    __builtin_memset(&event, 0, sizeof(event));
    event.src_ip = iph->saddr;
    event.dst_ip = iph->daddr;
    event.src_port = tcph->source;
    event.dst_port = tcph->dest;
    bpf_perf_event_output(skb, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    // --- 准备 PP Header ---
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
    pp_hdr.addr.ipv4.src_addr = iph->saddr;
    pp_hdr.addr.ipv4.dst_addr = iph->daddr;
    pp_hdr.addr.ipv4.src_port = tcph->source;
    pp_hdr.addr.ipv4.dst_port = tcph->dest;

    // --- 步骤 1: 在 IP 后扩容 12 字节 ---
    // 原: [ETH][IP][TCP][Payload]
    // 后: [ETH][IP][12字节空隙][TCP][Payload]
    if (bpf_skb_adjust_room(skb, sizeof(pp_hdr), BPF_ADJ_ROOM_NET, 0))
        return TC_ACT_SHOT;

    // --- 步骤 2: 搬运 TCP 头 ---
    // 目标: [ETH][IP][TCP][12字节空隙][Payload]
    // 我们需要把 TCP 头从"空隙后"搬到"IP后"
    
    __u32 ip_len = ihl * 4;
    __u32 pp_len = sizeof(pp_hdr); // 12
    __u32 old_tcp_offset = ETH_HLEN + ip_len + pp_len;
    __u32 new_tcp_offset = ETH_HLEN + ip_len;
    
    unsigned char tcp_buf[60]; // 最大 TCP 头
    __builtin_memset(tcp_buf, 0, sizeof(tcp_buf));

    // 🌟 核心修复: 使用 switch 枚举所有可能的 TCP 长度
    // 这样 bpf_skb_load_bytes 的长度参数就是常量了，验证器就会放行
    switch (tcp_len) {
        case 20: 
            if (bpf_skb_load_bytes(skb, old_tcp_offset, tcp_buf, 20)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, new_tcp_offset, tcp_buf, 20, 0)) return TC_ACT_SHOT;
            break;
        case 24:
            if (bpf_skb_load_bytes(skb, old_tcp_offset, tcp_buf, 24)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, new_tcp_offset, tcp_buf, 24, 0)) return TC_ACT_SHOT;
            break;
        case 28:
            if (bpf_skb_load_bytes(skb, old_tcp_offset, tcp_buf, 28)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, new_tcp_offset, tcp_buf, 28, 0)) return TC_ACT_SHOT;
            break;
        case 32:
            if (bpf_skb_load_bytes(skb, old_tcp_offset, tcp_buf, 32)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, new_tcp_offset, tcp_buf, 32, 0)) return TC_ACT_SHOT;
            break;
        case 36:
            if (bpf_skb_load_bytes(skb, old_tcp_offset, tcp_buf, 36)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, new_tcp_offset, tcp_buf, 36, 0)) return TC_ACT_SHOT;
            break;
        case 40:
            if (bpf_skb_load_bytes(skb, old_tcp_offset, tcp_buf, 40)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, new_tcp_offset, tcp_buf, 40, 0)) return TC_ACT_SHOT;
            break;
        case 44:
            if (bpf_skb_load_bytes(skb, old_tcp_offset, tcp_buf, 44)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, new_tcp_offset, tcp_buf, 44, 0)) return TC_ACT_SHOT;
            break;
        case 48:
            if (bpf_skb_load_bytes(skb, old_tcp_offset, tcp_buf, 48)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, new_tcp_offset, tcp_buf, 48, 0)) return TC_ACT_SHOT;
            break;
        case 52:
            if (bpf_skb_load_bytes(skb, old_tcp_offset, tcp_buf, 52)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, new_tcp_offset, tcp_buf, 52, 0)) return TC_ACT_SHOT;
            break;
        case 56:
            if (bpf_skb_load_bytes(skb, old_tcp_offset, tcp_buf, 56)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, new_tcp_offset, tcp_buf, 56, 0)) return TC_ACT_SHOT;
            break;
        case 60:
            if (bpf_skb_load_bytes(skb, old_tcp_offset, tcp_buf, 60)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, new_tcp_offset, tcp_buf, 60, 0)) return TC_ACT_SHOT;
            break;
        default:
            // 异常长度，不做处理
            return TC_ACT_OK;
    }

    // --- 步骤 3: 填入 Proxy Protocol (并计算 TCP Checksum) ---
    // 空隙现在位于: ETH + IP + TCP
    __u32 pp_offset = ETH_HLEN + ip_len + tcp_len;
    if (bpf_skb_store_bytes(skb, pp_offset, &pp_hdr, sizeof(pp_hdr), 1))
        return TC_ACT_SHOT;

    // --- 步骤 4: 修复 IP 头 (Length & Checksum) ---
    // 重新获取指针
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    
    eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_SHOT;
    
    iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return TC_ACT_SHOT;

    __u16 old_len = bpf_ntohs(iph->tot_len);
    __u16 new_len = old_len + sizeof(pp_hdr);
    
    // 更新 IP 校验和 (关键！)
    __u32 csum_offset = ETH_HLEN + 10; // offsetof(struct iphdr, check)
    __be32 old_val_32 = bpf_htons(old_len);
    __be32 new_val_32 = bpf_htons(new_len);
    
    if (bpf_l3_csum_replace(skb, csum_offset, old_val_32, new_val_32, 2))
        return TC_ACT_SHOT;

    // 更新 IP 长度
    iph->tot_len = bpf_htons(new_len);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
