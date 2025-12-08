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

    // 只拦截 SYN 包
    if ((tcph->flags & 0x12) != 0x02) return TC_ACT_OK;

    __u32 doff = (tcph->res1_doff & 0xF0) >> 4;
    if (doff < 5 || doff > 15) return TC_ACT_OK;
    __u32 tcp_len = doff * 4;

    struct log_event event;
    __builtin_memset(&event, 0, sizeof(event));
    event.src_ip = iph->saddr;
    event.dst_ip = iph->daddr;
    event.src_port = tcph->source;
    event.dst_port = tcph->dest;
    bpf_perf_event_output(skb, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    struct pp_v2_header pp_hdr;
    __builtin_memset(&pp_hdr, 0, sizeof(pp_hdr));
    
    // 构造 PP Header
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

    // --- 1. 扩容 ---
    // 在 L3 (IP) 后面增加 12 字节
    // 此时包结构：[IP] [12字节空白] [TCP] [Data]
    if (bpf_skb_adjust_room(skb, sizeof(pp_hdr), BPF_ADJ_ROOM_NET, 0))
        return TC_ACT_SHOT;

    // --- 2. 搬运 TCP 头 (乾坤大挪移) ---
    // 现在的 TCP 头被挤到了: ETH_HLEN + IP_LEN + 12 的位置
    // 我们要把它搬回: ETH_HLEN + IP_LEN 的位置
    // 这样 12 字节的空白就会跑到 TCP 头后面去
    
    __u32 ip_len = ihl * 4;
    __u32 pp_len = sizeof(pp_hdr); // 12
    __u32 old_tcp_offset = ETH_HLEN + ip_len + pp_len;
    __u32 new_tcp_offset = ETH_HLEN + ip_len;
    
    // 使用临时 buffer 读取被挤跑的 TCP 头
    // 注意：这里最大支持 60 字节的 TCP 头，我们分段读取
    unsigned char tcp_buf[60];
    __builtin_memset(tcp_buf, 0, sizeof(tcp_buf));
    
    // 从偏移位置读取 TCP 头
    // 关键参数：0 表示不重新计算校验和 (因为我们只是搬运)
    if (bpf_skb_load_bytes(skb, old_tcp_offset, tcp_buf, tcp_len))
        return TC_ACT_SHOT;
        
    // 将 TCP 头写回正确的位置 (紧挨着 IP 头)
    if (bpf_skb_store_bytes(skb, new_tcp_offset, tcp_buf, tcp_len, 0))
        return TC_ACT_SHOT;

    // --- 3. 写入 Proxy Protocol ---
    // 现在空白在: ETH_HLEN + IP_LEN + TCP_LEN
    __u32 pp_offset = ETH_HLEN + ip_len + tcp_len;
    
    // 写入 PP Header，并更新 TCP 校验和！
    // ⚠️ BPF_F_RECOMPUTE_CSUM (1) 很重要
    if (bpf_skb_store_bytes(skb, pp_offset, &pp_hdr, sizeof(pp_hdr), 1))
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
