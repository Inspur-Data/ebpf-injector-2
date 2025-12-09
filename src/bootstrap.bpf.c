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
#define TCPOPT_TOA  254
#define TCPOLEN_TOA 8

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

struct toa_opt {
    __u8 kind;
    __u8 len;
    __be16 port;
    __be32 ip;
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
int tc_toa_injector(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;
    if (iph->protocol != IPPROTO_TCP) return TC_ACT_OK;

    if ((iph->ver_ihl & 0x0F) != 5) return TC_ACT_OK;

    struct tcphdr *tcph = (void *)iph + 20;
    if ((void *)(tcph + 1) > data_end) return TC_ACT_OK;
    
    __u16 target_port = bpf_ntohs(tcph->dest);
    __u8 *val = bpf_map_lookup_elem(&ports_map, &target_port);
    if (!val || *val == 0) return TC_ACT_OK;

    // 仅拦截 SYN 包 (SYN=1, ACK=0)
    if ((tcph->flags & 0x12) != 0x02) return TC_ACT_OK;

    // 支持带 Timestamp 的 TCP 头
    __u32 doff = (tcph->res1_doff & 0xF0) >> 4;
    if (doff != 5 && doff != 8) return TC_ACT_OK;
    __u32 tcp_len = doff * 4;

    // 构造 TOA
    struct toa_opt toa;
    toa.kind = TCPOPT_TOA;
    toa.len = TCPOLEN_TOA;
    toa.port = tcph->source;
    toa.ip = iph->saddr;

    // --- 1. 扩容 8 字节 ---
    if (bpf_skb_adjust_room(skb, TCPOLEN_TOA, BPF_ADJ_ROOM_NET, 0))
        return TC_ACT_SHOT;

    // --- 2. 搬运 TCP 头 ---
    // 旧位置: ETH(14) + IP(20) + GAP(8) = 42
    // 新位置: ETH(14) + IP(20) = 34
    unsigned char buf[40]; 

    if (tcp_len == 20) {
        if (bpf_skb_load_bytes(skb, 42, buf, 20)) return TC_ACT_SHOT;
        buf[12] = 0x70; // 5->7
        if (bpf_skb_store_bytes(skb, 34, buf, 20, 1)) return TC_ACT_SHOT;
    } else { // 32
        if (bpf_skb_load_bytes(skb, 42, buf, 32)) return TC_ACT_SHOT;
        buf[12] = 0xA0 | (buf[12] & 0x0F); // 8->10
        if (bpf_skb_store_bytes(skb, 34, buf, 32, 1)) return TC_ACT_SHOT;
    }

    // --- 3. 写入 TOA Option ---
    __u32 toa_offset = 34 + tcp_len;
    if (bpf_skb_store_bytes(skb, toa_offset, &toa, TCPOLEN_TOA, 1))
        return TC_ACT_SHOT;

    // --- 4. 修复 TCP 伪首部校验和 ---
    __u32 tcp_csum_off = 34 + 16; 
    __u32 old_tcp_seg_len = tcp_len; 
    __u32 new_tcp_seg_len = tcp_len + 8;
    __be32 old_csum = bpf_htons(old_tcp_seg_len);
    __be32 new_csum = bpf_htons(new_tcp_seg_len);

    if (bpf_l4_csum_replace(skb, tcp_csum_off, old_csum, new_csum, BPF_F_PSEUDO_HDR))
        return TC_ACT_SHOT;

    // --- ⚠️ 抓取最终结果 ⚠️ ---
    // 此时包已经改好了，我们重新读取前 64 字节
    // 包含 ETH(14) + IP(20) + TCP(28/40) + TOA(8)
    struct log_event event;
    __builtin_memset(&event, 0, sizeof(event));
    
    // 重新获取指针来读 IP (虽然 load_bytes 不需要指针，但我们要填 IP 字段)
    // 简单起见，直接从 toa 结构体填，或者不填 IP 也没事，主要看 Hex
    event.src_ip = toa.ip;
    event.src_port = toa.port;
    
    bpf_skb_load_bytes(skb, 0, event.payload, 64);
    bpf_perf_event_output(skb, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
