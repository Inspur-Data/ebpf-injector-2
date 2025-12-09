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

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 128);
    __uint(map_flags, 0);
} log_events SEC(".maps");

// 占位
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u16);
    __type(value, __u8);
    __uint(map_flags, 0);
} ports_map SEC(".maps");

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

    // 计算 IP 头长度
    __u32 ihl = iph->ver_ihl & 0x0F;
    // 计算 TCP 头位置
    struct tcphdr *tcph = (void *)iph + (ihl * 4);
    if ((void *)(tcph + 1) > data_end) return TC_ACT_OK;
    
    // ⚠️ 侦探逻辑：打印端口 ⚠️
    // 我们分别打印网络字节序 (Raw) 和主机字节序 (ntohs)
    
    struct log_event event;
    __builtin_memset(&event, 0, sizeof(event));
    
    event.src_ip = iph->saddr;
    event.dst_ip = iph->daddr;
    
    // src_port 放 Raw Port (网络字节序)
    event.src_port = tcph->dest; 
    // dst_port 放 Host Port (主机字节序)
    event.dst_port = bpf_ntohs(tcph->dest);

    // 无论什么端口，只要是 TCP 就打印！
    // 这样我们能在日志里搜 "32499" 或者是它的十六进制 "7EF3"
    bpf_perf_event_output(skb, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
