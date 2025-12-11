// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

#include "common.h"

#define ETH_P_8021Q 0x8100
#define TCPOPT_TOA 254
#define TCPOLEN_TOA 8

// 调试宏
#define bpf_debug(fmt, val) ({ char _fmt[] = fmt; bpf_trace_printk(_fmt, sizeof(_fmt), val); })

struct toa_opt { __u8 k; __u8 l; __be16 p; __be32 i; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65535); __type(key, __u16); __type(value, __u8); } ports_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY); __uint(key_size, sizeof(int)); __uint(value_size, sizeof(int)); } log_events SEC(".maps");

SEC("xdp")
int xdp_debug_verbose(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    
    if (data + sizeof(*eth) > data_end) return XDP_PASS;
    __u32 ip_offset = sizeof(*eth);
    if (eth->h_proto == bpf_htons(ETH_P_8021Q)) ip_offset += 4;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP) && eth->h_proto != bpf_htons(ETH_P_8021Q)) {
        // bpf_debug("Not IP: %x\n", bpf_ntohs(eth->h_proto)); 
        return XDP_PASS;
    }

    struct iphdr *iph = data + ip_offset;
    if ((void*)iph + sizeof(*iph) > data_end) return XDP_PASS;
    
    if (iph->protocol != IPPROTO_TCP) {
        // bpf_debug("Not TCP: %d\n", iph->protocol);
        return XDP_PASS;
    }

    __u32 ip_hdr_len = iph->ihl * 4;
    struct tcphdr *tcph = (void*)iph + ip_hdr_len;
    if ((void*)tcph + sizeof(*tcph) > data_end) return XDP_PASS;

    __u16 dst_port = bpf_ntohs(tcph->dest);
    
    // 只关心 20020
    if (dst_port == 20020) {
        bpf_debug("=== HIT Port 20020 ===\n", 0);
        
        // 检查 Map
        if (!bpf_map_lookup_elem(&ports_map, &tcph->dest)) {
            bpf_debug("Map lookup FAILED!\n", 0);
        } else {
            bpf_debug("Map lookup OK!\n", 0);
        }

        // 检查 SYN
        if (!tcph->syn) bpf_debug("Not SYN\n", 0);
        else bpf_debug("Is SYN\n", 0);

        // 检查长度
        __u32 tcp_len = tcph->doff * 4;
        bpf_debug("TCP Len: %d\n", tcp_len);
    }

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
