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
#define TCPOPT_EOL 0
#define TCPOPT_NOP 1
#define TCPOPT_TIMESTAMP 8
#define TCPOPT_TOA 254
#define TCPOLEN_TOA 8

#define bpf_debug(fmt, val) ({ char _fmt[] = fmt; bpf_trace_printk(_fmt, sizeof(_fmt), val); })
#define bpf_debug2(fmt, v1, v2) ({ char _fmt[] = fmt; bpf_trace_printk(_fmt, sizeof(_fmt), v1, v2); })

struct toa_replace_block {
    __u8   kind;
    __u8   len;
    __be16 port;
    __be32 ip;
    __u8   nop1;
    __u8   nop2;
} __attribute__((packed));

struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65535); __type(key, __u16); __type(value, __u8); } ports_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY); __uint(key_size, sizeof(int)); __uint(value_size, sizeof(int)); } log_events SEC(".maps");

static __always_inline __u16 csum_fold_helper(__u64 csum) {
    int i;
    for (i = 0; i < 4; i++) {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline void update_tcp_csum(struct tcphdr *tcph, void *old_data, void *new_data, int len) {
    bpf_debug("Old Csum: 0x%x\n", bpf_ntohs(tcph->check));
    __u64 csum = bpf_csum_diff(old_data, len, new_data, len, ~tcph->check);
    tcph->check = csum_fold_helper(csum);
    bpf_debug("New Csum: 0x%x\n", bpf_ntohs(tcph->check));
}

static __always_inline void print_hex_dump(void *data, void *data_end) {
    if (data + 12 <= data_end) {
        __u32 *w = data;
        bpf_debug("Dump 0-3: %08x\n", bpf_ntohl(w[0]));
        bpf_debug("Dump 4-7: %08x\n", bpf_ntohl(w[1]));
        bpf_debug("Dump 8-11: %08x\n", bpf_ntohl(w[2]));
    }
}

SEC("xdp")
int xdp_toa_injector(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    
    if (data + sizeof(*eth) > data_end) return XDP_PASS;
    __u32 ip_offset = sizeof(*eth);
    if (eth->h_proto == bpf_htons(ETH_P_8021Q)) ip_offset += 4;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP) && eth->h_proto != bpf_htons(ETH_P_8021Q)) return XDP_PASS;

    struct iphdr *iph = data + ip_offset;
    if ((void*)iph + sizeof(*iph) > data_end) return XDP_PASS;
    if (iph->protocol != IPPROTO_TCP) return XDP_PASS;

    __u32 ip_hdr_len = iph->ihl * 4;
    struct tcphdr *tcph = (void*)iph + ip_hdr_len;
    if ((void*)tcph + sizeof(*tcph) > data_end) return XDP_PASS;

    __u16 dst_port = bpf_ntohs(tcph->dest);
    // 调试过滤器：只看目标端口 > 10000 的，或者 SYN 包
    if (dst_port < 10000 && !tcph->syn) return XDP_PASS; 

    bpf_debug("=== NEW PKT Port %d ===\n", dst_port);
    
    __u32 tcp_hdr_len = tcph->doff * 4;
    if (tcp_hdr_len < 32) {
        bpf_debug("Short header: %d\n", tcp_hdr_len);
        return XDP_PASS;
    }

    void *opts_start = (void*)tcph + 20;
    print_hex_dump(opts_start, data_end);

    // 假设 Timestamp 在偏移 26
    __u32 target_offset = ip_offset + 20 + 26;
    void *target_ptr = data + target_offset;
    
    if (target_ptr + 2 > data_end) return XDP_PASS;
    
    __u8 kind = *(__u8*)target_ptr;
    __u8 len = *(__u8*)(target_ptr + 1);
    
    bpf_debug2("At Off 26: Kind=%d Len=%d\n", kind, len);

    // 只有当这里真的是 Timestamp (Kind=8, Len=10) 时才替换
    if (kind != TCPOPT_TIMESTAMP || len != 10) {
        bpf_debug("TS not at 26! Abort.\n", 0);
        return XDP_PASS;
    }

    bpf_debug("Injecting at 26...\n", 0);

    struct toa_replace_block block;
    block.kind = TCPOPT_TOA;
    block.len = TCPOLEN_TOA;
    block.port = tcph->source;
    block.ip = iph->saddr;
    block.nop1 = TCPOPT_NOP;
    block.nop2 = TCPOPT_NOP;

    if (target_ptr + 10 > data_end) return XDP_PASS;

    __u8 old_data[10];
    __builtin_memcpy(old_data, target_ptr, 10);
    __builtin_memcpy(target_ptr, &block, sizeof(block));
    
    tcph = (void *)data + ip_offset + ip_hdr_len;
    if ((void*)tcph + sizeof(*tcph) <= data_end) {
         upda
