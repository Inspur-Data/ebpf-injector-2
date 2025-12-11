// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>

#include "common.h"

#define ETH_P_8021Q 0x8100
#define TCPOPT_EOL 0
#define TCPOPT_NOP 1
#define TCPOPT_TIMESTAMP 8
#define TCPOPT_TOA 254
#define TCPOLEN_TOA 8

#define bpf_debug(fmt, val) ({ char _fmt[] = fmt; bpf_trace_printk(_fmt, sizeof(_fmt), val); })

struct toa_replace_block {
    __u8   kind;
    __u8   len;
    __be16 port;
    __be32 ip;
    __u8   nop1;
    __u8   nop2;
} __attribute__((packed));

struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65535); __type(key, __u16); __type(value, __u8); } ports_map SEC(".maps");

// 状态表：Key=源端口, Value=原始源IP
// 使用 LRU 以防爆满
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, 65535); __type(key, __u16); __type(value, __be32); } conn_map SEC(".maps");

struct { __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY); __uint(key_size, sizeof(int)); __uint(value_size, sizeof(int)); } log_events SEC(".maps");

// --- 程序 1: Ingress XDP (只记录，不修改) ---
SEC("xdp")
int xdp_ingress_record(struct xdp_md *ctx) {
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

    // 端口匹配
    if (!bpf_map_lookup_elem(&ports_map, &tcph->dest)) return XDP_PASS;
    
    // 只记录 SYN
    if (!tcph->syn) return XDP_PASS;

    // --- 记录原始 IP ---
    __u16 src_port = tcph->source;
    __be32 src_ip = iph->saddr;
    
    bpf_map_update_elem(&conn_map, &src_port, &src_ip, BPF_ANY);
    
    // 调试日志
    bpf_debug("[ING] Recorded Port: %d\n", bpf_ntohs(src_port));
    
    // 发送事件到用户态
    struct log_event event = {src_ip, 0, src_port, 11111}; 
    bpf_perf_event_output(ctx, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return XDP_PASS;
}

// --- 程序 2: Egress TC (负责注入) ---
SEC("tc")
int tc_egress_inject(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    
    if (data + sizeof(*eth) > data_end) return TC_ACT_OK;
    __u32 ip_offset = sizeof(*eth);
    if (eth->h_proto == bpf_htons(ETH_P_8021Q)) ip_offset += 4;
    
    struct iphdr *iph = data + ip_offset;
    if ((void*)iph + sizeof(*iph) > data_end) return TC_ACT_OK;
    if (iph->protocol != IPPROTO_TCP) return TC_ACT_OK;

    __u32 ip_hdr_len = iph->ihl * 4;
    struct tcphdr *tcph = (void*)iph + ip_hdr_len;
    if ((void*)tcph + sizeof(*tcph) > data_end) return TC_ACT_OK;

    // Egress 阶段，不查 ports_map (因为目标端口变了)，只查 SYN
    if (!tcph->syn) return TC_ACT_OK;

    // 查表：这个源端口是不是我们之前记录过的？
    __u16 src_port = tcph->source;
    __be32 *original_ip = bpf_map_lookup_elem(&conn_map, &src_port);
    
    if (!original_ip) {
        // bpf_debug("[EGR] Miss Port: %d\n", bpf_ntohs(src_port));
        return TC_ACT_OK;
    }

    bpf_debug("[EGR] Hit! Injecting...\n", 0);

    // --- 注入逻辑 (覆盖 Timestamp) ---
    __u32 tcp_len = tcph->doff * 4;
    if (tcp_len < 32) return TC_ACT_OK;

    __u32 opts_offset = ip_offset + ip_hdr_len + 20; 
    __u32 opts_len = tcp_len - 20;
    __u32 found_offset = 0;

    // 扫描 Timestamp (TC 中需要用 load_bytes)
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if (opts_len < 2) break;
        
        __u8 kind;
        bpf_skb_load_bytes(skb, opts_offset, &kind, 1);
        
        if (kind == TCPOPT_EOL) break;
        if (kind == TCPOPT_NOP) { opts_offset++; opts_len--; continue; }
        
        __u8 len;
        bpf_skb_load_bytes(skb, opts_offset + 1, &len, 1);
        
        if (len < 2 || len > opts_len) break;
        
        if (kind == TCPOPT_TIMESTAMP && len == 10) {
            found_offset = opts_offset;
            break;
        }
        opts_offset += len;
        opts_len -= len;
    }

    if (found_offset == 0) return TC_ACT_OK;

    // 构造数据
    struct toa_replace_block block;
    block.kind = TCPOPT_TOA;
    block.len = TCPOLEN_TOA;
    block.port = src_port;
    block.ip = *original_ip; // 使用查到的原始 IP
    block.nop1 = TCPOPT_NOP;
    block.nop2 = TCPOPT_NOP;

    // 写入 (TC 自动处理校验和)
    if (bpf_skb_store_bytes(skb, found_offset, &block, 10, BPF_F_RECOMPUTE_CSUM) < 0) {
        bpf_debug("[EGR] Write Failed!\n", 0);
        return TC_ACT_SHOT;
    }

    // 发送成功事件
    struct log_event event = {*original_ip, iph->daddr, src_port, 22222};
    bpf_perf_event_output(skb, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
