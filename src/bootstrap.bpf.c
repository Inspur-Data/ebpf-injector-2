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
#define TCPOPT_NOP 1 

struct toa_opt {
    __u8   kind;
    __u8   len;
    __be16 port;
    __be32 ip;
};

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
    __u64 csum = bpf_csum_diff(old_data, len, new_data, len, ~tcph->check);
    tcph->check = csum_fold_helper(csum);
}

SEC("xdp")
int xdp_toa_injector(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct tcphdr *tcph;
    
    __u32 ip_offset, ip_hdr_len, tcp_hdr_len, toa_offset;
    __u16 h_proto;
    __be32 source_ip, dest_ip;
    __be16 source_port;

    ip_offset = sizeof(*eth);
    if (data + ip_offset > data_end) return XDP_PASS;

    h_proto = eth->h_proto;
    if (h_proto == bpf_htons(ETH_P_8021Q)) {
        ip_offset += 4;
        if (data + ip_offset > data_end) return XDP_PASS;
        struct ethhdr *inner_eth = data + 4; 
        h_proto = inner_eth->h_proto;
    }

    if (h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;
    
    iph = data + ip_offset;
    if ((void *)iph + sizeof(*iph) > data_end) return XDP_PASS;
    if (iph->protocol != IPPROTO_TCP) return XDP_PASS;

    ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(*iph)) return XDP_PASS;

    tcph = (void *)iph + ip_hdr_len;
    if ((void *)tcph + sizeof(*tcph) > data_end) return XDP_PASS;

    // 端口匹配
    if (!bpf_map_lookup_elem(&ports_map, &tcph->dest)) return XDP_PASS;
    
    if (!(tcph->syn && !tcph->ack)) return XDP_PASS;

    tcp_hdr_len = tcph->doff * 4;
    // 确保有足够空间容纳标准选项 (MSS 4 + SACK 2 + TS 10 = 16字节选项 + 20字节头 = 36)
    if (tcp_hdr_len < 36) return XDP_PASS;

    source_ip = iph->saddr;
    dest_ip = iph->daddr;
    source_port = tcph->source;

    // --- 构造替换块 (10 字节) ---
    // [TOA (8 bytes)] + [NOP (1 byte)] + [NOP (1 byte)]
    // 这将完美替换掉 Timestamp 选项 (10 bytes)
    __u8 new_block[10];
    
    // 1. 填入 TOA
    struct toa_opt *toa = (struct toa_opt *)new_block;
    toa->kind = TCPOPT_TOA;
    toa->len = TCPOLEN_TOA;
    toa->port = source_port;
    toa->ip = source_ip;
    
    // 2. 填入 NOP 填充尾部
    new_block[8] = TCPOPT_NOP;
    new_block[9] = TCPOPT_NOP;

    // --- 修改点：计算偏移量 ---
    // 从 24 改为 26，跳过 MSS(4) 和 SACK(2)
    toa_offset = ip_offset + ip_hdr_len + 26; 
    
    // --- 边界检查 ---
    if (data + toa_offset + 10 > data_end) return XDP_PASS;

    // --- 读取旧数据 (10字节) ---
    __u8 old_data[10];
    __builtin_memcpy(old_data, data + toa_offset, 10);

    // --- 写入新数据 ---
    // 我们的操作不改变包长度，且在 XDP 线性区，直接写入
    if (data + toa_offset + 10 <= data_end) {
        __builtin_memcpy(data + toa_offset, new_block, 10);
        
        // --- 重新计算校验和 ---
        tcph = (void *)data + ip_offset + ip_hdr_len;
        if ((void*)tcph + sizeof(*tcph) <= data_end) {
             update_tcp_csum(tcph, old_data, new_block, 10);
        }
    }

    struct log_event event = {
        .src_ip = source_ip,
        .dst_ip = dest_ip,
        .src_port = source_port,
        .dst_port = tcp_hdr_len
    };
    bpf_perf_event_output(ctx, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return XDP_PASS; 
}

char _license[] SEC("license") = "GPL";
