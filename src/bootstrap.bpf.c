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
#pragma unroll
    for (i = 0; i < 4; i++) {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline void update_tcp_csum(struct tcphdr *tcph, void *old_data, void *new_data, int len) {
    __s64 diff = bpf_csum_diff(old_data, len, new_data, len, 0);
    __u64 csum = bpf_ntohs(tcph->check);
    csum = ~csum & 0xffff;
    csum += diff;
    tcph->check = bpf_htons(csum_fold_helper(csum));
}

SEC("xdp")
int xdp_toa_injector(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct tcphdr *tcph;
    
    __u32 ip_offset, ip_hdr_len, tcp_hdr_len;
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
    // 简化 Verifier: 只处理标准 20 字节 IP 头
    if (ip_hdr_len != 20) return XDP_PASS;

    tcph = (void *)iph + 20;
    if ((void *)tcph + sizeof(*tcph) > data_end) return XDP_PASS;

    // 端口匹配 (双字节序 Map 保证命中)
    if (!bpf_map_lookup_elem(&ports_map, &tcph->dest)) return XDP_PASS;
    
    if (!(tcph->syn && !tcph->ack)) return XDP_PASS;

    tcp_hdr_len = tcph->doff * 4;
    if (tcp_hdr_len < 32 || tcp_hdr_len > 60) return XDP_PASS;

    source_ip = iph->saddr;
    dest_ip = iph->daddr;
    source_port = tcph->source;

    // --- 智能扫描 Timestamp 选项 ---
    // 我们的目标是找到 Kind=8, Len=10 的选项
    // 偏移量从 TCP 头(20) + 选项起始(0) 开始，相对于 data 的偏移是：
    // ip_offset + 20 + 20
    __u32 opts_offset = ip_offset + 40; 
    __u32 opts_len = tcp_hdr_len - 20;
    __u32 found_offset = 0;

    // 手动展开循环扫描 (Verifier 限制)
    // 假设选项最多 40 字节，我们扫描 10 次足够了 (每次跳过非目标选项)
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if (opts_len < 2) break; // 剩余长度不够

        void *opt_ptr = data + opts_offset;
        if (opt_ptr + 2 > data_end) break; // 越界保护

        __u8 kind = *(__u8*)opt_ptr;
        
        if (kind == TCPOPT_EOL) break;
        
        if (kind == TCPOPT_NOP) {
            opts_offset++;
            opts_len--;
            continue;
        }
        
        __u8 len = *(__u8*)(opt_ptr + 1);
        if (len < 2 || len > opts_len) break; // 格式错误

        // 找到了 Timestamp (Kind=8, Len=10)
        if (kind == TCPOPT_TIMESTAMP && len == 10) {
            found_offset = opts_offset;
            break;
        }

        opts_offset += len;
        opts_len -= len;
    }

    if (found_offset == 0) {
        // 没找到 Timestamp，无法安全注入，放行
        return XDP_PASS;
    }

    // --- 执行替换 ---
    struct toa_replace_block block;
    block.kind = TCPOPT_TOA;
    block.len = TCPOLEN_TOA;
    block.port = source_port;
    block.ip = source_ip;
    block.nop1 = TCPOPT_NOP;
    block.nop2 = TCPOPT_NOP;

    void *toa_ptr = data + found_offset;
    if (toa_ptr + 10 > data_end) return XDP_PASS;

    __u8 old_data[10];
    __builtin_memcpy(old_data, toa_ptr, 10);
    __builtin_memcpy(toa_ptr, &block, sizeof(block));
    
    // 重新获取 TCP 头指针用于校验和 (data 指针可能变了吗？没有 adjust_head 不会变，但为了逻辑严谨)
    void *tcph_ptr = (void*)data + ip_offset + 20;
    if (tcph_ptr + sizeof(struct tcphdr) <= data_end) {
         update_tcp_csum((struct tcphdr *)tcph_ptr, old_data, &block, 10);
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
