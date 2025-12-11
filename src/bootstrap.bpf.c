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

// 调试宏：严格限制参数数量，防止编译报错
// bpf_trace_printk 最多支持 3 个参数 (fmt + arg1 + arg2 + arg3)
#define log0(fmt) ({ char _fmt[] = fmt; bpf_trace_printk(_fmt, sizeof(_fmt)); })
#define log1(fmt, v1) ({ char _fmt[] = fmt; bpf_trace_printk(_fmt, sizeof(_fmt), v1); })
#define log2(fmt, v1, v2) ({ char _fmt[] = fmt; bpf_trace_printk(_fmt, sizeof(_fmt), v1, v2); })
#define log3(fmt, v1, v2, v3) ({ char _fmt[] = fmt; bpf_trace_printk(_fmt, sizeof(_fmt), v1, v2, v3); })

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
    log1("CSUM: Old Val=0x%x\n", bpf_ntohs(tcph->check));

    // 计算 diff
    __s64 diff = bpf_csum_diff(old_data, len, new_data, len, 0);
    
    // 打印 diff 的低 32 位和高 32 位 (模拟 64 位打印)
    log2("CSUM: Diff=%lld (Low32=%u)\n", diff, (__u32)diff);

    __u64 csum = bpf_ntohs(tcph->check);
    csum = ~csum & 0xffff;
    csum += diff;
    tcph->check = bpf_htons(csum_fold_helper(csum));
    
    log1("CSUM: New Val=0x%x\n", bpf_ntohs(tcph->check));
}

static __always_inline void print_hex_opts(void *data, void *data_end) {
    if (data + 12 <= data_end) {
        __u32 *w = data;
        log1("Hex 00-03: %08x\n", bpf_ntohl(w[0]));
        log1("Hex 04-07: %08x\n", bpf_ntohl(w[1]));
        log1("Hex 08-11: %08x\n", bpf_ntohl(w[2]));
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
    
    if (dst_port != 20020) return XDP_PASS;

    log0("\n=== HIT 20020 ===\n");
    
    // 打印包的关键 ID，方便和 tcpdump 对比
    log3("Seq: %u, Ack: %u, Win: %u\n", bpf_ntohl(tcph->seq), bpf_ntohl(tcph->ack_seq), bpf_ntohs(tcph->window));

    if (!bpf_map_lookup_elem(&ports_map, &tcph->dest)) {
        log0("Map: Miss\n");
    } else {
        log0("Map: Hit\n");
    }

    if (!tcph->syn) {
        log0("Not SYN\n");
        return XDP_PASS;
    }

    __u32 tcp_len = tcph->doff * 4;
    log1("Len: %d\n", tcp_len);

    if (tcp_len < 32) {
        log0("Short Header\n");
        return XDP_PASS;
    }

    // --- 打印 BEFORE ---
    void *opts_start = (void*)tcph + 20;
    log0("-- BEFORE --\n");
    print_hex_opts(opts_start, data_end);

    // --- 寻找 Timestamp ---
    __u32 opts_offset = ip_offset + ip_hdr_len + 20; 
    __u32 opts_len = tcp_len - 20;
    __u32 found_offset = 0;

    log0("Scanning Opts...\n");

    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if (opts_len < 2) break;
        void *opt_ptr = data + opts_offset;
        if (opt_ptr + 2 > data_end) break;
        
        __u8 kind = *(__u8*)opt_ptr;
        if (kind == TCPOPT_EOL) break;
        if (kind == TCPOPT_NOP) { opts_offset++; opts_len--; continue; }
        
        __u8 len = *(__u8*)(opt_ptr + 1);
        if (len < 2 || len > opts_len) break;
        
        // 打印每一个扫描到的选项
        log2("Idx %d: Kind=%d Len=%d\n", i, kind, len);

        if (kind == TCPOPT_TIMESTAMP && len == 10) {
            found_offset = opts_offset;
            log1("-> FOUND TS at offset %d\n", opts_offset);
            break;
        }
        opts_offset += len;
        opts_len -= len;
    }

    if (found_offset == 0) {
        log0("No TS Found!\n");
        return XDP_PASS;
    }

    // --- 执行替换 ---
    struct toa_replace_block block;
    block.kind = TCPOPT_TOA;
    block.len = TCPOLEN_TOA;
    block.port = tcph->source;
    block.ip = iph->saddr;
    block.nop1 = TCPOPT_NOP;
    block.nop2 = TCPOPT_NOP;

    void *toa_ptr = data + found_offset;
    if (toa_ptr + 10 > data_end) return XDP_PASS;

    __u8 old_data[10];
    __builtin_memcpy(old_data, toa_ptr, 10);
    __builtin_memcpy(toa_ptr, &block, sizeof(block));
    
    // --- 更新校验和 ---
    tcph = (void *)data + ip_offset + ip_hdr_len;
    if ((void*)tcph + sizeof(*tcph) <= data_end) {
         update_tcp_csum(tcph, old_data, &block, 10);
    }

    // --- 打印 AFTER ---
    tcph = (void *)data + ip_offset + ip_hdr_len;
    opts_start = (void*)tcph + 20;
    log0("-- AFTER --\n");
    print_hex_opts(opts_start, data_end);

    struct log_event event = {
        .src_ip = iph->saddr,
        .dst_ip = iph->daddr,
        .src_port = tcph->source,
        .dst_port = tcp_len
    };
    bpf_perf_event_output(ctx, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return XDP_PASS; 
}

char _license[] SEC("license") = "GPL";
