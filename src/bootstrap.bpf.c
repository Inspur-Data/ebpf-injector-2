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

// 调试宏：简化打印
#define DEBUG_PRINT(fmt, ...) ({ char _fmt[] = fmt; bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__); })

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
        if (csum >> 16) csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline void update_tcp_csum(struct tcphdr *tcph, void *old_data, void *new_data, int len) {
    // 打印旧校验和
    DEBUG_PRINT("CSUM: Old=0x%x\n", bpf_ntohs(tcph->check));
    
    __u64 csum = bpf_csum_diff(old_data, len, new_data, len, ~tcph->check);
    tcph->check = csum_fold_helper(csum);
    
    // 打印新校验和
    DEBUG_PRINT("CSUM: New=0x%x\n", bpf_ntohs(tcph->check));
}

// 辅助函数：打印 12 字节的十六进制数据
static __always_inline void print_hex_dump(void *data, void *data_end, const char *prefix) {
    if (data + 12 <= data_end) {
        __u32 w1 = *(__u32*)data;
        __u32 w2 = *(__u32*)(data + 4);
        __u32 w3 = *(__u32*)(data + 8);
        // 注意：这里打印的是网络字节序，方便和 tcpdump -X 对比
        // 020405b4 = MSS 1460
        DEBUG_PRINT("%s: %08x %08x %08x\n", prefix, w1, w2, w3);
    }
}

SEC("xdp")
int xdp_ct_scan(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    
    // 1. 基础解析
    if (data + sizeof(*eth) > data_end) return XDP_PASS;
    __u32 ip_offset = sizeof(*eth);
    if (eth->h_proto == bpf_htons(ETH_P_8021Q)) ip_offset += 4;
    if (data + ip_offset > data_end) return XDP_PASS;
    
    struct iphdr *iph = data + ip_offset;
    if ((void*)iph + sizeof(*iph) > data_end) return XDP_PASS;
    if (iph->protocol != IPPROTO_TCP) return XDP_PASS;

    __u32 ip_hdr_len = iph->ihl * 4;
    struct tcphdr *tcph = (void*)iph + ip_hdr_len;
    if ((void*)tcph + sizeof(*tcph) > data_end) return XDP_PASS;

    // 2. 端口过滤 (减少日志噪音)
    // 假设目标端口是 20020
    __u16 dst_port = bpf_ntohs(tcph->dest);
    // 这里硬编码一个范围或者只抓 SYN，防止日志被刷爆
    if (!tcph->syn && !tcph->ack) return XDP_PASS; // 只看 SYN
    if (dst_port != 20020) return XDP_PASS; 

    // --- 开始 CT 扫描 ---
    DEBUG_PRINT("\n=== CAPTURE START ===\n");
    
    __u32 tcp_hdr_len = tcph->doff * 4;
    DEBUG_PRINT("TCP Len: %d\n", tcp_hdr_len);

    // 打印修改前的选项 (前 12 字节)
    void *opts_start = (void*)tcph + 20;
    print_hex_dump(opts_start, data_end, "BEFORE");

    // --- 寻找 Timestamp ---
    __u32 opts_offset = ip_offset + ip_hdr_len + 20; 
    __u32 opts_len = tcp_hdr_len - 20;
    __u32 found_offset = 0;

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
        
        // 打印遍历过程，确认我们看到了什么
        // DEBUG_PRINT("Scan: Kind=%d Len=%d\n", kind, len);

        if (kind == TCPOPT_TIMESTAMP && len == 10) {
            found_offset = opts_offset;
            DEBUG_PRINT("HIT! TS at offset %d\n", opts_offset);
            break;
        }
        opts_offset += len;
        opts_len -= len;
    }

    if (found_offset == 0) {
        DEBUG_PRINT("No TS found. ABORT.\n");
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
    
    // --- 重新计算校验和 ---
    // 重新获取指针
    tcph = (void *)data + ip_offset + ip_hdr_len;
    if ((void*)tcph + sizeof(*tcph) <= data_end) {
         update_tcp_csum(tcph, old_data, &block, 10);
    }

    // --- 打印修改后的选项 ---
    // 重新获取指针
    tcph = (void *)data + ip_offset + ip_hdr_len;
    opts_start = (void*)tcph + 20;
    print_hex_dump(opts_start, data_end, "AFTER ");

    DEBUG_PRINT("=== CAPTURE END ===\n");

    return XDP_PASS; 
}

char _license[] SEC("license") = "GPL";
