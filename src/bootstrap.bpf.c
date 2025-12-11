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

// 调试宏
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
    
    // 1. 解析层
    if (data + sizeof(*eth) > data_end) return XDP_PASS;
    __u32 ip_offset = sizeof(*eth);
    if (eth->h_proto == bpf_htons(ETH_P_8021Q)) ip_offset += 4;
    
    // 简单检查 IP
    if (eth->h_proto != bpf_htons(ETH_P_IP) && eth->h_proto != bpf_htons(ETH_P_8021Q)) return XDP_PASS;

    struct iphdr *iph = data + ip_offset;
    if ((void*)iph + sizeof(*iph) > data_end) return XDP_PASS;
    if (iph->protocol != IPPROTO_TCP) return XDP_PASS;

    __u32 ip_hdr_len = iph->ihl * 4;
    struct tcphdr *tcph = (void*)iph + ip_hdr_len;
    if ((void*)tcph + sizeof(*tcph) > data_end) return XDP_PASS;

    __u16 dst_port = bpf_ntohs(tcph->dest);
    
    // 2. 调试逻辑
    if (dst_port == 20020) {
        bpf_debug("=== HIT Port 20020 ===\n", 0);
        
        // Map 检查
        if (!bpf_map_lookup_elem(&ports_map, &tcph->dest)) {
            bpf_debug("Map: FAIL\n", 0);
        } else {
            bpf_debug("Map: OK\n", 0);
        }

        // SYN 检查
        bpf_debug("SYN: %d\n", tcph->syn);

        // 长度检查
        __u32 tcp_len = tcph->doff * 4;
        bpf_debug("Len: %d\n", tcp_len);

        // --- Hex Dump (前12字节) ---
        if (tcp_len > 20) {
            __u8 *opts = (void*)tcph + 20;
            if ((void*)opts + 12 <= data_end) {
                __u32 w1 = *(__u32*)opts;
                __u32 w2 = *(__u32*)(opts + 4);
                __u32 w3 = *(__u32*)(opts + 8);
                // 打印 3 个 32位字
                bpf_debug("HEX 0-3: %08x\n", bpf_ntohl(w1));
                bpf_debug("HEX 4-7: %08x\n", bpf_ntohl(w2));
                bpf_debug("HEX 8-11: %08x\n", bpf_ntohl(w3));
            } else {
                bpf_debug("HEX: Too short to dump\n", 0);
            }
        } else {
            bpf_debug("HEX: No options\n", 0);
        }
    }

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
