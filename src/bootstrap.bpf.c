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

// 定义 Maps (保持与 bootstrap.c 兼容)
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65535); __type(key, __u16); __type(value, __u8); } ports_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY); __uint(key_size, sizeof(int)); __uint(value_size, sizeof(int)); } log_events SEC(".maps");

// 调试宏
#define bpf_debug(fmt, ...) ({ char _fmt[] = fmt; bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__); })

SEC("xdp")
int xdp_toa_injector(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct tcphdr *tcph;
    
    __u32 ip_offset, ip_hdr_len, tcp_hdr_len;
    __u16 h_proto;

    ip_offset = sizeof(*eth);
    if (data + ip_offset > data_end) return XDP_PASS;

    h_proto = eth->h_proto;
    if (h_proto == bpf_htons(ETH_P_8021Q)) {
        ip_offset += 4;
        if (data + ip_offset > data_end) return XDP_PASS;
        struct ethhdr *inner = data + 4; 
        h_proto = inner->h_proto;
    }

    if (h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;
    
    iph = data + ip_offset;
    if ((void *)iph + sizeof(*iph) > data_end) return XDP_PASS;
    if (iph->protocol != IPPROTO_TCP) return XDP_PASS;

    ip_hdr_len = iph->ihl * 4;
    tcph = (void *)iph + ip_hdr_len;
    if ((void *)tcph + sizeof(*tcph) > data_end) return XDP_PASS;

    // 端口匹配：利用双字节序 Map，无需转换
    if (!bpf_map_lookup_elem(&ports_map, &tcph->dest)) return XDP_PASS;
    
    if (!(tcph->syn && !tcph->ack)) return XDP_PASS;

    tcp_hdr_len = tcph->doff * 4;
    if (tcp_hdr_len <= 20) {
        bpf_debug("TCP Len: %d (No Options)\n", tcp_hdr_len);
        return XDP_PASS;
    }

    // --- 打印前 12 个字节的选项 (Hex) ---
    // 选项起始位置 = TCP头 + 20
    __u8 *opts = (void *)tcph + 20;
    
    // 安全检查
    if ((void *)opts + 12 <= data_end) {
        // 读取 3 个 32位字
        __u32 w1 = *(__u32 *)(opts);
        __u32 w2 = *(__u32 *)(opts + 4);
        __u32 w3 = *(__u32 *)(opts + 8);
        
        // 打印!
        // 格式: OPTS: [第1-4字节] [第5-8字节] [第9-12字节]
        bpf_debug("OPTS: %08x %08x %08x\n", 
                  bpf_ntohl(w1), bpf_ntohl(w2), bpf_ntohl(w3));
    } else {
        bpf_debug("TCP Len: %d (Too short to dump)\n", tcp_hdr_len);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
