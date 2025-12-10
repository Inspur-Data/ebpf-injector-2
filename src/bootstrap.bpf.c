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

    // --- 极简处理：我们只处理标准 IP 头 (20字节) ---
    // 这大大简化了 Verifier 的路径分析
    ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len != 20) return XDP_PASS;

    tcph = (void *)iph + 20; // 直接用常数 20
    if ((void *)tcph + sizeof(*tcph) > data_end) return XDP_PASS;

    if (!bpf_map_lookup_elem(&ports_map, &tcph->dest)) return XDP_PASS;
    
    if (!(tcph->syn && !tcph->ack)) return XDP_PASS;

    tcp_hdr_len = tcph->doff * 4;
    // 限制 TCP 头最大长度，防止溢出
    if (tcp_hdr_len < 36 || tcp_hdr_len > 60) return XDP_PASS;

    source_ip = iph->saddr;
    dest_ip = iph->daddr;
    source_port = tcph->source;

    __u8 new_block[10];
    struct toa_opt *toa = (struct toa_opt *)new_block;
    toa->kind = TCPOPT_TOA;
    toa->len = TCPOLEN_TOA;
    toa->port = source_port;
    toa->ip = source_ip;
    new_block[8] = TCPOPT_NOP;
    new_block[9] = TCPOPT_NOP;

    // --- 极其保守的指针计算 ---
    // 我们的目标位置是：Ethernet(14) + IP(20) + TCP_Base(20) + Offset(6) = 60
    // 如果有 VLAN，则加 4
    __u32 base_offset = ip_offset + 20 + 26; 
    
    // 这里的 base_offset 几乎是一个常数，Verifier 应该能接受
    void *toa_ptr = data + base_offset;

    // 边界检查：确保我们要写的 10 字节都在包内
    if (toa_ptr + 10 > data_end) return XDP_PASS;

    __u8 old_data[10];
    // 使用验证过的指针读取
    __builtin_memcpy(old_data, toa_ptr, 10);

    // 写入新数据
    __builtin_memcpy(toa_ptr, new_block, 10);
    
    // 重新获取 TCP 头指针用于校验和
    // 既然我们没有 adjust_head，data 指针没变，直接计算即可
    // tcph 已经在前面验证过，但在 XDP 中，再次验证是好习惯
    void *tcph_ptr = (void*)data + ip_offset + 20;
    if (tcph_ptr + sizeof(struct tcphdr) <= data_end) {
         update_tcp_csum((struct tcphdr *)tcph_ptr, old_data, new_block, 10);
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
