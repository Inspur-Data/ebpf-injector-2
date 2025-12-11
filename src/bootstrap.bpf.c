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

// 定义一个完整的替换块结构体，避免手动拼凑字节数组
// 使用 __attribute__((packed)) 确保没有编译器填充，并允许未对齐访问
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

    ip_hdr_len = iph->ihl * 4;
    // 强制 IP 头长度为 20，简化 Verifier 分析
    if (ip_hdr_len != 20) return XDP_PASS;

    tcph = (void *)iph + 20;
    if ((void *)tcph + sizeof(*tcph) > data_end) return XDP_PASS;

    // 直接使用网络字节序匹配，配合 bootstrap.c 的双字节序注册
    if (!bpf_map_lookup_elem(&ports_map, &tcph->dest)) return XDP_PASS;
    
    if (!(tcph->syn && !tcph->ack)) return XDP_PASS;

    tcp_hdr_len = tcph->doff * 4;
    // 确保有足够空间容纳 Timestamp (至少36字节总长)
    if (tcp_hdr_len < 36 || tcp_hdr_len > 60) return XDP_PASS;

    source_ip = iph->saddr;
    dest_ip = iph->daddr;
    source_port = tcph->source;

    // --- 修复：使用 packed 结构体构建数据，避免未对齐访问 ---
    struct toa_replace_block block;
    // 由于是 packed，编译器会生成逐字节写入的指令，安全！
    block.kind = TCPOPT_TOA;
    block.len = TCPOLEN_TOA;
    block.port = source_port;
    block.ip = source_ip;
    block.nop1 = TCPOPT_NOP;
    block.nop2 = TCPOPT_NOP;

    // 偏移量：以太网 + IP(20) + TCP基头(20) + 偏移(6) = 60 (如果有VLAN则加4)
    // 这里我们使用基于 ip_offset 的计算，Verifier 知道 ip_offset 是有限的
    // ip_offset (14 or 18) + 20 + 26
    __u32 base_offset = ip_offset + 46; 
    
    void *toa_ptr = data + base_offset;

    // 边界检查
    if (toa_ptr + sizeof(block) > data_end) return XDP_PASS;

    // 读取旧数据
    __u8 old_data[10];
    __builtin_memcpy(old_data, toa_ptr, 10);

    // 写入新数据
    // __builtin_memcpy 会被编译器优化为高效且安全的指令
    __builtin_memcpy(toa_ptr, &block, sizeof(block));
    
    // 更新校验和
    void *tcph_ptr = (void*)data + ip_offset + 20;
    // 再次边界检查，虽然冗余，但让 Verifier 开心
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
