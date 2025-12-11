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

// 保证结构体无填充，与数据包内存布局一致
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

// 标准的 Checksum Fold 函数
// 将 64 位的大数（包含进位）折叠成 16 位的校验和
static __always_inline __u16 csum_fold_helper(__u64 csum) {
    int i;
#pragma unroll
    for (i = 0; i < 4; i++) {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

// 经过严格审查的校验和更新函数
static __always_inline void update_tcp_csum(struct tcphdr *tcph, void *old_data, void *new_data, int len) {
    // 1. 计算 old_data 和 new_data 之间的差异 (diff)
    //    bpf_csum_diff 返回的是一个 64 位的差值，可能为负
    //    seed 参数传 0，表示我们只计算数据的 diff
    __s64 diff = bpf_csum_diff(old_data, len, new_data, len, 0);

    // 2. 将当前的校验和 (tcph->check) 还原为反码形式 (unfold)
    //    注意：tcph->check 是网络字节序，但在 16 位加法中，字节序不影响进位逻辑
    //    我们把它当做普通的 u16 处理
    __u64 csum = bpf_ntohs(tcph->check);
    
    //    取反得到累加和 (one's complement sum)
    csum = ~csum & 0xffff;

    // 3. 将 diff 应用到累加和上
    //    内核处理 diff 的标准方式
    csum += diff;

    // 4. 折叠 (Fold) 回 16 位
    //    这个 helper 会处理所有的循环进位，并最后取反
    tcph->check = bpf_htons(csum_fold_helper(csum));
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
    // 强制 IP 头长度为 20，简化处理
    if (ip_hdr_len != 20) return XDP_PASS;

    tcph = (void *)iph + 20;
    if ((void *)tcph + sizeof(*tcph) > data_end) return XDP_PASS;

    // 端口匹配 (利用双字节序 Map，无需转换)
    if (!bpf_map_lookup_elem(&ports_map, &tcph->dest)) return XDP_PASS;
    
    if (!(tcph->syn && !tcph->ack)) return XDP_PASS;

    tcp_hdr_len = tcph->doff * 4;
    // 确保有空间覆盖
    if (tcp_hdr_len < 36 || tcp_hdr_len > 60) return XDP_PASS;

    source_ip = iph->saddr;
    dest_ip = iph->daddr;
    source_port = tcph->source;

    // 构造数据
    struct toa_replace_block block;
    block.kind = TCPOPT_TOA;
    block.len = TCPOLEN_TOA;
    block.port = source_port;
    block.ip = source_ip;
    block.nop1 = TCPOPT_NOP;
    block.nop2 = TCPOPT_NOP;

    // 计算偏移量：IP头(20) + 26
    __u32 base_offset = ip_offset + 46; 
    void *toa_ptr = data + base_offset;

    if (toa_ptr + sizeof(block) > data_end) return XDP_PASS;

    // --- 关键动作：读取旧数据 ---
    __u8 old_data[10];
    __builtin_memcpy(old_data, toa_ptr, 10);

    // --- 写入新数据 ---
    __builtin_memcpy(toa_ptr, &block, sizeof(block));
    
    // --- 更新校验和 ---
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
