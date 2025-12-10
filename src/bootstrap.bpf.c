// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "common.h"

// VLAN 协议号
#define ETH_P_8021Q 0x8100

// TOA 选项定义
#define TCPOPT_TOA 254
#define TCPOLEN_TOA 8
struct toa_opt {
    __u8   kind;
    __u8   len;
    __be16 port;
    __be32 ip;
};

// eBPF Maps
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65535); __type(key, __u16); __type(value, __u8); } ports_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY); __uint(key_size, sizeof(int)); __uint(value_size, sizeof(int)); } log_events SEC(".maps");

// 使用 SEC("xdp") 定义一个 XDP 程序
SEC("xdp")
int xdp_toa_injector(struct xdp_md *ctx) {
    // "先解析" - Part 1: 获取数据包指针
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct tcphdr *tcph;
    
    // "先解析" - Part 2: 定义所有需要从包中读取的变量
    __u32 ip_offset, ip_hdr_len, tcp_hdr_len;
    __u16 h_proto, target_port;
    __be32 source_ip, dest_ip;
    __be16 source_port;

    // --- 开始解析 ---
    ip_offset = sizeof(*eth);
    if (data + ip_offset > data_end) return XDP_PASS;

    h_proto = eth->h_proto;
    if (h_proto == bpf_htons(ETH_P_8021Q)) {
        ip_offset += 4;
        if (data + ip_offset > data_end) return XDP_PASS;
        // 假设只有一个VLAN tag, 重新读取内部的协议号
        struct ethhdr *inner_eth = data + 4;
        h_proto = inner_eth->h_proto;
    }

    if (h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;
    
    iph = data + ip_offset;
    if ((void *)iph + sizeof(*iph) > data_end) return XDP_PASS;
    if (iph->protocol != IPPROTO_TCP) return XDP_PASS;

    ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(*iph)) return XDP_PASS; // 保证 ip_hdr_len 至少为 20

    tcph = (void *)iph + ip_hdr_len;
    if ((void *)tcph + sizeof(*tcph) > data_end) return XDP_PASS;

    target_port = bpf_ntohs(tcph->dest);
    if (!bpf_map_lookup_elem(&ports_map, &target_port)) return XDP_PASS;
    
    if (!(tcph->syn && !tcph->ack)) return XDP_PASS;

    tcp_hdr_len = tcph->doff * 4;
    if (tcp_hdr_len < 32) return XDP_PASS; // "覆盖"模式的安全检查

    // "先解析" - Part 3: 将所有需要的值存入局部变量
    source_ip = iph->saddr;
    dest_ip = iph->daddr;
    source_port = tcph->source;
    // --- "先解析" 阶段完全结束 ---


    // --- "后写入" 阶段 ---
    
    // 1. 准备 TOA 数据
    struct toa_opt toa;
    toa.kind = TCPOPT_TOA;
    toa.len = TCPOLEN_TOA;
    toa.port = source_port;
    toa.ip = source_ip;

    // 2. 计算覆盖位置 (使用已存入局部变量的值)
    __u32 toa_offset = ip_offset + ip_hdr_len + 24;

    // 3. 边界检查
    if (data + toa_offset + sizeof(toa) > data_end) return XDP_PASS;
    
    // 4. 核心修改：在XDP中，任何修改都需要先确保数据区是线性的。
    //    bpf_xdp_adjust_head 是一个可以用来达成此目的的技巧。
    if (bpf_xdp_adjust_head(ctx, 0 - (int)toa_offset)) return XDP_DROP;
    if (bpf_xdp_adjust_head(ctx, (int)toa_offset)) return XDP_DROP;

    // 5. 重新获取指针，因为 adjust_head 可能改变了它们
    data     = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    // 6. 再次进行边界检查
    if (data + toa_offset + sizeof(toa) > data_end) return XDP_DROP;

    // 7. 执行覆盖
    __builtin_memcpy(data + toa_offset, &toa, sizeof(toa));

    // 8. 依赖网卡驱动的 Checksum Offload 功能来修复校验和。

    // 9. 记录日志
    struct log_event event = {source_ip, dest_ip, source_port, tcp_hdr_len};
    bpf_perf_event_output(ctx, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return XDP_PASS; // 放行我们修改过的、但被伪装成“原始”数据包的 skb
}

char _license[] SEC("license") = "GPL";
