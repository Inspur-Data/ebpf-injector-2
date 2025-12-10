// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>

#include "common.h"

// VLAN header definition
struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

// TOA option definition
#define TCPOPT_TOA 254
#define TCPOLEN_TOA 8
struct toa_opt {
    __u8   kind;
    __u8   len;
    __be16 port;
    __be32 ip;
};

// eBPF map definitions
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, __u16);
    __type(value, __u8);
} ports_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} log_events SEC(".maps");


SEC("tc")
int tc_toa_injector(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct tcphdr *tcph;
    
    __u32 ip_offset, ip_hdr_len;
    __be32 source_ip, dest_ip;
    __be16 source_port;
    __u16 h_proto, target_port;

    if (data + sizeof(*eth) > data_end) return TC_ACT_OK;

    h_proto = eth->h_proto;
    ip_offset = sizeof(*eth);

    if (h_proto == bpf_htons(ETH_P_8021Q)) {
        struct vlan_hdr *vlan = (void *)eth + sizeof(*eth);
        if ((void *)vlan + sizeof(*vlan) > data_end) return TC_ACT_OK;
        h_proto = vlan->h_vlan_encapsulated_proto;
        ip_offset += sizeof(*vlan);
    }

    if (h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    iph = (struct iphdr *)(data + ip_offset);
    if ((void *)iph + sizeof(*iph) > data_end) return TC_ACT_OK;

    if (iph->protocol != IPPROTO_TCP) return TC_ACT_OK;

    ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(*iph)) return TC_ACT_OK;

    tcph = (struct tcphdr *)((void *)iph + ip_hdr_len);
    if ((void *)tcph + sizeof(*tcph) > data_end) return TC_ACT_OK;
    
    target_port = bpf_ntohs(tcph->dest);
    if (!bpf_map_lookup_elem(&ports_map, &target_port)) return TC_ACT_OK;
    
    if (!(tcph->syn && !tcph->ack)) return TC_ACT_OK;
    
    __u32 tcp_hdr_len = tcph->doff * 4;
    // --- "覆盖"模式的核心检查：TCP头必须足够长，我们才有空间可以覆盖 ---
    if (tcp_hdr_len < 32) {
        // 如果TCP头小于32字节 (比如标准的20或24字节)，它就没有足够的选项空间给我们去覆盖。
        // 为了绝对安全，我们选择放弃修改，直接放行。
        return TC_ACT_OK;
    }

    source_ip = iph->saddr;
    dest_ip = iph->daddr;
    source_port = tcph->source;

    // --- "覆盖"模式的核心逻辑 ---
    // 1. 计算要覆盖的起始位置。我们选择TCP头部的第24个字节开始。
    //    这个位置通常是SACK或Timestamp选项，覆盖它们相对安全。
    __u32 toa_offset = ip_offset + ip_hdr_len + 24;
    
    // 2. 再次确认写入操作不会越过数据包的末尾 (这是一个安全的好习惯)
    if ((void *)(long)(toa_offset + TCPOLEN_TOA) > data_end) {
        return TC_ACT_OK;
    }

    // 3. 准备TOA数据
    struct toa_opt toa;
    toa.kind = TCPOPT_TOA;
    toa.len = TCPOLEN_TOA;
    toa.port = source_port;
    toa.ip = source_ip;

    // 4. 核心操作：暴力覆盖！并让内核为我们重算校验和。
    //    这个单一的操作，替代了之前所有复杂的、有风险的长度和校验和修改。
    if (bpf_skb_store_bytes(skb, toa_offset, &toa, sizeof(toa), BPF_F_RECOMPUTE_CSUM) < 0) {
        return TC_ACT_SHOT; // 如果写入失败，则丢弃该包
    }

    // --- 记录日志 ---
    struct log_event event;
    event.src_ip = source_ip;
    event.dst_ip = dest_ip;
    event.src_port = source_port;
    event.dst_port = tcp_hdr_len; // 仍然记录原始长度，用于调试
    bpf_perf_event_output(skb, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
