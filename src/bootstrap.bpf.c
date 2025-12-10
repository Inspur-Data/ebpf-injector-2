// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h> // 包含 TC_ACT_* 定义

#include "common.h"

// TOA 选项定义
#define TCPOPT_TOA 254
#define TCPOLEN_TOA 8
struct toa_opt {
    __u8 kind;
    __u8 len;
    __be16 port;
    __be32 ip;
};

// eBPF Maps 定义
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
    // 1. 初始化和 L2/L3 层解析
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    __u16 h_proto;
    __u32 ip_offset;

    if (data + sizeof(*eth) > data_end)
        return TC_ACT_OK;

    h_proto = eth->h_proto;
    ip_offset = sizeof(*eth);

    if (h_proto == bpf_htons(ETH_P_8021Q)) {
        struct vlan_hdr { __be16 h_vlan_TCI; __be16 h_vlan_encapsulated_proto; };
        struct vlan_hdr *vlan = (void *)eth + sizeof(*eth);
        if ((void *)vlan + sizeof(*vlan) > data_end)
            return TC_ACT_OK;
        h_proto = vlan->h_vlan_encapsulated_proto;
        ip_offset += sizeof(*vlan);
    }

    if (h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    iph = (struct iphdr *)(data + ip_offset);
    if ((void *)iph + sizeof(*iph) > data_end)
        return TC_ACT_OK;

    if (iph->protocol != IPPROTO_TCP)
        return TC_ACT_OK;
    
    // 2. L4 层解析和条件检查
    __u32 ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(*iph))
        return TC_ACT_OK;

    struct tcphdr *tcph = (struct tcphdr *)((void *)iph + ip_hdr_len);
    if ((void *)tcph + sizeof(*tcph) > data_end)
        return TC_ACT_OK;
    
    __u16 target_port = bpf_ntohs(tcph->dest);
    if (!bpf_map_lookup_elem(&ports_map, &target_port))
        return TC_ACT_OK;

    // 只处理 SYN 包 (SYN=1, ACK=0)
    if (!(tcph->syn && !tcph->ack))
        return TC_ACT_OK;

    // 3. TOA 注入核心逻辑
    struct toa_opt toa;
    toa.kind = TCPOPT_TOA;
    toa.len = TCPOLEN_TOA;
    toa.port = tcph->source;
    toa.ip = iph->saddr;

    __u32 old_tcp_len = tcph->doff * 4;
    if (old_tcp_len < sizeof(*tcph))
        return TC_ACT_OK;
    
    if (bpf_skb_adjust_room(skb, TCPOLEN_TOA, BPF_ADJ_ROOM_NET, 0))
        return TC_ACT_SHOT;

    // --- 指针失效，必须重新加载所有指针！ ---
    data_end = (void *)(long)skb->data_end;
    data = (void *)(long)skb->data;
    iph = (struct iphdr *)(data + ip_offset);
    if ((void *)iph + sizeof(*iph) > data_end)
        return TC_ACT_SHOT;
    
    // --- L3 (IP) 头部修正 ---
    __be16 new_tot_len = bpf_htons(bpf_ntohs(iph->tot_len) + TCPOLEN_TOA);
    bpf_l3_csum_replace(skb, ip_offset + offsetof(struct iphdr, check), iph->tot_len, new_tot_len, sizeof(new_tot_len));
    bpf_skb_store_bytes(skb, ip_offset + offsetof(struct iphdr, tot_len), &new_tot_len, sizeof(new_tot_len), 0);

    // --- L4 (TCP) 头部修正 (已简化并修复) ---
    
    // 1. 准备新的 TCP Data Offset (doff) 字节
    //    doff 位于 TCP 头第 12 字节的高 4 位。
    __u8 new_doff_byte = ((old_tcp_len + TCPOLEN_TOA) / 4) << 4; 

    // 2. 写入新的 doff 字节。
    //    使用硬编码的 TCP 头部偏移量 12，因为 `offsetof` 不能用于位域 `doff`。
    bpf_skb_store_bytes(skb, ip_offset + iph->ihl * 4 + 12, &new_doff_byte, sizeof(new_doff_byte), 0);
    
    // 3. 写入 TOA 选项，并让内核重算 L4 校验和。
    //    BPF_F_RECOMPUTE_CSUM 标志会自动处理所有影响校验和的因素：
    //    a) doff 值的改变
    //    b) 新增的 TOA 选项内容
    //    c) IP 层长度改变导致的伪首部变化
    bpf_skb_store_bytes(skb, ip_offset + iph->ihl * 4 + old_tcp_len, &toa, TCPOLEN_TOA, BPF_F_RECOMPUTE_CSUM);

    // 4. 记录日志
    struct log_event event;
    event.src_ip = iph->saddr;
    event.dst_ip = iph->daddr;
    event.src_port = tcph->source;
    event.dst_port = old_tcp_len;
    bpf_perf_event_output(skb, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
