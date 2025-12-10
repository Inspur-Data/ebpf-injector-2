// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include "common.h"

// ... (struct 定义和 map 定义保持不变) ...

SEC("tc")
int tc_toa_injector(struct __sk_buff *skb) {
    // --- 1. 初始化和L2/L3层解析 ---
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
    
    // --- 2. L4层解析和条件检查 ---
    __u32 ip_hdr_len = iph->ihl * 4;
    // 防止 ip_hdr_len < 20 的情况
    if (ip_hdr_len < sizeof(*iph))
        return TC_ACT_OK;

    struct tcphdr *tcph = (struct tcphdr *)((void *)iph + ip_hdr_len);
    if ((void *)tcph + sizeof(*tcph) > data_end)
        return TC_ACT_OK;
    
    __u16 target_port = bpf_ntohs(tcph->dest);
    if (!bpf_map_lookup_elem(&ports_map, &target_port))
        return TC_ACT_OK;

    // 只处理SYN包
    if (!(tcph->syn && !tcph->ack))
        return TC_ACT_OK;

    // --- 3. TOA 注入核心逻辑 ---
    struct toa_opt toa;
    toa.kind = TCPOPT_TOA;
    toa.len = TCPOLEN_TOA;
    toa.port = tcph->source;
    toa.ip = iph->saddr;

    __u32 old_tcp_len = tcph->doff * 4;
    // 确保TCP头长度有效
    if (old_tcp_len < sizeof(*tcph))
        return TC_ACT_OK;
    
    // **严重BUG修复：在这里先进行 room 调整**
    if (bpf_skb_adjust_room(skb, TCPOLEN_TOA, BPF_ADJ_ROOM_NET, 0))
        return TC_ACT_SHOT;

    // **严重BUG修复：指针失效，必须重新加载所有指针！**
    data_end = (void *)(long)skb->data_end;
    data = (void *)(long)skb->data;
    eth = (struct ethhdr *)data; // 虽然下面没用，但这是标准做法
    iph = (struct iphdr *)(data + ip_offset);
    // 再次检查边界
    if ((void *)iph + sizeof(*iph) > data_end)
        return TC_ACT_SHOT;
    
    tcph = (struct tcphdr *)((void *)iph + ip_hdr_len);
    if ((void *)tcph + sizeof(*tcph) > data_end)
        return TC_ACT_SHOT;

    // **严重BUG修复：更新 IP 头总长度**
    __be16 new_tot_len = bpf_htons(bpf_ntohs(iph->tot_len) + TCPOLEN_TOA);
    bpf_l3_csum_replace(skb, ip_offset + offsetof(struct iphdr, check),
                        iph->tot_len, new_tot_len, sizeof(new_tot_len));
    bpf_skb_store_bytes(skb, ip_offset + offsetof(struct iphdr, tot_len),
                        &new_tot_len, sizeof(new_tot_len), 0);

    // 更新TCP头长度 (doff)
    __u8 new_doff = ((old_tcp_len + TCPOLEN_TOA) / 4) << 4;
    bpf_l4_csum_replace(skb, ip_offset + ip_hdr_len + offsetof(struct tcphdr, check),
                        tcph->doff << 8, new_doff << 8, sizeof(new_doff));
    bpf_skb_store_bytes(skb, ip_offset + ip_hdr_len + offsetof(struct tcphdr, doff),
                        &new_doff, sizeof(new_doff), 0);
    
    // 写入 TOA 选项
    bpf_skb_store_bytes(skb, ip_offset + ip_hdr_len + old_tcp_len, &toa,
                        TCPOLEN_TOA, BPF_F_RECOMPUTE_CSUM);

    // 记录日志 (可选)
    struct log_event event = {
        .src_ip = iph->saddr,
        .dst_ip = iph->daddr,
        .src_port = tcph->source,
        .dst_port = old_tcp_len,
    };
    bpf_perf_event_output(skb, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

