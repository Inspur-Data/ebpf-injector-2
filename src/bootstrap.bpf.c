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

// --- BUG FIX #1: 添加缺失的 VLAN header 定义 ---
struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

// TOA option definition
#define TCPOPT_TOA 254
#define TCPOLEN_TOA 8
struct toa_opt {
    __u8 kind;
    __u8 len;
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
    // --- 1. "Parse First" 阶段：读取所有需要的值到局部变量 ---
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct tcphdr *tcph;
    
    __u32 ip_offset;
    __u32 ip_hdr_len;
    __u32 old_tcp_len;
    __be16 old_tot_len;
    __be32 source_ip;
    __be32 dest_ip;
    __be16 source_port;
    __u16 h_proto;
    __u16 target_port;

    if (data + sizeof(*eth) > data_end) return TC_ACT_OK;

    // --- BUG FIX #2: 使用更健壮的逻辑正确处理 VLAN 头部 ---
    h_proto = eth->h_proto;
    ip_offset = sizeof(*eth);

    if (h_proto == bpf_htons(ETH_P_8021Q)) {
        struct vlan_hdr *vlan = (void *)eth + sizeof(*eth);
        if ((void *)vlan + sizeof(*vlan) > data_end)
            return TC_ACT_OK;
        h_proto = vlan->h_vlan_encapsulated_proto; // 读取真正的 L3 协议
        ip_offset += sizeof(*vlan);             // 增加 VLAN 头部的偏移量
    }

    if (h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    // --- VLAN 逻辑修正完毕 ---

    iph = (struct iphdr *)(data + ip_offset);
    if ((void *)iph + sizeof(*iph) > data_end) return TC_ACT_OK;

    if (iph->protocol != IPPROTO_TCP) return TC_ACT_OK;

    ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(*iph)) return TC_ACT_OK;

    tcph = (struct tcphdr *)((void *)iph + ip_hdr_len);
    if ((void *)tcph + sizeof(*tcph) > data_end) return TC_ACT_OK;
    
    // --- BUG FIX #3: 恢复被错误删除的字节序转换 ---
    target_port = bpf_ntohs(tcph->dest);
    if (!bpf_map_lookup_elem(&ports_map, &target_port)) return TC_ACT_OK;
    
    if (!(tcph->syn && !tcph->ack)) return TC_ACT_OK;
    
    // --- 将所有未来需要的值，从指针复制到安全的局部变量 ---
    old_tcp_len = tcph->doff * 4;
    if (old_tcp_len < sizeof(*tcph)) return TC_ACT_OK;
    
    old_tot_len = iph->tot_len;
    source_ip = iph->saddr;
    dest_ip = iph->daddr;
    source_port = tcph->source;
    // --- "Parse First" 阶段结束 ---

    // --- 2. 修改数据包 ---
    if (bpf_skb_adjust_room(skb, TCPOLEN_TOA, BPF_ADJ_ROOM_NET, 0))
        return TC_ACT_SHOT;

    // --- 3. "Write Later" 阶段：只写入，并只使用安全的局部变量 ---
    struct toa_opt toa;
    toa.kind = TCPOPT_TOA;
    toa.len = TCPOLEN_TOA;
    toa.port = source_port;
    toa.ip = source_ip;

    __be16 new_tot_len = bpf_htons(bpf_ntohs(old_tot_len) + TCPOLEN_TOA);
    bpf_l3_csum_replace(skb, ip_offset + offsetof(struct iphdr, check), old_tot_len, new_tot_len, sizeof(new_tot_len));
    bpf_skb_store_bytes(skb, ip_offset + offsetof(struct iphdr, tot_len), &new_tot_len, sizeof(new_tot_len), 0);

    __u8 new_doff_byte = ((old_tcp_len + TCPOLEN_TOA) / 4) << 4; 
    bpf_skb_store_bytes(skb, ip_offset + ip_hdr_len + 12, &new_doff_byte, sizeof(new_doff_byte), 0);
    
    bpf_skb_store_bytes(skb, ip_offset + ip_hdr_len + old_tcp_len, &toa, TCPOLEN_TOA, BPF_F_RECOMPUTE_CSUM);

    struct log_event event;
    event.src_ip = source_ip;
    event.dst_ip = dest_ip;
    event.src_port = source_port;
    event.dst_port = old_tcp_len;
    bpf_perf_event_output(skb, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
