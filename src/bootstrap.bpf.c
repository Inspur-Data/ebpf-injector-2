// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h> // 修复 #1: 包含此头文件以定义 TC_ACT_OK 和 TC_ACT_SHOT

#include "common.h"

// 修复 #2: 添加缺失的 TOA 选项定义
#define TCPOPT_TOA 254      // TOA 选项的 Kind 值
#define TCPOLEN_TOA 8       // TOA 选项的长度 (Kind + Len + Port + IP = 1+1+2+4 = 8)
struct toa_opt {
    __u8 kind;
    __u8 len;
    __be16 port;
    __be32 ip;
};

// 修复 #3: 明确定义 eBPF maps
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
// --- 所有修复完成 ---


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

    // 指针失效，必须重新加载所有指针！
    data_end = (void *)(long)skb->data_end;
    data = (void *)(long)skb->data;
    iph = (struct iphdr *)(data + ip_offset);
    if ((void *)iph + sizeof(*iph) > data_end)
        return TC_ACT_SHOT;
    
    tcph = (struct tcphdr *)((void *)iph + ip_hdr_len);
    if ((void *)tcph + sizeof(*tcph) > data_end)
        return TC_ACT_SHOT;

    // 更新 IP 头总长度
    __be16 new_tot_len = bpf_htons(bpf_ntohs(iph->tot_len) + TCPOLEN_TOA);
    bpf_l3_csum_replace(skb, ip_offset + offsetof(struct iphdr, check), iph->tot_len, new_tot_len, sizeof(new_tot_len));
    bpf_skb_store_bytes(skb, ip_offset + offsetof(struct iphdr, tot_len), &new_tot_len, sizeof(new_tot_len), 0);

    // 更新 TCP 头长度 (doff)
    __u8 new_doff = ((old_tcp_len + TCPOLEN_TOA) / 4) << 4;
    bpf_l4_csum_replace(skb, ip_offset + ip_hdr_len + offsetof(struct tcphdr, check), (__be32)tcph->doff << 8, (__be32)new_doff << 8, sizeof(new_doff));
    bpf_skb_store_bytes(skb, ip_offset + ip_hdr_len + offsetof(struct tcphdr, doff), &new_doff, sizeof(new_doff), 0);
    
    // 写入 TOA 选项，并让内核自动重算校验和
    bpf_skb_store_bytes(skb, ip_offset + ip_hdr_len + old_tcp_len, &toa, TCPOLEN_TOA, BPF_F_RECOMPUTE_CSUM);

    // 记录日志
    struct log_event event;
    event.src_ip = iph->saddr;
    event.dst_ip = iph->daddr;
    event.src_port = tcph->source;
    event.dst_port = old_tcp_len; // 回传原始TCP头长
    bpf_perf_event_output(skb, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
