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

#define TCPOPT_TOA 254
#define TCPOLEN_TOA 8
struct toa_opt {
    __u8 kind;
    __u8 len;
    __be16 port;
    __be32 ip;
};

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
    // --- 1. "Parse First" 阶段：读取所有需要的值并检查 ---
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct tcphdr *tcph;
    
    __u16 h_proto;
    __u32 ip_offset;
    __u32 ip_hdr_len;
    __u32 old_tcp_len;
    __be16 old_tot_len;

    if (data + sizeof(*eth) > data_end) return TC_ACT_OK;

    h_proto = eth->h_proto;
    ip_offset = sizeof(*eth);

    if (h_proto == bpf_htons(ETH_P_8021Q)) {
        ip_offset += 4;
    } else if (h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    iph = (struct iphdr *)(data + ip_offset);
    if ((void *)iph + sizeof(*iph) > data_end) return TC_ACT_OK;

    if (iph->protocol != IPPROTO_TCP) return TC_ACT_OK;

    ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(*iph)) return TC_ACT_OK;

    tcph = (struct tcphdr *)((void *)iph + ip_hdr_len);
    if ((void *)tcph + sizeof(*tcph) > data_end) return TC_ACT_OK;
    
    if (!bpf_map_lookup_elem(&ports_map, &tcph->dest)) return TC_ACT_OK;
    if (!(tcph->syn && !tcph->ack)) return TC_ACT_OK;
    
    // 将所有需要的值保存到局部变量中
    old_tcp_len = tcph->doff * 4;
    old_tot_len = iph->tot_len;
    if (old_tcp_len < sizeof(*tcph)) return TC_ACT_OK;

    // --- "Parse First" 阶段结束 ---

    // --- 2. 修改数据包 ---
    if (bpf_skb_adjust_room(skb, TCPOLEN_TOA, BPF_ADJ_ROOM_NET, 0))
        return TC_ACT_SHOT;

    // --- 3. "Write Later" 阶段：只写入，并使用之前保存的可信变量 ---
    struct toa_opt toa;
    toa.kind = TCPOPT_TOA;
    toa.len = TCPOLEN_TOA;
    toa.port = tcph->source; // tcph 指针虽然失效，但其内容在 adjust_room 前已验证，可用于填充 toa
    toa.ip = iph->saddr;     // 同上

    // 修正 L3 (IP) 头部
    __be16 new_tot_len = bpf_htons(bpf_ntohs(old_tot_len) + TCPOLEN_TOA);
    bpf_l3_csum_replace(skb, ip_offset + offsetof(struct iphdr, check), old_tot_len, new_tot_len, sizeof(new_tot_len));
    bpf_skb_store_bytes(skb, ip_offset + offsetof(struct iphdr, tot_len), &new_tot_len, sizeof(new_tot_len), 0);

    // 修正 L4 (TCP) 头部
    __u8 new_doff_byte = ((old_tcp_len + TCPOLEN_TOA) / 4) << 4; 
    // 使用之前保存的 ip_hdr_len，不再从失效的 iph 指针读取
    bpf_skb_store_bytes(skb, ip_offset + ip_hdr_len + 12, &new_doff_byte, sizeof(new_doff_byte), 0);
    
    // 写入 TOA 选项，并让内核重算 L4 校验和
    bpf_skb_store_bytes(skb, ip_offset + ip_hdr_len + old_tcp_len, &toa, TCPOLEN_TOA, BPF_F_RECOMPUTE_CSUM);

    // 记录日志 (iph 和 tcph 指针已失效，但其内容已保存到 event 结构体)
    struct log_event event;
    event.src_ip = iph->saddr;
    event.dst_ip = iph->daddr;
    event.src_port = tcph->source;
    event.dst_port = old_tcp_len;
    bpf_perf_event_output(skb, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
