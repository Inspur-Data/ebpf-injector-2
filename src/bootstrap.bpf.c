// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "common.h" // <-- 1. 包含我们新的共享头文件

#define ETH_P_IP 0x0800
#define ETH_HLEN 14

struct pp_v2_header {
    __u8 sig[12]; __u8 ver_cmd; __u8 fam; __be16 len;
    union {
        struct { __be32 src_addr; __be32 dst_addr; __be16 src_port; __be16 dst_port; } ipv4;
    } addr;
};

// --- BPF Maps ---
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, __u16);
    __type(value, __u8);
} ports_map SEC(".maps");

// <-- 2. 定义用于发送日志的 Perf Buffer Map
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} log_events SEC(".maps");


SEC("tc")
int tc_proxy_protocol(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct tcphdr *tcph;

    if (data + sizeof(*eth) > data_end) return 0;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return 0;

    iph = data + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end) return 0;
    if (iph->protocol != IPPROTO_TCP) return 0;

    tcph = (void *)iph + iph->ihl * 4;
    if ((void *)tcph + sizeof(*tcph) > data_end) return 0;
    
    __u16 target_port = bpf_ntohs(tcph->dest);
    __u8 *val = bpf_map_lookup_elem(&ports_map, &target_port);
    if (!val || *val == 0) return 0;

    if (!(tcph->syn && !tcph->ack)) return 0;

    // <-- 3. 当我们决定要处理这个包时，发送日志！
    struct log_event event = {};
    event.src_ip = iph->saddr;
    event.dst_ip = iph->daddr;
    event.src_port = tcph->source;
    event.dst_port = tcph->dest;
    bpf_perf_event_output(skb, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    struct pp_v2_header pp_hdr;
    __builtin_memset(&pp_hdr, 0, sizeof(pp_hdr));
    __builtin_memcpy(pp_hdr.sig, "\r\n\r\n\0\r\nQUIT\n", 12);
    pp_hdr.ver_cmd = 0x21; pp_hdr.fam = 0x11; pp_hdr.len = bpf_htons(12);
    pp_hdr.addr.ipv4.src_addr = iph->saddr; pp_hdr.addr.ipv4.dst_addr = iph->daddr;
    pp_hdr.addr.ipv4.src_port = tcph->source; pp_hdr.addr.ipv4.dst_port = tcph->dest;
    
    if (bpf_skb_adjust_room(skb, sizeof(pp_hdr), BPF_ADJ_ROOM_NET, 0)) return 1;

    if (bpf_skb_store_bytes(skb, ETH_HLEN + iph->ihl * 4 + tcph->doff * 4, &pp_hdr, sizeof(pp_hdr), 0)) return 1;

    return 0;
}

char _license[] SEC("license") = "GPL";
