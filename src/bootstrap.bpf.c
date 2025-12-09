// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define ETH_HLEN 14

struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16 h_proto;
};

struct iphdr {
    __u8 ver_ihl;
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __u16 check;
    __be32 saddr;
    __be32 daddr;
};

struct tcphdr {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u8 res1_doff;
    __u8 flags;
    __be16 window;
    __u16 check;
    __u16 urg_ptr;
};

// 调试类型枚举
enum {
    DBG_NONE = 0,
    DBG_ETH_PROTO,
    DBG_IP_VER,
    DBG_IP_PROTO,
    DBG_PORT_MISMATCH,
    DBG_MAP_HIT,
    DBG_SUCCESS
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, __u16);
    __type(value, __u8);
    __uint(map_flags, 0);
} ports_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 128);
    __uint(map_flags, 0);
} log_events SEC(".maps");

static __always_inline void send_debug(struct __sk_buff *skb, int type, int val1, int val2) {
    struct log_event event;
    __builtin_memset(&event, 0, sizeof(event));
    event.src_ip = type; 
    event.src_port = val1;
    event.dst_port = val2;
    bpf_perf_event_output(skb, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
}

SEC("tc")
int tc_toa_injector(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;

    // 1. 检查以太网类型
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        // 如果不是 IP 包，忽略
        return TC_ACT_OK;
    }

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;

    // 2. 检查 IP 版本
    if ((iph->ver_ihl & 0xF0) != 0x40) {
        return TC_ACT_OK;
    }

    // 3. 检查 TCP
    if (iph->protocol != IPPROTO_TCP) {
        return TC_ACT_OK;
    }

    __u32 ihl = iph->ver_ihl & 0x0F;
    struct tcphdr *tcph = (void *)iph + (ihl * 4);
    if ((void *)(tcph + 1) > data_end) return TC_ACT_OK;
    
    // 获取目标端口
    __u16 dst_port_net = tcph->dest;
    __u16 dst_port_host = bpf_ntohs(dst_port_net);

    // 4. Map 查找测试
    // 先查主机序 (32499)
    __u8 *val_host = bpf_map_lookup_elem(&ports_map, &dst_port_host);
    // 再查网络序 (0x7EF3)
    __u8 *val_net = bpf_map_lookup_elem(&ports_map, &dst_port_net);

    // 只要有一个命中，就说明是我们的包
    if (val_host || val_net) {
        send_debug(skb, DBG_MAP_HIT, dst_port_host, dst_port_net);
        // 这里可以继续执行注入逻辑...
        return TC_ACT_OK;
    }

    // 5. 没命中 Map，但端口如果是 32499，说明 Map 写入有问题！
    if (dst_port_host == 32499 || dst_port_net == 32499) {
        send_debug(skb, DBG_PORT_MISMATCH, dst_port_host, dst_port_net);
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
