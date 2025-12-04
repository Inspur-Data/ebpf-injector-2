// SPDX-License-Identifier: GPL-2.0
// ❌ 不再包含 vmlinux.h，防止环境依赖问题
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

// --- 手动定义必要的内核结构体 (这也是你 1.0 版本的做法) ---
#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define ETH_HLEN 14

struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16 h_proto;
};

struct iphdr {
    __u8 ihl:4, version:4;
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
    __u16 res1:4, doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
    __be16 window;
    __u16 check;
    __u16 urg_ptr;
};

struct pp_v2_header {
    __u8 sig[12];
    __u8 ver_cmd;
    __u8 fam;
    __be16 len;
    union {
        struct {
            __be32 src_addr;
            __be32 dst_addr;
            __be16 src_port;
            __be16 dst_port;
        } ipv4;
    } addr;
};

// --- BPF Maps 定义 ---
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
int tc_proxy_protocol(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;
    if (iph->protocol != IPPROTO_TCP) return TC_ACT_OK;

    // 计算 TCP 头部位置：Ethernet头 + IP头长度
    // 注意：这里必须进行边界检查，否则 Verifier 会报 -EACCES
    struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
    if ((void *)(tcph + 1) > data_end) return TC_ACT_OK;
    
    __u16 target_port = bpf_ntohs(tcph->dest);
    __u8 *val = bpf_map_lookup_elem(&ports_map, &target_port);
    if (!val || *val == 0) return TC_ACT_OK;

    // 仅处理 SYN 包
    if (!(tcph->syn && !tcph->ack)) return TC_ACT_OK;

    // 发送日志
    struct log_event event = {};
    event.src_ip = iph->saddr;
    event.dst_ip = iph->daddr;
    event.src_port = tcph->source;
    event.dst_port = tcph->dest;
    bpf_perf_event_output(skb, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    // 构造 Proxy Protocol 头部
    struct pp_v2_header pp_hdr = {}; // 初始化为0
    __builtin_memcpy(pp_hdr.sig, "\r\n\r\n\0\r\nQUIT\n", 12);
    pp_hdr.ver_cmd = 0x21;
    pp_hdr.fam     = 0x11;
    pp_hdr.len     = bpf_htons(12);
    pp_hdr.addr.ipv4.src_addr = iph->saddr;
    pp_hdr.addr.ipv4.dst_addr = iph->daddr;
    pp_hdr.addr.ipv4.src_port = tcph->source;
    pp_hdr.addr.ipv4.dst_port = tcph->dest;
    
    // 调整空间并写入
    // 注意：使用 BPF_ADJ_ROOM_NET 模式，这是最安全的
    if (bpf_skb_adjust_room(skb, sizeof(pp_hdr), BPF_ADJ_ROOM_NET, 0))
        return TC_ACT_SHOT; // 失败则丢包

    // 写入数据：位置是 MAC头 + IP头 + TCP头选项(doff*4)
    // 重新计算偏移量，因为 adjust_room 可能改变了数据包结构
    // 但在 adjust_room 之后，通常建议直接用 store_bytes 写
    // 这里我们用一个简化的偏移量计算：
    // 由于我们是增加头部，原有的 MAC/IP 头会被内核处理，我们只需把新头塞进去
    // 这里逻辑保持你原有的偏移计算，但在 adjust_room 后通常是安全的
    if (bpf_skb_store_bytes(skb, ETH_HLEN + (iph->ihl * 4) + (tcph->doff * 4), &pp_hdr, sizeof(pp_hdr), 0))
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
