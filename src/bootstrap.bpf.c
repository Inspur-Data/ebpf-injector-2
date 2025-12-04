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

// --- 简化的结构体定义 (避免位域) ---
struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16 h_proto;
};

struct iphdr {
    __u8 ver_ihl; // 手动处理 version 和 ihl
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
    __u8 res1_doff; // 手动处理 doff
    __u8 flags;
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

    // 1. 解析 Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    // 2. 解析 IP
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;
    if (iph->protocol != IPPROTO_TCP) return TC_ACT_OK;

    // 手动提取 IHL (Header Length)
    // iph->ver_ihl 的低4位是 IHL
    __u32 ihl = iph->ver_ihl & 0x0F;
    if (ihl < 5) return TC_ACT_OK; // 最小长度

    // 3. 解析 TCP
    // 计算 TCP 头位置: eth + ip_len
    struct tcphdr *tcph = (void *)iph + (ihl * 4);
    if ((void *)(tcph + 1) > data_end) return TC_ACT_OK;
    
    // 检查端口映射
    __u16 target_port = bpf_ntohs(tcph->dest);
    __u8 *val = bpf_map_lookup_elem(&ports_map, &target_port);
    if (!val || *val == 0) return TC_ACT_OK;

    // 检查 SYN 包 (Flags 在第13字节后)
    // 0x02 是 SYN, 0x10 是 ACK. 我们要 SYN=1, ACK=0
    if ((tcph->flags & 0x12) != 0x02) return TC_ACT_OK;

    // --- 准备数据 ---
    // 提取 TCP Data Offset
    __u32 doff = (tcph->res1_doff & 0xF0) >> 4;
    if (doff < 5) return TC_ACT_OK;

    struct log_event event = {};
    event.src_ip = iph->saddr;
    event.dst_ip = iph->daddr;
    event.src_port = tcph->source;
    event.dst_port = tcph->dest;
    bpf_perf_event_output(skb, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    // 计算插入位置: MAC + IP + TCP
    // 使用固定值计算，避免验证器认为变量不可控
    __u32 payload_offset = ETH_HLEN + (ihl * 4) + (doff * 4);

    struct pp_v2_header pp_hdr = {};
    __builtin_memcpy(pp_hdr.sig, "\r\n\r\n\0\r\nQUIT\n", 12);
    pp_hdr.ver_cmd = 0x21;
    pp_hdr.fam     = 0x11;
    pp_hdr.len     = bpf_htons(12);
    pp_hdr.addr.ipv4.src_addr = iph->saddr;
    pp_hdr.addr.ipv4.dst_addr = iph->daddr;
    pp_hdr.addr.ipv4.src_port = tcph->source;
    pp_hdr.addr.ipv4.dst_port = tcph->dest;

    // --- 修改数据包 ---
    // 1. 腾出空间
    if (bpf_skb_adjust_room(skb, sizeof(pp_hdr), BPF_ADJ_ROOM_NET, 0))
        return TC_ACT_SHOT;

    // 2. 写入数据 (使用计算好的安全偏移量)
    if (bpf_skb_store_bytes(skb, payload_offset, &pp_hdr, sizeof(pp_hdr), 0))
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

// ❌ 移除这行: char _license[] SEC("license") = "GPL";
// ✅ 改用这种方式强制定义 License 段，不生成 .rodata map
SEC("license") const char __license[] = "GPL";
