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

// --- 结构体 ---
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

// --- Map 定义 (最稳健写法) ---
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

SEC("tc")
int tc_proxy_protocol(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    // --- 1. 基础解析 (只读，不动指针) ---
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;
    if (iph->protocol != IPPROTO_TCP) return TC_ACT_OK;

    // 仅支持标准 20 字节 IP 头
    if ((iph->ver_ihl & 0x0F) != 5) return TC_ACT_OK;

    struct tcphdr *tcph = (void *)iph + 20;
    if ((void *)(tcph + 1) > data_end) return TC_ACT_OK;
    
    // 检查端口
    __u16 target_port = bpf_ntohs(tcph->dest);
    __u8 *val = bpf_map_lookup_elem(&ports_map, &target_port);
    if (!val || *val == 0) return TC_ACT_OK;

    // 检查 SYN
    if ((tcph->flags & 0x12) != 0x02) return TC_ACT_OK;

    // 计算 TCP 长度
    __u32 doff = (tcph->res1_doff & 0xF0) >> 4;
    if (doff < 5 || doff > 15) return TC_ACT_OK;
    __u32 tcp_len = doff * 4;

    // 保存必要信息到栈变量 (adjust_room 后指针失效)
    __u16 old_ip_len = bpf_ntohs(iph->tot_len);
    __be32 saddr = iph->saddr;
    __be32 daddr = iph->daddr;
    __be16 source = tcph->source;
    __be16 dest = tcph->dest;

    // 发送日志 (adjust_room 前发)
    struct log_event event;
    __builtin_memset(&event, 0, sizeof(event));
    event.src_ip = saddr; event.dst_ip = daddr;
    event.src_port = source; event.dst_port = dest;
    bpf_perf_event_output(skb, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    // --- 2. 构造 PP Header ---
    struct pp_v2_header pp_hdr;
    __builtin_memset(&pp_hdr, 0, sizeof(pp_hdr));
    pp_hdr.sig[0] = 0x0D; pp_hdr.sig[1] = 0x0A;
    pp_hdr.sig[2] = 0x0D; pp_hdr.sig[3] = 0x0A;
    pp_hdr.sig[4] = 0x00; pp_hdr.sig[5] = 0x0D;
    pp_hdr.sig[6] = 0x0A; pp_hdr.sig[7] = 0x51;
    pp_hdr.sig[8] = 0x55; pp_hdr.sig[9] = 0x49;
    pp_hdr.sig[10] = 0x54; pp_hdr.sig[11] = 0x0A;
    pp_hdr.ver_cmd = 0x21;
    pp_hdr.fam     = 0x11;
    pp_hdr.len     = bpf_htons(12);
    pp_hdr.addr.ipv4.src_addr = saddr;
    pp_hdr.addr.ipv4.dst_addr = daddr;
    pp_hdr.addr.ipv4.src_port = source;
    pp_hdr.addr.ipv4.dst_port = dest;

    // --- 3. 扩容 ---
    // 在 L3 (IP) 后面增加 12 字节
    if (bpf_skb_adjust_room(skb, 12, BPF_ADJ_ROOM_NET, 0))
        return TC_ACT_SHOT;

    // --- 4. 搬运 TCP 头 ---
    // 现在的布局: [ETH 14] [GAP 12] [IP 20] [TCP N]
    // 目标布局:   [ETH 14] [IP 20] [TCP N] [GAP 12]
    
    // a. 先把 IP 头搬到前面 (填补 GAP 的前 12 字节，留出后面空隙) -> 错！
    // 正确逻辑：
    // 旧 TCP 位置: 14 + 12 + 20 = 46
    // 新 TCP 位置: 14 + 20 = 34
    // 移动距离: 12 字节
    
    // 我们先把 IP 头从 (14+12) 搬到 14
    unsigned char ip_buf[20];
    if (bpf_skb_load_bytes(skb, 34, ip_buf, 20)) return TC_ACT_SHOT;
    if (bpf_skb_store_bytes(skb, 14, ip_buf, 20, 0)) return TC_ACT_SHOT;

    // b. 再搬运 TCP 头
    // 旧位置: 46 (34+12)
    // 新位置: 34
    
    unsigned char tcp_buf[60]; // 最大栈空间
    
    // 笨办法：穷举所有可能的长度。验证器最喜欢这种确定的代码。
    switch (tcp_len) {
        case 20:
            if (bpf_skb_load_bytes(skb, 46, tcp_buf, 20)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, 34, tcp_buf, 20, 0)) return TC_ACT_SHOT;
            break;
        case 24:
            if (bpf_skb_load_bytes(skb, 46, tcp_buf, 24)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, 34, tcp_buf, 24, 0)) return TC_ACT_SHOT;
            break;
        case 28:
            if (bpf_skb_load_bytes(skb, 46, tcp_buf, 28)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, 34, tcp_buf, 28, 0)) return TC_ACT_SHOT;
            break;
        case 32:
            if (bpf_skb_load_bytes(skb, 46, tcp_buf, 32)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, 34, tcp_buf, 32, 0)) return TC_ACT_SHOT;
            break;
        case 36:
            if (bpf_skb_load_bytes(skb, 46, tcp_buf, 36)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, 34, tcp_buf, 36, 0)) return TC_ACT_SHOT;
            break;
        case 40:
            if (bpf_skb_load_bytes(skb, 46, tcp_buf, 40)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, 34, tcp_buf, 40, 0)) return TC_ACT_SHOT;
            break;
        case 44:
            if (bpf_skb_load_bytes(skb, 46, tcp_buf, 44)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, 34, tcp_buf, 44, 0)) return TC_ACT_SHOT;
            break;
        case 48:
            if (bpf_skb_load_bytes(skb, 46, tcp_buf, 48)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, 34, tcp_buf, 48, 0)) return TC_ACT_SHOT;
            break;
        default:
            // 极其罕见的情况，为了安全直接放弃注入，而不是让程序崩掉
            return TC_ACT_OK;
    }

    // --- 5. 写入 PP Header ---
    // 位置: 14 + 20 + tcp_len
    __u32 pp_off = 34 + tcp_len;
    // BPF_F_RECOMPUTE_CSUM (1) 更新 TCP 校验和
    if (bpf_skb_store_bytes(skb, pp_off, &pp_hdr, 12, 1)) 
        return TC_ACT_SHOT;

    // --- 6. 修复 IP 头 ---
    // 因为我们搬运了 IP 头，现在要改它的长度和校验和
    // 位置: 14
    __u16 new_len = old_ip_len + 12;
    __be32 old_l = bpf_htons(old_ip_len);
    __be32 new_l = bpf_htons(new_len);
    
    // 更新 IP 校验和 (offset 24 = 14 + 10)
    if (bpf_l3_csum_replace(skb, 24, old_l, new_l, 2))
        return TC_ACT_SHOT;

    // 更新 IP 长度 (offset 16 = 14 + 2)
    __be16 new_len_be = bpf_htons(new_len);
    if (bpf_skb_store_bytes(skb, 16, &new_len_be, 2, 0))
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
