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
#define TCPOPT_TOA  254  // 自定义 TOA Option ID (通常用 200 或 254)
#define TCPOLEN_TOA 8    // Kind(1) + Len(1) + Port(2) + IP(4) = 8 bytes

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

// TOA 结构体
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
int tc_toa_injector(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;
    if (iph->protocol != IPPROTO_TCP) return TC_ACT_OK;

    if ((iph->ver_ihl & 0x0F) != 5) return TC_ACT_OK;

    struct tcphdr *tcph = (void *)iph + 20;
    if ((void *)(tcph + 1) > data_end) return TC_ACT_OK;
    
    __u16 target_port = bpf_ntohs(tcph->dest);
    __u8 *val = bpf_map_lookup_elem(&ports_map, &target_port);
    if (!val || *val == 0) return TC_ACT_OK;

    // ⚠️ 关键：TOA 只能在 SYN 包插入
    // 且不能是 SYN-ACK (Flags=0x12)，必须是纯 SYN (0x02)
    if ((tcph->flags & 0x12) != 0x02) return TC_ACT_OK;

    // 检查 TCP 选项空间是否足够
    // TCP 头最大 60 字节。标准头 20。我们还要插 8 字节。
    // 所以原 TCP 头长度不能超过 52 (60-8)。
    __u32 doff = (tcph->res1_doff & 0xF0) >> 4;
    if (doff > 13) return TC_ACT_OK; // 13 * 4 = 52

    // 准备日志
    struct log_event event;
    __builtin_memset(&event, 0, sizeof(event));
    event.src_ip = iph->saddr;
    event.dst_ip = iph->daddr;
    event.src_port = tcph->source;
    event.dst_port = tcph->dest;
    bpf_perf_event_output(skb, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    // --- 构造 TOA Option ---
    struct toa_opt toa;
    toa.kind = TCPOPT_TOA;
    toa.len = TCPOLEN_TOA;
    toa.port = tcph->source;
    toa.ip = iph->saddr;

    // --- 1. 扩容 TCP 头部空间 ---
    // 在 TCP 头之后 (offset: ETH+IP+TCP_LEN) 插入 8 字节
    // 这会自动更新 IP 总长度
    // 使用 BPF_ADJ_ROOM_NET 模式，会自动处理 IP/TCP 校验和的大部分工作
    // 但我们需要告诉它，我们要增加的是 Option 长度
    
    // 计算插入位置偏移量 (相对于 L3 开始)
    __u32 tcp_len = doff * 4;
    __u32 mac_len = ETH_HLEN;
    __u32 ip_len = 20;
    
    // 关键调用：调整包大小
    if (bpf_skb_adjust_room(skb, TCPOLEN_TOA, BPF_ADJ_ROOM_NET, 0))
        return TC_ACT_SHOT;

    // --- 2. 更新 TCP Data Offset ---
    // adjust_room 之后，数据被推后了，但 TCP 头的 doff 字段没变
    // 我们需要增加 2 (8字节 / 4)
    // 因为 skb 变了，重新加载指针
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    
    eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_SHOT;
    iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return TC_ACT_SHOT;
    
    // 重新定位 TCP 头 (注意 IP 头不需要动)
    tcph = (void *)iph + 20;
    if ((void *)(tcph + 1) > data_end) return TC_ACT_SHOT;

    // 更新 doff
    __u8 old_doff_byte = tcph->res1_doff;
    __u8 new_doff = doff + 2; // +8 bytes = +2 words
    __u8 new_doff_byte = (new_doff << 4) | (old_doff_byte & 0x0F);
    
    // 更新 doff 并修正 TCP 校验和
    // 偏移量：ETH(14) + IP(20) + 12 (offset of res1_doff in tcphdr) = 46
    // 这里只需要 update store，内核会自动处理增量 checksum 如果我们用了 adjust_room
    // 但更稳妥的是用 csum_replace
    // 不过对于 1 字节的修改，直接 store 且带 CSUM flag 是最简单的
    // 注意：TCP 校验和包含头部，所以必须更新
    
    // 计算 doff 在 skb 中的绝对偏移
    __u32 doff_offset = ETH_HLEN + 20 + 12;
    if (bpf_skb_store_bytes(skb, doff_offset, &new_doff_byte, 1, BPF_F_RECOMPUTE_CSUM))
        return TC_ACT_SHOT;

    // --- 3. 写入 TOA Option ---
    // 插入位置：紧跟在原 TCP 头后面
    // 原 TCP 头长度 tcp_len
    // 绝对偏移：ETH + IP + tcp_len
    __u32 toa_offset = ETH_HLEN + 20 + tcp_len;
    
    if (bpf_skb_store_bytes(skb, toa_offset, &toa, TCPOLEN_TOA, BPF_F_RECOMPUTE_CSUM))
        return TC_ACT_SHOT;

    // --- 4. 修复 IP 校验和 ---
    // adjust_room 更新了 skb->len，但 IP 头里的 tot_len 还是旧的？
    // 实际上 bpf_skb_adjust_room(NET) 会自动更新 IP Total Length 和 IP Checksum！
    // 所以我们不需要手动修 IP 头。
    
    // ⚠️ 唯一需要手动修的是 TCP 伪首部校验和 ⚠️
    // 因为 TCP 长度变了 (+8)
    __u32 tcp_csum_off = ETH_HLEN + 20 + 16;
    __u32 old_tcp_seg_len = tcp_len; // SYN 包 payload 为 0，段长 = 头长
    __u32 new_tcp_seg_len = tcp_len + 8;
    
    __be32 old_csum = bpf_htons(old_tcp_seg_len);
    __be32 new_csum = bpf_htons(new_tcp_seg_len);
    
    if (bpf_l4_csum_replace(skb, tcp_csum_off, old_csum, new_csum, BPF_F_PSEUDO_HDR))
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
