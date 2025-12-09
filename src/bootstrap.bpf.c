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
#define TCPOPT_TOA  254
#define TCPOLEN_TOA 8

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

    // 仅拦截 SYN 包 (无 ACK)
    if ((tcph->flags & 0x12) != 0x02) return TC_ACT_OK;

    // 检查 TCP 头部长度，只支持标准 20 字节
    // 如果客户端发送了带 Option 的 SYN (如 TimeStamp)，我们为了安全不注入 TOA
    // 这会覆盖绝大多数情况
    __u32 doff = (tcph->res1_doff & 0xF0) >> 4;
    if (doff != 5) return TC_ACT_OK; 

    // 准备日志
    struct log_event event;
    __builtin_memset(&event, 0, sizeof(event));
    event.src_ip = iph->saddr;
    event.dst_ip = iph->daddr;
    event.src_port = tcph->source;
    event.dst_port = tcph->dest;
    bpf_perf_event_output(skb, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    // 构造 TOA
    struct toa_opt toa;
    toa.kind = TCPOPT_TOA;
    toa.len = TCPOLEN_TOA;
    toa.port = tcph->source;
    toa.ip = iph->saddr;

    // --- 1. 扩容 8 字节 ---
    // 此时: [ETH] [IP] [GAP 8] [TCP]
    if (bpf_skb_adjust_room(skb, TCPOLEN_TOA, BPF_ADJ_ROOM_NET, 0))
        return TC_ACT_SHOT;

    // --- 2. 搬运 TCP 头 ---
    // 我们要把 TCP 头从 GAP 后面搬到 GAP 前面 (紧挨着 IP)
    // 这样 GAP 就会跑到 TCP 后面，成为 TCP Option 的一部分
    
    // 旧位置: ETH(14) + IP(20) + GAP(8) = 42
    // 新位置: ETH(14) + IP(20) = 34
    
    unsigned char tcp_buf[20]; // 标准 TCP 头长度
    
    // 读取旧 TCP 头
    if (bpf_skb_load_bytes(skb, 42, tcp_buf, 20)) return TC_ACT_SHOT;
    
    // 修改 TCP 头里的 Data Offset
    // 原来是 5 (20 bytes), 现在加了 8 bytes, 变成 7 (28 bytes)
    // res1_doff: 高4位是 doff
    // 5 << 4 = 0x50. 7 << 4 = 0x70.
    // 我们直接在 buffer 里改，这样写入时 checksum 会基于新值计算
    tcp_buf[12] = 0x70; // Set Data Offset to 7

    // 写入新位置 (并更新 TCP Checksum)
    // ⚠️ 关键: BPF_F_RECOMPUTE_CSUM (1)
    if (bpf_skb_store_bytes(skb, 34, tcp_buf, 20, 1)) return TC_ACT_SHOT;

    // --- 3. 写入 TOA Option ---
    // 位置: 34 + 20 = 54 (紧跟在 TCP 头后面)
    if (bpf_skb_store_bytes(skb, 54, &toa, TCPOLEN_TOA, 1))
        return TC_ACT_SHOT;

    // --- 4. 修复 TCP 伪首部校验和 ---
    // 因为 TCP Segment 长度增加了 8 字节
    // IP Total Length 增加了，内核 adjust_room 会自动处理 IP Checksum
    // 但 TCP Checksum 包含伪首部里的长度，需要手动更新
    
    __u32 tcp_csum_off = 34 + 16; 
    
    // SYN 包 payload 为 0
    __u32 old_len = 20;      // 旧 TCP 头长
    __u32 new_len = 20 + 8;  // 新 TCP 头长 + Option

    __be32 old_csum_val = bpf_htons(old_len);
    __be32 new_csum_val = bpf_htons(new_len);

    if (bpf_l4_csum_replace(skb, tcp_csum_off, old_csum_val, new_csum_val, BPF_F_PSEUDO_HDR))
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
