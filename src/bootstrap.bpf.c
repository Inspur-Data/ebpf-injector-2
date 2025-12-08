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

    if ((tcph->flags & 0x12) != 0x02) return TC_ACT_OK;

    __u32 doff = (tcph->res1_doff & 0xF0) >> 4;
    if (doff < 5 || doff > 15) return TC_ACT_OK;
    __u32 tcp_len = doff * 4;

    __u16 old_ip_tot_len = bpf_ntohs(iph->tot_len);

    // 准备日志结构体，但不急着发
    struct log_event event;
    __builtin_memset(&event, 0, sizeof(event));
    event.src_ip = iph->saddr;
    event.dst_ip = iph->daddr;
    event.src_port = tcph->source;
    event.dst_port = tcph->dest;

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
    pp_hdr.addr.ipv4.src_addr = iph->saddr;
    pp_hdr.addr.ipv4.dst_addr = iph->daddr;
    pp_hdr.addr.ipv4.src_port = tcph->source;
    pp_hdr.addr.ipv4.dst_port = tcph->dest;

    // 1. 扩容
    if (bpf_skb_adjust_room(skb, 12, BPF_ADJ_ROOM_NET, 0))
        return TC_ACT_SHOT;

    // 2. 搬运 IP 头
    unsigned char buf[60];
    // ❌ 之前的错误逻辑：试图从 34 读 IP 头，但那里是空的！
    // ✅ 正确逻辑：现在不需要搬运 IP 头！因为 adjust_room(NET) 是在 IP 头之后扩容的
    // IP 头还在原位 (offset 14)，只是后面多出了 12 字节空白
    // 所以我们只需要搬运 TCP 头来填补 IP 头后面的空白

    // 3. 搬运 TCP 头
    // 旧 TCP 位置: ETH(14) + IP(20) + GAP(12) = 46
    // 新 TCP 位置: ETH(14) + IP(20) = 34
    // 我们要把 46 处的数据搬到 34 处
    __u32 old_tcp_off = 46;
    __u32 new_tcp_off = 34;

    switch (tcp_len) {
        case 20:
            if (bpf_skb_load_bytes(skb, old_tcp_off, buf, 20)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, new_tcp_off, buf, 20, 1)) return TC_ACT_SHOT;
            break;
        case 32:
            if (bpf_skb_load_bytes(skb, old_tcp_off, buf, 32)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, new_tcp_off, buf, 32, 1)) return TC_ACT_SHOT;
            break;
        case 40:
            if (bpf_skb_load_bytes(skb, old_tcp_off, buf, 40)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, new_tcp_off, buf, 40, 1)) return TC_ACT_SHOT;
            break;
        case 44:
            if (bpf_skb_load_bytes(skb, old_tcp_off, buf, 44)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, new_tcp_off, buf, 44, 1)) return TC_ACT_SHOT;
            break;
        default:
            return TC_ACT_OK;
    }

    // 4. 写入 PP Header
    __u32 pp_off = 34 + tcp_len;
    if (bpf_skb_store_bytes(skb, pp_off, &pp_hdr, 12, 1)) 
        return TC_ACT_SHOT;

    // 5. 修复 IP 头
    __u16 new_len = old_ip_tot_len + 12;
    __be32 old_l = bpf_htons(old_ip_tot_len);
    __be32 new_l = bpf_htons(new_len);
    
    if (bpf_l3_csum_replace(skb, 24, old_l, new_l, 2))
        return TC_ACT_SHOT;

    __be16 new_len_be = bpf_htons(new_len);
    if (bpf_skb_store_bytes(skb, 16, &new_len_be, 2, 0))
        return TC_ACT_SHOT;

    // 6. 修复 TCP 伪首部校验和
    __u32 tcp_csum_off = 34 + 16; 
    __u32 old_tcp_seg_len = old_ip_tot_len - 20;
    __u32 new_tcp_seg_len = old_tcp_seg_len + 12;

    __be32 old_csum_val = bpf_htons(old_tcp_seg_len);
    __be32 new_csum_val = bpf_htons(new_tcp_seg_len);

    if (bpf_l4_csum_replace(skb, tcp_csum_off, old_csum_val, new_csum_val, BPF_F_PSEUDO_HDR))
        return TC_ACT_SHOT;

    // ⚠️⚠️⚠️ 抓包逻辑 ⚠️⚠️⚠️
    // 修改完成了，现在把整个包的前 100 字节读出来发送给用户态
    // 这样我们就能在日志里看到最终的包长什么样了
    bpf_skb_load_bytes(skb, 0, event.payload, 100);
    bpf_perf_event_output(skb, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
