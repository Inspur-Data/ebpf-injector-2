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

    // 🔒 简化：只支持标准 20 字节 IP 头
    // 这极大地简化了逻辑，让 Verifier 更容易通过
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

    // --- 构造 PP Header ---
    struct pp_v2_header pp_hdr;
    // 初始化清零
    __builtin_memset(&pp_hdr, 0, sizeof(pp_hdr));
    // 填充签名
    pp_hdr.sig[0] = 0x0D; pp_hdr.sig[1] = 0x0A;
    pp_hdr.sig[2] = 0x0D; pp_hdr.sig[3] = 0x0A;
    pp_hdr.sig[4] = 0x00; pp_hdr.sig[5] = 0x0D;
    pp_hdr.sig[6] = 0x0A; pp_hdr.sig[7] = 0x51;
    pp_hdr.sig[8] = 0x55; pp_hdr.sig[9] = 0x49;
    pp_hdr.sig[10] = 0x54; pp_hdr.sig[11] = 0x0A;
    // 填充内容
    pp_hdr.ver_cmd = 0x21;
    pp_hdr.fam     = 0x11;
    pp_hdr.len     = bpf_htons(12);
    pp_hdr.addr.ipv4.src_addr = iph->saddr;
    pp_hdr.addr.ipv4.dst_addr = iph->daddr;
    pp_hdr.addr.ipv4.src_port = tcph->source;
    pp_hdr.addr.ipv4.dst_port = tcph->dest;

    // --- 1. 扩容 12 字节 (L3) ---
    // 之前: [ETH][IP][TCP]...
    // 之后: [ETH][ 12 ][IP][TCP]...
    if (bpf_skb_adjust_room(skb, sizeof(pp_hdr), BPF_ADJ_ROOM_NET, 0))
        return TC_ACT_SHOT;

    // --- 2. 搬运 IP 头 (20字节) ---
    // 目标: [ETH][IP][ 12 ][TCP]...
    unsigned char buf[60]; // 通用缓冲区
    
    // 从 ETH+12 读 IP 头
    if (bpf_skb_load_bytes(skb, ETH_HLEN + 12, buf, 20)) return TC_ACT_SHOT;
    // 写入到 ETH 位置
    if (bpf_skb_store_bytes(skb, ETH_HLEN, buf, 20, 0)) return TC_ACT_SHOT;

    // --- 3. 搬运 TCP 头 ---
    // 目标: [ETH][IP][TCP][ 12 ]...
    // 此时 TCP 头位于: ETH(14) + GAP(12) + IP(20) = 46
    // 我们要把它搬到: ETH(14) + IP(20) = 34
    __u32 old_tcp_off = ETH_HLEN + 12 + 20;
    __u32 new_tcp_off = ETH_HLEN + 20;

    // 使用 switch 处理变长 TCP 头，安抚 Verifier
    switch (tcp_len) {
        case 20:
            if (bpf_skb_load_bytes(skb, old_tcp_off, buf, 20)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, new_tcp_off, buf, 20, 0)) return TC_ACT_SHOT;
            break;
        case 32:
            if (bpf_skb_load_bytes(skb, old_tcp_off, buf, 32)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, new_tcp_off, buf, 32, 0)) return TC_ACT_SHOT;
            break;
        case 40: // 常见选项长度
        case 44:
            if (bpf_skb_load_bytes(skb, old_tcp_off, buf, 40)) return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb, new_tcp_off, buf, 40, 0)) return TC_ACT_SHOT;
            break;
        // 如果是其他不常见的长度，我们选择放行，不处理（避免 switch 过大报错）
        default:
            // 如果长度不是上面几种，我们无法安全搬运，为了安全起见，放弃注入
            // 这是一个权衡：覆盖 99% 的场景，换取 Verifier 通过
            return TC_ACT_OK;
    }

    // --- 4. 写入 PP Header ---
    // 此时空隙位于: ETH(14) + IP(20) + TCP(tcp_len)
    __u32 pp_offset = ETH_HLEN + 20 + tcp_len;
    
    // 写入并更新 TCP 校验和
    if (bpf_skb_store_bytes(skb, pp_offset, &pp_hdr, sizeof(pp_hdr), 1))
        return TC_ACT_SHOT;

    // --- 5. 修复 IP 头 (Length & Checksum) ---
    // 重新获取指针来修改 IP 头
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    
    struct iphdr *new_iph = (void *)((char *)data + ETH_HLEN);
    if ((void *)(new_iph + 1) > data_end) return TC_ACT_SHOT;

    __u16 old_len = bpf_ntohs(new_iph->tot_len);
    __u16 new_len = old_len + sizeof(pp_hdr);
    
    // 更新 IP 校验和
    // 使用增量更新：csum_replace(skb, offset, old, new, flags)
    // offset 是相对于 skb->data 的
    __u32 csum_off = ETH_HLEN + 10; // offsetof(iphdr, check)
    __be32 old_l = bpf_htons(old_len);
    __be32 new_l = bpf_htons(new_len);
    
    if (bpf_l3_csum_replace(skb, csum_off, old_l, new_l, 2))
        return TC_ACT_SHOT;

    // 更新长度
    new_iph->tot_len = bpf_htons(new_len);

    // 发送日志 (放在最后，成功了再发)
    struct log_event event;
    __builtin_memset(&event, 0, sizeof(event));
    event.src_ip = pp_hdr.addr.ipv4.src_addr;
    event.dst_ip = pp_hdr.addr.ipv4.dst_addr;
    event.src_port = pp_hdr.addr.ipv4.src_port;
    event.dst_port = pp_hdr.addr.ipv4.dst_port;
    bpf_perf_event_output(skb, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
