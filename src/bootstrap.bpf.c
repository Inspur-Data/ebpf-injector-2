// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// Proxy Protocol v2 头部结构体 (这个是你自定义的，需要保留)
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

// BPF Map (保持不变)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, __u16);
    __type(value, __u8);
} ports_map SEC(".maps");


SEC("tc")
int tc_proxy_protocol(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    // 使用 vmlinux.h 提供的标准结构体
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct tcphdr *tcph;

    // ETH_HLEN, ETH_P_IP, IPPROTO_TCP 这些宏现在由 <vmlinux.h> 间接提供
    if (data + sizeof(*eth) > data_end) return 0;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return 0;

    iph = data + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end) return 0;
    if (iph->protocol != IPPROTO_TCP) return 0;

    // 注意：这里的 iph->ihl * 4 是关键，因为 ihl 是 32位字的数量
    tcph = (void *)iph + iph->ihl * 4;
    if ((void *)tcph + sizeof(*tcph) > data_end) return 0;
    
    __u16 target_port = bpf_ntohs(tcph->dest);
    __u8 *val = bpf_map_lookup_elem(&ports_map, &target_port);
    if (!val || *val == 0) return 0;

    // 只在 TCP SYN 包上注入
    if (!(tcph->syn && !tcph->ack)) return 0;

    struct pp_v2_header pp_hdr;
    __builtin_memset(&pp_hdr, 0, sizeof(pp_hdr));
    __builtin_memcpy(pp_hdr.sig, "\r\n\r\n\0\r\nQUIT\n", 12);
    pp_hdr.ver_cmd = 0x21; // PROXY command
    pp_hdr.fam     = 0x11; // TCP over IPv4
    pp_hdr.len     = bpf_htons(12);
    pp_hdr.addr.ipv4.src_addr = iph->saddr;
    pp_hdr.addr.ipv4.dst_addr = iph->daddr;
    pp_hdr.addr.ipv4.src_port = tcph->source;
    pp_hdr.addr.ipv4.dst_port = tcph->dest;
    
    // 调整 skb 缓冲区，为 PPv2 header 腾出空间
    if (bpf_skb_adjust_room(skb, sizeof(pp_hdr), BPF_ADJ_ROOM_NET, 0))
        return 1; // BPF_DROP

    // 将 PPv2 header 写入数据包
    // 注意：这里的 tcph->doff * 4 也是关键，doff 是 TCP header 的大小（32位字）
    if (bpf_skb_store_bytes(skb, ETH_HLEN + iph->ihl * 4 + tcph->doff * 4, &pp_hdr, sizeof(pp_hdr), 0))
        return 1; // BPF_DROP

    return 0; // BPF_OK
}

char _license[] SEC("license") = "GPL";
