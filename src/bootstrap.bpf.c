// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6

// --- 补回 log_events ---
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 128);
    __uint(map_flags, 0);
} log_events SEC(".maps");

// --- 补回 ports_map (占位，防止报错) ---
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u16);
    __type(value, __u8);
    __uint(map_flags, 0);
} ports_map SEC(".maps");

// 诊断模式：只读，不注入
SEC("tc")
int tc_toa_injector(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    unsigned char buf[64];
    if (bpf_skb_load_bytes(skb, 0, buf, 64)) return TC_ACT_OK;

    int is_target = 0;
    int offset_mode = 0;

    // 检查 Offset 36 (无VLAN)
    if (buf[36] == 0x7E && buf[37] == 0xF3) {
        is_target = 1;
        offset_mode = 0;
    } 
    // 检查 Offset 40 (有VLAN)
    else if (buf[40] == 0x7E && buf[41] == 0xF3) {
        is_target = 1;
        offset_mode = 1;
    }

    if (is_target) {
        struct log_event event;
        __builtin_memset(&event, 0, sizeof(event));
        
        __builtin_memcpy(event.payload, buf, 64);

        int tcp_start = (offset_mode == 0) ? 34 : 38;
        
        __u8 doff_raw = buf[tcp_start + 12];
        __u8 doff = (doff_raw & 0xF0) >> 4;
        __u8 flags = buf[tcp_start + 13];

        event.src_ip = 0xDEB06; 
        event.dst_ip = offset_mode;
        event.src_port = flags;
        event.dst_port = doff * 4;

        bpf_perf_event_output(skb, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
