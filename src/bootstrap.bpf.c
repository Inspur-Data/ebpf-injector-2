// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6

// 诊断模式：只读，不注入
SEC("tc")
int tc_toa_injector(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    // 我们直接暴力读取前 64 字节，人工分析
    unsigned char buf[64];
    if (bpf_skb_load_bytes(skb, 0, buf, 64)) return TC_ACT_OK;

    // 目标端口 32499 = 0x7EF3 (Big Endian: 7E F3)
    // 我们检查两个最常见的位置：
    // 1. 无 VLAN: ETH(14) + IP(20) + SrcPort(2) = 36
    // 2. 单 VLAN: ETH(14) + VLAN(4) + IP(20) + SrcPort(2) = 40
    
    int is_target = 0;
    int offset_mode = 0; // 0=std, 1=vlan

    if (buf[36] == 0x7E && buf[37] == 0xF3) {
        is_target = 1;
        offset_mode = 0;
    } else if (buf[40] == 0x7E && buf[41] == 0xF3) {
        is_target = 1;
        offset_mode = 1;
    }

    if (is_target) {
        struct log_event event;
        __builtin_memset(&event, 0, sizeof(event));
        
        // 抓取快照
        __builtin_memcpy(event.payload, buf, 64);

        // 分析 TCP 头信息
        // TCP 头开始位置: 
        // Mode 0: 14 + 20 = 34
        // Mode 1: 18 + 20 = 38
        int tcp_start = (offset_mode == 0) ? 34 : 38;
        
        // Data Offset (Header Length) 在 TCP 头的第 12 字节
        // 高 4 位
        __u8 doff_raw = buf[tcp_start + 12];
        __u8 doff = (doff_raw & 0xF0) >> 4;
        
        // Flags 在 TCP 头的第 13 字节
        __u8 flags = buf[tcp_start + 13];

        // 将诊断信息填入 event
        // src_ip = 0xDEB06 (DEBUG)
        event.src_ip = 0xDEB06; 
        
        // dst_ip = Offset Mode (告诉我是不是 VLAN)
        event.dst_ip = offset_mode;

        // src_port = TCP Flags (看看是不是 SYN=2)
        event.src_port = flags;

        // dst_port = TCP Header Length (看看是不是 5 或 8)
        event.dst_port = doff * 4; // 字节数

        bpf_perf_event_output(skb, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
