// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/resource.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include "bootstrap.skel.h"
#include "common.h"

// 全局变量，用于信号处理，优雅地退出程序
static volatile bool exiting = false;

// 信号处理函数
static void sig_handler(int sig) {
    exiting = true;
}

// libbpf 的日志回调函数，可以过滤掉一些不必要的信息
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    // 您可以根据需要调整日志级别，LIBBPF_WARN 是一个不错的选择
    if (level > LIBBPF_WARN) {
        return 0;
    }
    return vfprintf(stderr, format, args);
}

// perf buffer 的事件处理回调函数，当 eBPF 程序发送数据时被调用
void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    const struct log_event *e = data;
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    
    // 将 IP 地址从网络字节序转换成点分十进制字符串
    inet_ntop(AF_INET, &e->src_ip, src, sizeof(src));
    inet_ntop(AF_INET, &e->dst_ip, dst, sizeof(dst));
    
    // 这里的 dst_port 实际上是我们回传的原始 TCP Header Length，用于调试
    fprintf(stdout, "[LOG] TOA Injected! Src: %s:%d -> Dst: %s (Original TCP Hdr Len: %d)\n", 
           src, ntohs(e->src_port), dst, e->dst_port);
}

// 解析用户输入的端口字符串（如 "80,443,8000-8080"）并更新 eBPF map
void parse_and_update_ports(struct bpf_map *map, char *ports_str) {
    if (!map) return;

    char *ports_copy = strdup(ports_str);
    if (!ports_copy) {
        perror("strdup");
        return;
    }

    char *p = strtok(ports_copy, ",");
    while (p) {
        int start = atoi(p), end = start;
        char *dash = strchr(p, '-');
        if (dash) {
            end = atoi(dash + 1);
        }

        if (start > 0 && end >= start && start <= 65535 && end <= 65535) {
            for (int port = start; port <= end; port++) {
                __u16 k = port;
                __u8 v = 1;
                // 将端口号作为 key 写入 map
                bpf_map__update_elem(map, &k, sizeof(k), &v, sizeof(v), BPF_ANY);
            }
            fprintf(stderr, "INFO: Enabled ports range: %d-%d\n", start, end);
        } else {
            fprintf(stderr, "WARN: Invalid port or range: %s\n", p);
        }
        p = strtok(NULL, ",");
    }
    free(ports_copy);
}

int main(int argc, char **argv) {
    struct bootstrap_bpf *skel = NULL;
    struct perf_buffer *pb = NULL;
    struct bpf_tc_hook tc_hook;
    struct bpf_tc_opts tc_opts;
    int ifindex;
    int err = 0;

    // 推荐在函数开头就将结构体清零，防止使用到未初始化的值
    memset(&tc_hook, 0, sizeof(tc_hook));
    memset(&tc_opts, 0, sizeof(tc_opts));

    // 禁用标准输出/错误的缓冲，确保日志能实时打印
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    
    libbpf_set_print(libbpf_print_fn);

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <interface> <ports>\n", argv[0]);
        return 1;
    }

    // 提升 RLIMIT_MEMLOCK 限制，这是 eBPF 程序加载所必需的
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        return 1;
    }

    // 将网络接口名称（如 "eth0"）转换为内核使用的接口索引
    ifindex = if_nametoindex(argv[1]);
    if (!ifindex) {
        perror("if_nametoindex");
        return 1;
    }

    // 打开 eBPF 骨架文件
    skel = bootstrap_bpf__open();
    if (!skel) {
        fprintf(stderr, "ERROR: Failed to open BPF skeleton\n");
        return 1;
    }

    // --- 重新加入的逻辑 ---
    // 强制清零所有 map 的 flags，以防止潜在的 Exclusivity 错误
    // 这在某些特定环境或旧内核下可能是一个有效的 workaround
    struct bpf_map *map;
    bpf_object__for_each_map(map, skel->obj) {
        bpf_map__set_map_flags(map, 0);
    }
    // ----------------------

    // 加载 eBPF 程序和 map 到内核
    if (bootstrap_bpf__load(skel)) {
        fprintf(stderr, "ERROR: Failed to load BPF skeleton\n");
        err = 1;
        goto cleanup;
    }

    // 解析用户指定的端口并更新 map
    parse_and_update_ports(skel->maps.ports_map, argv[2]);

    // 创建 perf buffer，用于接收内核 eBPF 程序的日志事件
    pb = perf_buffer__new(bpf_map__fd(skel->maps.log_events), 8, handle_event, NULL, NULL, NULL);
    if (!pb) {
        err = -errno;
        fprintf(stderr, "ERROR: Failed to create perf buffer: %d\n", err);
        goto cleanup;
    }

    // --- TC eBPF 附加逻辑 ---
    tc_hook.sz = sizeof(tc_hook);
    tc_hook.ifindex = ifindex;
    tc_hook.attach_point = BPF_TC_INGRESS; // 挂载到 ingress hook 点

    // 创建 TC hook，这会在指定的网卡上创建一个 clsact qdisc (如果它还不存在)
    if (bpf_tc_hook_create(&tc_hook) < 0) {
        fprintf(stderr, "ERROR: Failed to create TC hook on interface %s: %s\n", argv[1], strerror(errno));
        err = 1;
        goto cleanup;
    }

    tc_opts.sz = sizeof(tc_opts);
    tc_opts.prog_fd = bpf_program__fd(skel->progs.tc_toa_injector);
    
    // (可选但推荐) 先尝试分离一次，确保环境干净，防止附加失败
    bpf_tc_detach(&tc_hook, &tc_opts); 
    
    // 将 eBPF 程序附加到 TC hook 上
    if (bpf_tc_attach(&tc_hook, &tc_opts) < 0) {
        fprintf(stderr, "ERROR: Failed to attach TC program to interface %s: %s\n", argv[1], strerror(errno));
        err = 1;
        goto cleanup;
    }
    
    fprintf(stdout, "Successfully attached TOA injector to interface %s. Watching for events... Press Ctrl+C to exit.\n", argv[1]);
    
    // 注册信号处理，以便可以优雅地退出
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    // --- 主循环，保持程序运行 ---
    while (!exiting) {
        // 从 perf buffer 中轮询事件，超时时间 100 毫秒
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "ERROR: Polling perf buffer: %s\n", strerror(-err));
            break; // 出现错误，退出循环
        }
    }
    fprintf(stdout, "\nExiting...\n");

cleanup:
    // 只有在程序准备退出或中途出错时，才会执行这里的清理代码
    fprintf(stdout, "Detaching TC program and cleaning up resources...\n");
    if (tc_hook.ifindex) {
        // 销毁 TC hook，这会移除 eBPF 程序和 clsact qdisc
        bpf_tc_hook_destroy(&tc_hook);
    }
    // 释放 perf buffer
    if (pb) perf_buffer__free(pb);
    // 销毁 eBPF 骨架，释放所有相关资源
    if (skel) bootstrap_bpf__destroy(skel);
    
    return -err;
}
