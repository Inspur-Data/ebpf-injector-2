// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <arpa/inet.h>       // <-- 1. 包含用于 IP 地址转换的头文件
#include <bpf/libbpf.h>
#include "bootstrap.skel.h"
#include "common.h"          // <-- 2. 包含我们新的共享头文件

static volatile bool exiting = false;

static void sig_handler(int sig) {
    exiting = true;
}

// <-- 3. 这是处理从内核收到的日志事件的回调函数
void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    const struct log_event *e = data;
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];

    // 将 IP 地址从数字格式转换成字符串格式
    inet_ntop(AF_INET, &e->src_ip, src_ip_str, sizeof(src_ip_str));
    inet_ntop(AF_INET, &e->dst_ip, dst_ip_str, sizeof(dst_ip_str));

    // 打印格式化的日志
    printf("[LOG] Injected PPv2 for flow: %s:%d -> %s:%d\n",
           src_ip_str, ntohs(e->src_port), dst_ip_str, ntohs(e->dst_port));
}

// (parse_and_update_ports 函数保持不变)
void parse_and_update_ports(struct bpf_map *map, char *ports_str) {
    // ... 此函数内容无任何变化 ...
    if (!map) return;
    char *ports_copy = strdup(ports_str);
    if (!ports_copy) { perror("strdup"); return; }
    char *port_token = strtok(ports_copy, ",");
    while (port_token != NULL) {
        char *range_sep = strchr(port_token, '-');
        if (range_sep) {
            *range_sep = '\0';
            int start_port = atoi(port_token);
            int end_port = atoi(range_sep + 1);
            if (start_port > 0 && end_port > 0 && end_port >= start_port) {
                printf("Enabling Proxy Protocol for port range %d-%d\n", start_port, end_port);
                for (int port = start_port; port <= end_port; port++) {
                    __u16 p = (__u16)port; __u8 v = 1;
                    bpf_map__update_elem(map, &p, sizeof(p), &v, sizeof(v), BPF_ANY);
                }
            }
        } else {
            int port = atoi(port_token);
            if (port > 0 && port < 65536) {
                __u16 p = (__u16)port; __u8 v = 1;
                bpf_map__update_elem(map, &p, sizeof(p), &v, sizeof(v), BPF_ANY);
                printf("Enabled Proxy Protocol for port %d\n", port);
            }
        }
        port_token = strtok(NULL, ",");
    }
    free(ports_copy);
}

int main(int argc, char **argv) {
    struct bootstrap_bpf *skel;
    struct perf_buffer *pb = NULL; // <-- 4. 声明 Perf Buffer 对象
    int ifindex, err;
    char *iface, *ports_str;
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .attach_point = BPF_TC_INGRESS);

    if (argc != 3) { fprintf(stderr, "Usage: %s <interface> <port_list>\n", argv[0]); return 1; }
    iface = argv[1]; ports_str = argv[2];
    ifindex = if_nametoindex(iface);
    if (!ifindex) { perror("if_nametoindex"); return 1; }
    
    skel = bootstrap_bpf__open_and_load();
    if (!skel) { fprintf(stderr, "ERROR: Failed to open and load BPF skeleton\n"); return 1; }

    parse_and_update_ports(skel->maps.ports_map, ports_str);
    
    // <-- 5. 设置 Perf Buffer
    pb = perf_buffer__new(bpf_map__fd(skel->maps.log_events), 8, handle_event, NULL, NULL, NULL);
    if (!pb) { err = -errno; fprintf(stderr, "Failed to setup perf buffer: %d\n", err); goto cleanup; }

    tc_hook.ifindex = ifindex;
    bpf_tc_hook_destroy(&tc_hook); // Clean up old hooks first
    err = bpf_tc_hook_create(&tc_hook);
    if (err && err != -EEXIST) { fprintf(stderr, "Failed to create TC hook: %s\n", strerror(-err)); goto cleanup; }
    int prog_fd = bpf_program__fd(skel->progs.tc_proxy_protocol);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .prog_fd = prog_fd);
    err = bpf_tc_attach(&tc_hook, &tc_opts);
    if (err) { fprintf(stderr, "Failed to attach TC program: %s\n", strerror(-err)); goto cleanup; }

    printf("Successfully attached eBPF program to %s. Press Ctrl+C to exit.\n", iface);

    signal(SIGINT, sig_handler); signal(SIGTERM, sig_handler);
    
    // <-- 6. 修改主循环，使用 perf_buffer__poll 来等待事件
    while (!exiting) {
        err = perf_buffer__poll(pb, 100 /* timeout, ms */);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling perf buffer: %s\n", strerror(-err));
            goto cleanup;
        }
    }

cleanup:
    printf("\nDetaching eBPF program and cleaning up...\n");
    bpf_tc_hook_destroy(&tc_hook);
    perf_buffer__free(pb); // <-- 7. 释放 Perf Buffer
    bootstrap_bpf__destroy(skel);
    return 0;
}
