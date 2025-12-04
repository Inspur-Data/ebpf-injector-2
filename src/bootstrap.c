// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/resource.h> // <-- 1. 新增头文件，用于调整资源限制
#include <net/if.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include "bootstrap.skel.h"
#include "common.h"

static volatile bool exiting = false;

static void sig_handler(int sig) {
    exiting = true;
}

// <-- 2. 新增日志回调函数，用于打印 libbpf 的详细调试信息
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    // 只有在出错或需要调试时才打印 DEBUG 级别的信息
    // 这里我们全部打印，以便排查 -EACCES 问题
    return vfprintf(stderr, format, args);
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    const struct log_event *e = data;
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &e->src_ip, src_ip_str, sizeof(src_ip_str));
    inet_ntop(AF_INET, &e->dst_ip, dst_ip_str, sizeof(dst_ip_str));

    printf("[LOG] Injected PPv2 for flow: %s:%d -> %s:%d\n",
           src_ip_str, ntohs(e->src_port), dst_ip_str, ntohs(e->dst_port));
}

void parse_and_update_ports(struct bpf_map *map, char *ports_str) {
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
    struct perf_buffer *pb = NULL;
    int ifindex, err;
    char *iface, *ports_str;
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .attach_point = BPF_TC_INGRESS);

    // <-- 3. 设置 libbpf 的日志打印函数，一旦出错，我们需要看到 Verifier 的日志
    libbpf_set_print(libbpf_print_fn);

    if (argc != 3) { fprintf(stderr, "Usage: %s <interface> <port_list>\n", argv[0]); return 1; }
    iface = argv[1]; ports_str = argv[2];
    ifindex = if_nametoindex(iface);
    if (!ifindex) { perror("if_nametoindex"); return 1; }

    // <-- 4. 关键修复：将内存锁定限制设置为无限大
    // 这通常是容器环境中 -EACCES 错误的根本原因
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        return 1;
    }
    
    skel = bootstrap_bpf__open_and_load();
    if (!skel) { 
        // 如果这里失败了，现在的 libbpf_set_print 会在控制台打印出详细的错误日志
        fprintf(stderr, "ERROR: Failed to open and load BPF skeleton\n"); 
        return 1; 
    }

    parse_and_update_ports(skel->maps.ports_map, ports_str);
    
    pb = perf_buffer__new(bpf_map__fd(skel->maps.log_events), 8, handle_event, NULL, NULL, NULL);
    if (!pb) { err = -errno; fprintf(stderr, "Failed to setup perf buffer: %d\n", err); goto cleanup; }

    tc_hook.ifindex = ifindex;
    bpf_tc_hook_destroy(&tc_hook);
    err = bpf_tc_hook_create(&tc_hook);
    if (err && err != -EEXIST) { fprintf(stderr, "Failed to create TC hook: %s\n", strerror(-err)); goto cleanup; }
    int prog_fd = bpf_program__fd(skel->progs.tc_proxy_protocol);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .prog_fd = prog_fd);
    err = bpf_tc_attach(&tc_hook, &tc_opts);
    if (err) { fprintf(stderr, "Failed to attach TC program: %s\n", strerror(-err)); goto cleanup; }

    printf("Successfully attached eBPF program to %s. Press Ctrl+C to exit.\n", iface);

    signal(SIGINT, sig_handler); signal(SIGTERM, sig_handler);
    
    while (!exiting) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling perf buffer: %s\n", strerror(-err));
            goto cleanup;
        }
    }

cleanup:
    printf("\nDetaching eBPF program and cleaning up...\n");
    bpf_tc_hook_destroy(&tc_hook);
    perf_buffer__free(pb);
    bootstrap_bpf__destroy(skel);
    return 0;
}
