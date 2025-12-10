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
    if (level > LIBBPF_WARN) {
        return 0;
    }
    return vfprintf(stderr, format, args);
}

// perf buffer 的事件处理回调函数，当 eBPF 程序发送数据时被调用
void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    const struct log_event *e = data;
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &e->src_ip, src, sizeof(src));
    inet_ntop(AF_INET, &e->dst_ip, dst, sizeof(dst));
    
    fprintf(stdout, "[LOG] TOA Injected! Src: %s:%d -> Dst: %s (Original TCP Hdr Len: %d)\n", 
           src, ntohs(e->src_port), dst, e->dst_port);
}

// 解析用户输入的端口字符串并更新 eBPF map
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

    memset(&tc_hook, 0, sizeof(tc_hook));
    memset(&tc_opts, 0, sizeof(tc_opts));

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    
    libbpf_set_print(libbpf_print_fn);

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <interface> <ports>\n", argv[0]);
        return 1;
    }

    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        return 1;
    }

    ifindex = if_nametoindex(argv[1]);
    if (!ifindex) {
        perror("if_nametoindex");
        return 1;
    }

    skel = bootstrap_bpf__open();
    if (!skel) {
        fprintf(stderr, "ERROR: Failed to open BPF skeleton\n");
        return 1;
    }

    struct bpf_map *map;
    bpf_object__for_each_map(map, skel->obj) {
        bpf_map__set_map_flags(map, 0);
    }

    if (bootstrap_bpf__load(skel)) {
        fprintf(stderr, "ERROR: Failed to load BPF skeleton\n");
        err = 1;
        goto cleanup;
    }

    parse_and_update_ports(skel->maps.ports_map, argv[2]);

    pb = perf_buffer__new(bpf_map__fd(skel->maps.log_events), 8, handle_event, NULL, NULL, NULL);
    if (!pb) {
        err = -errno;
        fprintf(stderr, "ERROR: Failed to create perf buffer: %d\n", err);
        goto cleanup;
    }

    tc_hook.sz = sizeof(tc_hook);
    tc_hook.ifindex = ifindex;
    tc_hook.attach_point = BPF_TC_INGRESS;

    // --- 最终的、健壮的 TC Hook 创建逻辑 ---
    if (bpf_tc_hook_create(&tc_hook) < 0) {
        // 如果错误不是 EEXIST (File exists)，那才是真正的错误
        if (errno != EEXIST) {
            fprintf(stderr, "ERROR: Failed to create TC hook on interface %s: %s\n", argv[1], strerror(errno));
            err = 1;
            goto cleanup;
        }
        // 如果错误是 EEXIST，说明 hook 已经在了，这是好事，打印一条信息然后继续即可
        fprintf(stderr, "INFO: TC hook already exists on interface %s. Continuing.\n", argv[1]);
    }

    tc_opts.sz = sizeof(tc_opts);
    tc_opts.prog_fd = bpf_program__fd(skel->progs.tc_toa_injector);
    
    bpf_tc_detach(&tc_hook, &tc_opts); 
    
    if (bpf_tc_attach(&tc_hook, &tc_opts) < 0) {
        fprintf(stderr, "ERROR: Failed to attach TC program to interface %s: %s\n", argv[1], strerror(errno));
        err = 1;
        goto cleanup;
    }
    
    fprintf(stdout, "Successfully attached TOA injector to interface %s. Watching for events... Press Ctrl+C to exit.\n", argv[1]);
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    while (!exiting) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "ERROR: Polling perf buffer: %s\n", strerror(-err));
            break;
        }
    }
    fprintf(stdout, "\nExiting...\n");

cleanup:
    fprintf(stdout, "Detaching TC program and cleaning up resources...\n");
    if (tc_hook.ifindex) {
        bpf_tc_hook_destroy(&tc_hook);
    }
    if (pb) perf_buffer__free(pb);
    if (skel) bootstrap_bpf__destroy(skel);
    
    return -err;
}
