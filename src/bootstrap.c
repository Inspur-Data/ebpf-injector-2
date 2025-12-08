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
#include <time.h>
#include <sys/time.h> // 用于获取毫秒时间
#include "bootstrap.skel.h"
#include "common.h"

static volatile bool exiting = false;

static void sig_handler(int sig) { exiting = true; }

// 获取当前时间戳字符串 [HH:MM:SS.ms]
void log_prefix() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm *tm_info = localtime(&tv.tv_sec);
    char buffer[26];
    strftime(buffer, 26, "%H:%M:%S", tm_info);
    fprintf(stdout, "[%s.%03ld] ", buffer, tv.tv_usec / 1000);
}

// 包装 printf，自动加时间戳和换行
#define LOG(fmt, ...) do { log_prefix(); fprintf(stdout, fmt "\n", ##__VA_ARGS__); } while(0)

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    char buf[1024];
    vsnprintf(buf, sizeof(buf), format, args);
    // 过滤掉 Exclusivity 噪音
    if (strstr(buf, "Exclusivity flag on")) return 0;
    // libbpf 日志写到 stderr
    return vfprintf(stderr, format, args);
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    const struct log_event *e = data;
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &e->src_ip, src, sizeof(src));
    inet_ntop(AF_INET, &e->dst_ip, dst, sizeof(dst));
    LOG("Proxy Protocol Injected: %s:%d -> %s:%d", 
        src, ntohs(e->src_port), dst, ntohs(e->dst_port));
}

void parse_and_update_ports(struct bpf_map *map, char *ports_str) {
    if (!map) return;
    
    LOG("DEBUG: Start parsing ports: '%s'", ports_str);
    
    char *ports_copy = strdup(ports_str);
    char *p = strtok(ports_copy, ",");
    int count = 0;

    while (p) {
        int start = atoi(p), end = start;
        char *dash = strchr(p, '-');
        if (dash) end = atoi(dash + 1);
        
        LOG("DEBUG: Processing range %d-%d", start, end);
        
        for (int port = start; port <= end; port++) {
            __u16 k = port; __u8 v = 1;
            // 记录一下更新 Map 是否耗时
            if (bpf_map__update_elem(map, &k, sizeof(k), &v, sizeof(v), BPF_ANY)) {
                 fprintf(stderr, "Failed to update port %d\n", port);
            }
            count++;
        }
        p = strtok(NULL, ",");
    }
    free(ports_copy);
    LOG("DEBUG: Finished updating ports map. Total ports: %d", count);
}

int main(int argc, char **argv) {
    struct bootstrap_bpf *skel;
    struct perf_buffer *pb = NULL;
    int ifindex;

    // 1. 🚨 关键：禁用 stdout 缓冲，确保日志通过 kubectl logs 立即显示
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    
    LOG("🚀 Starting ebpf-injector...");
    
    libbpf_set_print(libbpf_print_fn);

    if (argc != 3) {
        LOG("Usage: %s <interface> <port_list>", argv[0]);
        return 1;
    }

    LOG("DEBUG: Arguments received: iface=%s, ports=%s", argv[1], argv[2]);

    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &r);

    ifindex = if_nametoindex(argv[1]);
    if (!ifindex) { perror("if_nametoindex"); return 1; }

    LOG("DEBUG: Opening and Loading Skeleton (This might take a moment)...");
    skel = bootstrap_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "!!! FAILED TO LOAD SKELETON !!!\n");
        return 1;
    }
    LOG("DEBUG: Skeleton loaded successfully.");

    LOG("DEBUG: Updating Maps...");
    parse_and_update_ports(skel->maps.ports_map, argv[2]);

    pb = perf_buffer__new(bpf_map__fd(skel->maps.log_events), 8, handle_event, NULL, NULL, NULL);

    LOG("DEBUG: Creating and Attaching TC Hook...");
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS);
    
    // 忽略错误
    bpf_tc_hook_create(&tc_hook);
    
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .prog_fd = bpf_program__fd(skel->progs.tc_proxy_protocol));
    bpf_tc_detach(&tc_hook, &tc_opts); 
    
    if (bpf_tc_attach(&tc_hook, &tc_opts)) {
        fprintf(stderr, "Failed to attach TC: %s\n", strerror(errno));
        goto cleanup;
    }
    
    LOG("✅ Successfully attached eBPF program to %s. Waiting for traffic...", argv[1]);
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    while (!exiting) {
        perf_buffer__poll(pb, 100);
    }

cleanup:
    LOG("Cleaning up...");
    bpf_tc_hook_destroy(&tc_hook);
    bootstrap_bpf__destroy(skel);
    return 0;
}
