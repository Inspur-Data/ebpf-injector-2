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
#include <time.h> // 引入时间头文件用于计时
#include "bootstrap.skel.h"
#include "common.h"

static volatile bool exiting = false;

static void sig_handler(int sig) { exiting = true; }

// 日志过滤器：屏蔽 Exclusivity 噪音
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    char buf[1024];
    vsnprintf(buf, sizeof(buf), format, args);
    if (strstr(buf, "Exclusivity flag on")) return 0;
    return fprintf(stderr, "%s", buf);
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    const struct log_event *e = data;
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &e->src_ip, src, sizeof(src));
    inet_ntop(AF_INET, &e->dst_ip, dst, sizeof(dst));
    printf("[LOG] Proxy Protocol Injected: %s:%d -> %s:%d\n", 
           src, ntohs(e->src_port), dst, ntohs(e->dst_port));
}

// 优化后的端口解析函数
void parse_and_update_ports(struct bpf_map *map, char *ports_str) {
    if (!map) return;
    
    printf("DEBUG: Starting to parse ports: '%s'\n", ports_str);
    
    char *ports_copy = strdup(ports_str);
    if (!ports_copy) { perror("strdup"); return; }
    
    int total_ports = 0;
    char *p = strtok(ports_copy, ",");
    
    while (p) {
        // 去除可能的空格
        while (*p == ' ') p++;
        
        int start = atoi(p);
        int end = start;
        char *dash = strchr(p, '-');
        if (dash) end = atoi(dash + 1);
        
        // 防御性检查：端口范围是否合法
        if (start <= 0 || start > 65535 || end <= 0 || end > 65535) {
            fprintf(stderr, "WARNING: Invalid port range ignored: %s (parsed as %d-%d)\n", p, start, end);
            p = strtok(NULL, ",");
            continue;
        }

        if (end < start) {
            int tmp = start; start = end; end = tmp;
        }

        printf("DEBUG: Processing range %d-%d... ", start, end);
        fflush(stdout); // 强制刷新缓冲区，确保日志立即显示

        int count = 0;
        for (int port = start; port <= end; port++) {
            __u16 k = port; __u8 v = 1;
            int ret = bpf_map__update_elem(map, &k, sizeof(k), &v, sizeof(v), BPF_ANY);
            if (ret < 0) {
                fprintf(stderr, "\nFailed to update map for port %d: %s\n", port, strerror(-ret));
            }
            count++;
            total_ports++;
        }
        printf("Done. Added %d ports.\n", count);
        
        p = strtok(NULL, ",");
    }
    
    free(ports_copy);
    printf("DEBUG: Total ports enabled: %d\n", total_ports);
}

int main(int argc, char **argv) {
    struct bootstrap_bpf *skel;
    struct perf_buffer *pb = NULL;
    int ifindex;
    
    libbpf_set_print(libbpf_print_fn);

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <interface> <ports>\n", argv[0]);
        return 1;
    }

    // 打印当前参数，确认传入的是什么
    printf("DEBUG: Interface=%s, Ports=%s\n", argv[1], argv[2]);

    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &r);

    ifindex = if_nametoindex(argv[1]);
    if (!ifindex) { perror("if_nametoindex"); return 1; }

    printf("DEBUG: Opening skeleton...\n");
    skel = bootstrap_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "!!! FAILED TO LOAD SKELETON !!!\n");
        return 1;
    }

    printf("DEBUG: Updating ports map...\n");
    parse_and_update_ports(skel->maps.ports_map, argv[2]);

    printf("DEBUG: Setting up perf buffer...\n");
    pb = perf_buffer__new(bpf_map__fd(skel->maps.log_events), 8, handle_event, NULL, NULL, NULL);

    printf("DEBUG: Attaching TC hook...\n");
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS);
    
    // 忽略错误，尝试创建hook
    bpf_tc_hook_create(&tc_hook);
    
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .prog_fd = bpf_program__fd(skel->progs.tc_proxy_protocol));
    
    // 先卸载旧的
    bpf_tc_detach(&tc_hook, &tc_opts); 
    
    if (bpf_tc_attach(&tc_hook, &tc_opts)) {
        fprintf(stderr, "Failed to attach TC: %s\n", strerror(errno));
        goto cleanup;
    }
    
    printf("Successfully attached eBPF program to %s. Press Ctrl+C to exit.\n", argv[1]);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    while (!exiting) {
        perf_buffer__poll(pb, 100);
    }

cleanup:
    printf("Cleaning up...\n");
    bpf_tc_hook_destroy(&tc_hook);
    bootstrap_bpf__destroy(skel);
    return 0;
}
