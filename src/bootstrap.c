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
#include "bootstrap.skel.h"
#include "common.h"

static volatile bool exiting = false;

static void sig_handler(int sig) { exiting = true; }

// 使用 stderr，确保不缓冲！
#define LOG(fmt, ...) fprintf(stderr, "[DEBUG] " fmt "\n", ##__VA_ARGS__)

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
    LOG("Proxy Protocol Injected: %s:%d -> %s:%d", 
        src, ntohs(e->src_port), dst, ntohs(e->dst_port));
}

void parse_and_update_ports(struct bpf_map *map, char *ports_str) {
    if (!map) {
        LOG("ERROR: Map pointer is NULL!");
        return;
    }
    
    // 打印 Map 的文件描述符，确保它是有效的 (>0)
    int fd = bpf_map__fd(map);
    LOG("Start parsing ports: '%s'. Map FD: %d", ports_str, fd);
    
    if (fd < 0) {
        LOG("CRITICAL ERROR: Map FD is invalid. Map was not created properly.");
        return;
    }

    char *ports_copy = strdup(ports_str);
    if (!ports_copy) { perror("strdup"); return; }

    LOG("String duplicated. Tokenizing...");
    
    char *p = strtok(ports_copy, ",");
    int count = 0;

    while (p) {
        // 打印当前的 token，确认 strtok 正常工作
        LOG("Token found: '%s'", p);

        int start = atoi(p);
        int end = start;
        char *dash = strchr(p, '-');
        if (dash) end = atoi(dash + 1);
        
        LOG("Range parsed: %d to %d. Starting loop...", start, end);
        
        for (int port = start; port <= end; port++) {
            __u16 k = port; 
            __u8 v = 1;
            
            // 打印正在更新哪个端口
            // LOG("Updating port %d...", port); // 嫌吵可以注释掉这行
            
            int ret = bpf_map__update_elem(map, &k, sizeof(k), &v, sizeof(v), BPF_ANY);
            if (ret < 0) {
                 LOG("Failed to update port %d: %s (errno=%d)", port, strerror(-ret), -ret);
            }
            count++;
        }
        LOG("Range %d-%d done.", start, end);
        
        p = strtok(NULL, ",");
    }
    free(ports_copy);
    LOG("Finished updating ports map. Total ports: %d", count);
}

int main(int argc, char **argv) {
    struct bootstrap_bpf *skel;
    struct perf_buffer *pb = NULL;
    int ifindex;

    // 双重保险：禁用缓冲
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    
    libbpf_set_print(libbpf_print_fn);

    if (argc != 3) {
        LOG("Usage: %s <interface> <port_list>", argv[0]);
        return 1;
    }

    LOG("Main start. Interface=%s, Ports=%s", argv[1], argv[2]);

    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &r);

    ifindex = if_nametoindex(argv[1]);
    if (!ifindex) { perror("if_nametoindex"); return 1; }

    LOG("Loading Skeleton...");
    skel = bootstrap_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "!!! FAILED TO LOAD SKELETON !!!\n");
        return 1;
    }
    LOG("Skeleton loaded.");

    LOG("Calling parse_and_update_ports...");
    parse_and_update_ports(skel->maps.ports_map, argv[2]);

    LOG("Setting up perf buffer...");
    pb = perf_buffer__new(bpf_map__fd(skel->maps.log_events), 8, handle_event, NULL, NULL, NULL);

    LOG("Attaching TC hook...");
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS);
    
    bpf_tc_hook_create(&tc_hook);
    
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .prog_fd = bpf_program__fd(skel->progs.tc_proxy_protocol));
    bpf_tc_detach(&tc_hook, &tc_opts); 
    
    if (bpf_tc_attach(&tc_hook, &tc_opts)) {
        LOG("Failed to attach TC: %s", strerror(errno));
        goto cleanup;
    }
    
    LOG("✅ Successfully attached eBPF program to %s. Waiting...", argv[1]);
    
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
