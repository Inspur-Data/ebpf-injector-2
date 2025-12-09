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

static volatile bool exiting = false;
static void sig_handler(int sig) { exiting = true; }

// 日志过滤器
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    char buf[1024];
    vsnprintf(buf, sizeof(buf), format, args);
    // 过滤掉那些烦人的噪音
    if (strstr(buf, "Exclusivity flag on")) return 0;
    return fprintf(stderr, "%s", buf);
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    const struct log_event *e = data;
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &e->src_ip, src, sizeof(src));
    inet_ntop(AF_INET, &e->dst_ip, dst, sizeof(dst));
    
    // 这里的 dst_port 实际上是我们回传的 TCP Header Length
    fprintf(stderr, "[LOG] TOA Injected! Src: %s:%d -> %s (TCP Len: %d)\n", 
           src, ntohs(e->src_port), dst, e->dst_port);
}

void parse_and_update_ports(struct bpf_map *map, char *ports_str) {
    if (!map) return;
    char *ports_copy = strdup(ports_str);
    char *p = strtok(ports_copy, ",");
    while (p) {
        int start = atoi(p), end = start;
        char *dash = strchr(p, '-');
        if (dash) end = atoi(dash + 1);
        for (int port = start; port <= end; port++) {
            __u16 k = port; __u8 v = 1;
            bpf_map__update_elem(map, &k, sizeof(k), &v, sizeof(v), BPF_ANY);
        }
        fprintf(stderr, "Enabled ports: %d-%d\n", start, end);
        p = strtok(NULL, ",");
    }
    free(ports_copy);
}

int main(int argc, char **argv) {
    struct bootstrap_bpf *skel = NULL;
    struct perf_buffer *pb = NULL;
    int ifindex;
    int err;
    
    // 禁用缓冲，确保日志实时输出
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    
    libbpf_set_print(libbpf_print_fn);

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <interface> <ports>\n", argv[0]);
        return 1;
    }

    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &r);

    ifindex = if_nametoindex(argv[1]);
    if (!ifindex) { perror("if_nametoindex"); return 1; }

    skel = bootstrap_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open skeleton\n");
        return 1;
    }

    // 强制清零 Flags，防止 Exclusivity 错误
    struct bpf_map *map;
    bpf_object__for_each_map(map, skel->obj) {
        bpf_map__set_map_flags(map, 0);
    }

    if (bootstrap_bpf__load(skel)) {
        fprintf(stderr, "Failed to load skeleton\n");
        goto cleanup;
    }

    parse_and_update_ports(skel->maps.ports_map, argv[2]);

    pb = perf_buffer__new(bpf_map__fd(skel->maps.log_events), 8, handle_event, NULL, NULL, NULL);

    // 手动初始化 TC Hook 结构体
    struct bpf_tc_hook tc_hook;
    memset(&tc_hook, 0, sizeof(tc_hook));
    tc_hook.sz = sizeof(tc_hook);
    tc_hook.ifindex = ifindex;
    tc_hook.attach_point = BPF_TC_INGRESS;

    struct bpf_tc_opts tc_opts;
    memset(&tc_opts, 0, sizeof(tc_opts));
    tc_opts.sz = sizeof(tc_opts);
    tc_opts.prog_fd = bpf_program__fd(skel->progs.tc_toa_injector); // 确认名字对齐

    bpf_tc_hook_create(&tc_hook);
    bpf_tc_detach(&tc_hook, &tc_opts); 
    
    if (bpf_tc_attach(&tc_hook, &tc_opts)) {
        fprintf(stderr, "Failed to attach TC: %s\n", strerror(errno));
        goto cleanup;
    }
    
    printf("Successfully attached TOA injector to %s\n", argv[1]);
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    while (!exiting) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling perf buffer: %s\n", strerror(-err));
            break;
        }
    }

cleanup:
    bpf_tc_hook_destroy(&tc_hook);
    if (pb) perf_buffer__free(pb);
    if (skel) bootstrap_bpf__destroy(skel);
    return 0;
}
