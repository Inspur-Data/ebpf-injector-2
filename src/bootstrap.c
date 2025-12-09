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

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    char buf[1024];
    vsnprintf(buf, sizeof(buf), format, args);
    if (strstr(buf, "Exclusivity flag on")) return 0;
    return fprintf(stderr, "%s", buf);
}

// --- 打印 Hex Dump ---
void print_hex(const unsigned char *data, int size) {
    fprintf(stderr, "HEX: ");
    for (int i = 0; i < size; i++) {
        fprintf(stderr, "%02X ", data[i]);
    }
    fprintf(stderr, "\n");
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    const struct log_event *e = data;
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &e->src_ip, src, sizeof(src));
    inet_ntop(AF_INET, &e->dst_ip, dst, sizeof(dst));
    
    fprintf(stderr, "[LOG] Injected: %s:%d -> %s:%d\n", 
           src, ntohs(e->src_port), dst, ntohs(e->dst_port));
    
    // 打印包内容快照
    print_hex(e->payload, 64);
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
    
    // 禁用缓冲
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    
    libbpf_set_print(libbpf_print_fn);

    if (argc != 3) return 1;

    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &r);

    ifindex = if_nametoindex(argv[1]);
    if (!ifindex) { perror("if_nametoindex"); return 1; }

    skel = bootstrap_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open skeleton\n");
        return 1;
    }

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

    // ⚠️ 关键修复：手动初始化 TC 结构体，防止 garbage value 导致报错
    struct bpf_tc_hook tc_hook;
    memset(&tc_hook, 0, sizeof(tc_hook));
    tc_hook.sz = sizeof(tc_hook);
    tc_hook.ifindex = ifindex;
    tc_hook.attach_point = BPF_TC_INGRESS;

    struct bpf_tc_opts tc_opts;
    memset(&tc_opts, 0, sizeof(tc_opts));
    tc_opts.sz = sizeof(tc_opts);
    tc_opts.prog_fd = bpf_program__fd(skel->progs.tc_proxy_protocol);

    // 尝试创建 Hook (忽略错误，可能已存在)
    bpf_tc_hook_create(&tc_hook);
    
    // 先卸载旧的
    bpf_tc_detach(&tc_hook, &tc_opts); 
    
    if (bpf_tc_attach(&tc_hook, &tc_opts)) {
        fprintf(stderr, "Failed to attach TC: %s\n", strerror(errno));
        goto cleanup;
    }
    
    printf("Successfully attached to %s\n", argv[1]);
    
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
    // 清理时同样需要清零结构体 (虽然这里复用了变量)
    bpf_tc_hook_destroy(&tc_hook);
    if (pb) perf_buffer__free(pb);
    if (skel) bootstrap_bpf__destroy(skel);
    return 0;
}
