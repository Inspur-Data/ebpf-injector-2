// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/resource.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include "bootstrap.skel.h"
#include "common.h"

static volatile bool exiting = false;
static int ifindex = -1;
static __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE;
static struct bpf_tc_hook tc_hook;

static void sig_handler(int sig) {
    exiting = true;
}

void cleanup_all() {
    if (ifindex > 0) {
        // 清理 XDP
        bpf_xdp_detach(ifindex, xdp_flags, 0);
        printf("Detached XDP.\n");
        
        // 清理 TC
        if (tc_hook.ifindex > 0) {
            bpf_tc_hook_destroy(&tc_hook);
            printf("Destroyed TC hook.\n");
        }
    }
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) { 
    if (level > LIBBPF_WARN) return 0; 
    return vfprintf(stderr, format, args); 
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) { 
    const struct log_event *e = data; 
    
    // 我们用 dst_port 来区分是哪个程序发的日志
    // 11111 = Ingress XDP (Record)
    // 22222 = Egress TC (Inject)
    
    char src[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &e->src_ip, src, sizeof(src));

    if (e->dst_port == 11111) {
        fprintf(stdout, "[INGRESS] Recorded: %s:%u\n", src, ntohs(e->src_port));
    } else if (e->dst_port == 22222) {
        fprintf(stdout, "[EGRESS ] Injected: %s:%u (Success!)\n", src, ntohs(e->src_port));
    } else {
        fprintf(stdout, "[UNKNOWN] Src: %s:%u\n", src, ntohs(e->src_port));
    }
}

void parse_and_update_ports(struct bpf_map *map, char *ports_str) { 
    // ... (保持之前的双字节序注册逻辑不变) ...
    if (!map) return; char *ports_copy = strdup(ports_str); if (!ports_copy) return; char *p = strtok(ports_copy, ","); while (p) { int start = atoi(p), end = start; char *dash = strchr(p, '-'); if (dash) end = atoi(dash + 1); if (start > 0) { for (int port = start; port <= end; port++) { __u8 v = 1; __u16 k_host = port; bpf_map__update_elem(map, &k_host, sizeof(k_host), &v, sizeof(v), BPF_ANY); __u16 k_net = htons(port); bpf_map__update_elem(map, &k_net, sizeof(k_net), &v, sizeof(v), BPF_ANY); } fprintf(stderr, "INFO: Enabled ports range: %d-%d\n", start, end); } p = strtok(NULL, ","); } free(ports_copy);
}

int main(int argc, char **argv) {
    struct bootstrap_bpf *skel;
    struct perf_buffer *pb = NULL;
    int err;

    libbpf_set_print(libbpf_print_fn);
    if (argc != 3) { fprintf(stderr, "Usage: %s <interface> <ports>\n", argv[0]); return 1; }

    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) { perror("setrlimit"); return 1; }

    ifindex = if_nametoindex(argv[1]);
    if (!ifindex) { perror("if_nametoindex"); return 1; }
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    skel = bootstrap_bpf__open();
    if (!skel) { fprintf(stderr, "ERROR: Open BPF\n"); return 1; }

    struct bpf_map *map;
    bpf_object__for_each_map(map, skel->obj) { bpf_map__set_map_flags(map, 0); }

    if (bootstrap_bpf__load(skel)) { fprintf(stderr, "ERROR: Load BPF\n"); goto cleanup; }

    parse_and_update_ports(skel->maps.ports_map, argv[2]);

    // 1. 挂载 XDP Ingress
    err = bpf_xdp_attach(ifindex, bpf_program__fd(skel->progs.xdp_ingress_record), xdp_flags, NULL);
    if (err) { fprintf(stderr, "ERROR: Attach XDP: %s\n", strerror(-err)); goto cleanup; }
    printf("XDP Ingress attached.\n");

    // 2. 挂载 TC Egress
    memset(&tc_hook, 0, sizeof(tc_hook));
    tc_hook.sz = sizeof(tc_hook);
    tc_hook.ifindex = ifindex;
    tc_hook.attach_point = BPF_TC_EGRESS; // 关键！挂在出口

    struct bpf_tc_opts tc_opts = {.sz = sizeof(tc_opts), .prog_fd = bpf_program__fd(skel->progs.tc_egress_inject)};
    
    // 尝试清理旧的
    bpf_tc_hook_create(&tc_hook); // 忽略 EEXIST
    bpf_tc_detach(&tc_hook, &tc_opts);

    if (bpf_tc_attach(&tc_hook, &tc_opts)) {
        fprintf(stderr, "ERROR: Attach TC: %s\n", strerror(errno));
        goto cleanup;
    }
    printf("TC Egress attached.\n");

    pb = perf_buffer__new(bpf_map__fd(skel->maps.log_events), 8, handle_event, NULL, NULL, NULL);
    if (!pb) { fprintf(stderr, "ERROR: Perf buffer\n"); goto cleanup; }

    printf("Running... Press Ctrl+C to exit.\n");
    
    while (!exiting) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) break;
    }

cleanup:
    cleanup_all();
    if (pb) perf_buffer__free(pb);
    if (skel) bootstrap_bpf__destroy(skel);
    return -err;
}
