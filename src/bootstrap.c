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

static void sig_handler(int sig) {
    exiting = true;
}

void cleanup_xdp() {
    if (ifindex > 0) {
        bpf_xdp_detach(ifindex, xdp_flags, 0);
        printf("\nDetached XDP program from interface %d.\n", ifindex);
    }
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) { 
    if (level > LIBBPF_WARN) return 0; 
    return vfprintf(stderr, format, args); 
}

// --- 修改点：打印 TCP 选项的 Hex 数据 ---
void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) { 
    const struct log_event *e = data; 
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN]; 
    inet_ntop(AF_INET, &e->src_ip, src, sizeof(src)); 
    inet_ntop(AF_INET, &e->dst_ip, dst, sizeof(dst)); 
    
    fprintf(stdout, "[LOG] TOA Injected! Src: %s:%u -> Dst: %s (Len: %u)\n", 
           src, ntohs(e->src_port), dst, e->dst_port);
    
    // 打印 12 字节的 Hex
    fprintf(stdout, "      Raw Opts: %08x %08x %08x\n", 
            ntohl(e->opts_w1), ntohl(e->opts_w2), ntohl(e->opts_w3));
}

void parse_and_update_ports(struct bpf_map *map, char *ports_str) { 
    if (!map) return; 
    char *ports_copy = strdup(ports_str); 
    if (!ports_copy) { perror("strdup"); return; } 
    char *p = strtok(ports_copy, ","); 
    while (p) { 
        int start = atoi(p), end = start; 
        char *dash = strchr(p, '-'); 
        if (dash) end = atoi(dash + 1); 
        if (start > 0 && end >= start && start <= 65535 && end <= 65535) { 
            for (int port = start; port <= end; port++) { 
                __u8 v = 1;
                __u16 k_host = port; 
                bpf_map__update_elem(map, &k_host, sizeof(k_host), &v, sizeof(v), BPF_ANY);
                __u16 k_net = htons(port);
                bpf_map__update_elem(map, &k_net, sizeof(k_net), &v, sizeof(v), BPF_ANY);
            } 
            fprintf(stderr, "INFO: Enabled ports range: %d-%d (Dual Endian)\n", start, end); 
        } 
        p = strtok(NULL, ","); 
    } 
    free(ports_copy); 
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
    if (!skel) { fprintf(stderr, "ERROR: Failed to open BPF skeleton\n"); return 1; }

    struct bpf_map *map;
    bpf_object__for_each_map(map, skel->obj) {
        bpf_map__set_map_flags(map, 0);
    }

    if (bootstrap_bpf__load(skel)) { fprintf(stderr, "ERROR: Failed to load BPF skeleton\n"); goto cleanup; }

    parse_and_update_ports(skel->maps.ports_map, argv[2]);

    err = bpf_xdp_attach(ifindex, bpf_program__fd(skel->progs.xdp_toa_injector), xdp_flags, NULL);
    if (err) {
        fprintf(stderr, "ERROR: Failed to attach XDP program: %s\n", strerror(-err));
        goto cleanup;
    }
    printf("Successfully attached XDP TOA injector to interface %s (ifindex %d).\n", argv[1], ifindex);

    pb = perf_buffer__new(bpf_map__fd(skel->maps.log_events), 8, handle_event, NULL, NULL, NULL);
    if (!pb) { err = -errno; fprintf(stderr, "ERROR: Failed to create perf buffer: %d\n", err); goto cleanup; }

    printf("Watching for events... Press Ctrl+C to exit.\n");
    
    while (!exiting) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "ERROR: Polling perf buffer: %s\n", strerror(-err));
            break;
        }
    }

cleanup:
    cleanup_xdp();
    if (pb) perf_buffer__free(pb);
    if (skel) bootstrap_bpf__destroy(skel);
    return -err;
}
