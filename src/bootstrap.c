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

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    const struct log_event *e = data;
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &e->src_ip, src, sizeof(src));
    inet_ntop(AF_INET, &e->dst_ip, dst, sizeof(dst));
    printf("[LOG] Proxy Protocol Injected: %s:%d -> %s:%d\n", 
           src, ntohs(e->src_port), dst, ntohs(e->dst_port));
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
        printf("Enabled ports: %d-%d\n", start, end);
        p = strtok(NULL, ",");
    }
    free(ports_copy);
}

int main(int argc, char **argv) {
    struct bootstrap_bpf *skel;
    struct perf_buffer *pb = NULL;
    int ifindex;
    
    libbpf_set_print(libbpf_print_fn);

    if (argc != 3) return 1;

    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &r);

    ifindex = if_nametoindex(argv[1]);
    if (!ifindex) { perror("if_nametoindex"); return 1; }

    skel = bootstrap_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "!!! FAILED TO LOAD SKELETON !!!\n");
        return 1;
    }

    // 注意：如果使用 Legacy Map，skel->maps.ports_map 可能仍然可用
    // 如果编译报错，可以使用 bpf_object__find_map_by_name(skel->obj, "ports_map")
    parse_and_update_ports(skel->maps.ports_map, argv[2]);

    pb = perf_buffer__new(bpf_map__fd(skel->maps.log_events), 8, handle_event, NULL, NULL, NULL);

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS);
    bpf_tc_hook_create(&tc_hook);
    
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .prog_fd = bpf_program__fd(skel->progs.tc_proxy_protocol));
    bpf_tc_detach(&tc_hook, &tc_opts); 
    
    if (bpf_tc_attach(&tc_hook, &tc_opts)) {
        fprintf(stderr, "Failed to attach TC: %s\n", strerror(errno));
        goto cleanup;
    }
    
    printf("Running... Press Ctrl+C to stop.\n");
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    while (!exiting) {
        perf_buffer__poll(pb, 100);
    }

cleanup:
    bpf_tc_hook_destroy(&tc_hook);
    bootstrap_bpf__destroy(skel);
    return 0;
}
