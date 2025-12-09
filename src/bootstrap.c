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
    char buf[1024];
    vsnprintf(buf, sizeof(buf), format, args);
    if (strstr(buf, "Exclusivity flag on")) return 0;
    return fprintf(stderr, "%s", buf);
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    const struct log_event *e = data;
    int type = e->src_ip;
    int val1 = e->src_port;
    int val2 = e->dst_port;

    switch (type) {
        case 5: // DBG_PORT_MISMATCH
            fprintf(stderr, "[DEBUG] Port Found BUT Map Lookup Failed! Host: %d, Net: %d\n", val1, val2);
            break;
        case 6: // DBG_MAP_HIT
            fprintf(stderr, "[SUCCESS] Map Hit! Traffic captured for port %d\n", val1);
            break;
        default:
            fprintf(stderr, "[DEBUG] Unknown event type: %d\n", type);
    }
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
            // 写入主机字节序
            __u16 k = port; 
            __u8 v = 1;
            bpf_map__update_elem(map, &k, sizeof(k), &v, sizeof(v), BPF_ANY);
            fprintf(stderr, "Added port %d (Host Endian) to Map\n", port);
            
            // 为了防止大小端问题，我们也写入网络字节序试试
            __u16 k_net = htons(port);
            bpf_map__update_elem(map, &k_net, sizeof(k_net), &v, sizeof(v), BPF_ANY);
        }
        p = strtok(NULL, ",");
    }
    free(ports_copy);
}

int main(int argc, char **argv) {
    struct bootstrap_bpf *skel = NULL;
    struct perf_buffer *pb = NULL;
    int ifindex;
    
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

    struct bpf_tc_hook tc_hook;
    memset(&tc_hook, 0, sizeof(tc_hook));
    tc_hook.sz = sizeof(tc_hook);
    tc_hook.ifindex = ifindex;
    tc_hook.attach_point = BPF_TC_INGRESS;

    struct bpf_tc_opts tc_opts;
    memset(&tc_opts, 0, sizeof(tc_opts));
    tc_opts.sz = sizeof(tc_opts);
    tc_opts.prog_fd = bpf_program__fd(skel->progs.tc_toa_injector);

    bpf_tc_hook_create(&tc_hook);
    bpf_tc_detach(&tc_hook, &tc_opts); 
    
    if (bpf_tc_attach(&tc_hook, &tc_opts)) {
        fprintf(stderr, "Failed to attach TC\n");
        goto cleanup;
    }
    
    printf("Successfully attached to %s\n", argv[1]);
    
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
