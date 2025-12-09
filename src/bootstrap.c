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

void print_hex(const unsigned char *data, int size) {
    fprintf(stderr, "HEX: ");
    for (int i = 0; i < size; i++) {
        fprintf(stderr, "%02X ", data[i]);
    }
    fprintf(stderr, "\n");
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    const struct log_event *e = data;
    
    if (e->src_ip == 0xDEB06) {
        fprintf(stderr, "========= DIAGNOSTIC REPORT =========\n");
        fprintf(stderr, "VLAN Mode: %s\n", e->dst_ip == 1 ? "YES (Offset 18)" : "NO (Offset 14)");
        fprintf(stderr, "TCP Flags: 0x%02X (SYN=0x02, PSH=0x08, ACK=0x10)\n", e->src_port);
        fprintf(stderr, "TCP Head Len: %d bytes\n", e->dst_port);
        
        if (e->src_port != 2) {
            fprintf(stderr, "❌ FAILURE REASON: Not a pure SYN packet!\n");
        } else if (e->dst_port != 20 && e->dst_port != 32) {
            fprintf(stderr, "❌ FAILURE REASON: Unsupported Header Length (Code only supports 20 or 32)!\n");
        } else {
            fprintf(stderr, "✅ STATUS: Packet looks perfect. Logic should have worked.\n");
        }
        
        print_hex(e->payload, 64);
        fprintf(stderr, "=====================================\n");
    }
}

// ... (parse_and_update_ports 保持不变) ...
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
        p = strtok(NULL, ",");
    }
    free(ports_copy);
}

// ... (Main 函数保持不变) ...
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
    if (!skel) return 1;

    struct bpf_map *map;
    bpf_object__for_each_map(map, skel->obj) {
        bpf_map__set_map_flags(map, 0);
    }

    if (bootstrap_bpf__load(skel)) return 1;

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
    bpf_tc_attach(&tc_hook, &tc_opts);
    
    printf("Diagnostic Mode Running on %s...\n", argv[1]);
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    while (!exiting) {
        perf_buffer__poll(pb, 100);
    }

    bpf_tc_hook_destroy(&tc_hook);
    bootstrap_bpf__destroy(skel);
    return 0;
}
