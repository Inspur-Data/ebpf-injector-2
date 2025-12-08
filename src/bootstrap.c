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

// 日志过滤器
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    char buf[1024];
    vsnprintf(buf, sizeof(buf), format, args);
    if (strstr(buf, "Exclusivity flag on")) return 0;
    return fprintf(stderr, "%s", buf);
}

// 打印 Hex Dump 的辅助函数
void print_hex_dump(const unsigned char *data, size_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    fprintf(stderr, "Packet Dump:\n");
    for (i = 0; i < size; ++i) {
        fprintf(stderr, "%02X ", data[i]);
        if (data[i] >= ' ' && data[i] <= '~') {
            ascii[i % 16] = data[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || (i + 1) == size) {
            fprintf(stderr, " ");
            if ((i + 1) % 16 == 0) {
                fprintf(stderr, "|  %s \n", ascii);
            } else if ((i + 1) == size) {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8) {
                    fprintf(stderr, " ");
                }
                for (j = (i + 1) % 16; j < 16; ++j) {
                    fprintf(stderr, "   ");
                }
                fprintf(stderr, "|  %s \n", ascii);
            }
        }
    }
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    const struct log_event *e = data;
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &e->src_ip, src, sizeof(src));
    inet_ntop(AF_INET, &e->dst_ip, dst, sizeof(dst));
    
    fprintf(stderr, "[LOG] Injected: %s:%d -> %s:%d\n", 
           src, ntohs(e->src_port), dst, ntohs(e->dst_port));
    
    // 打印包内容
    print_hex_dump(e->payload, 100);
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
    struct bootstrap_bpf *skel;
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

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS);
    bpf_tc_hook_create(&tc_hook);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .prog_fd = bpf_program__fd(skel->progs.tc_proxy_protocol));
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
