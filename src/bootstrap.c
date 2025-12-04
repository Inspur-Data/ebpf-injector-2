// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <errno.h>
#include "bootstrap.skel.h" // ！！！ 关键：包含正确的骨架文件名

static volatile bool exiting = false;

static void sig_handler(int sig) {
    exiting = true;
}

// 函数保持不变，但传入的 map 参数类型变为 struct bpf_map *
void parse_and_update_ports(struct bpf_map *map, char *ports_str) {
    if (!map) {
        fprintf(stderr, "BPF map is NULL\n");
        return;
    }

    char *ports_copy = strdup(ports_str);
    if (!ports_copy) {
        perror("strdup");
        return;
    }

    char *port_token = strtok(ports_copy, ",");
    while (port_token != NULL) {
        char *range_sep = strchr(port_token, '-');
        if (range_sep) {
            *range_sep = '\0';
            int start_port = atoi(port_token);
            int end_port = atoi(range_sep + 1);
            if (start_port > 0 && end_port > 0 && end_port >= start_port) {
                printf("Enabling Proxy Protocol for port range %d-%d\n", start_port, end_port);
                for (int port = start_port; port <= end_port; port++) {
                    __u16 p = (__u16)port;
                    __u8 v = 1;
                    bpf_map__update_elem(map, &p, sizeof(p), &v, sizeof(v), BPF_ANY);
                }
            } else {
                fprintf(stderr, "Invalid port range: %s-%s\n", port_token, range_sep + 1);
            }
        } else {
            int port = atoi(port_token);
            if (port > 0 && port < 65536) {
                __u16 p = (__u16)port;
                __u8 v = 1;
                bpf_map__update_elem(map, &p, sizeof(p), &v, sizeof(v), BPF_ANY);
                printf("Enabled Proxy Protocol for port %d\n", port);
            } else {
                fprintf(stderr, "Invalid port: %s\n", port_token);
            }
        }
        port_token = strtok(NULL, ",");
    }
    free(ports_copy);
}

int main(int argc, char **argv) {
    struct bootstrap_bpf *skel; // ！！！ 关键：使用由 bootstrap.skel.h 定义的结构体
    int ifindex, err;
    char *iface;
    char *ports_str;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <interface> <port_list>\n", argv[0]);
        fprintf(stderr, "Example: %s eth0 2000-3000,39075\n", argv[0]);
        return 1;
    }

    iface = argv[1];
    ports_str = argv[2];

    ifindex = if_nametoindex(iface);
    if (!ifindex) {
        perror("if_nametoindex");
        return 1;
    }
    
    // ！！！ 关键：调用正确的骨架函数
    skel = bootstrap_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "ERROR: Failed to open and load BPF skeleton\n");
        return 1;
    }

    // 通过骨架访问 map
    parse_and_update_ports(skel->maps.ports_map, ports_str);

    // ！！！ 关键：通过骨架附加 TC 程序
    // 注意：这里的 tc_proxy_protocol 是你在 bpf.c 文件中 SEC("tc") 宏下面的函数名
    skel->links.tc_proxy_protocol = bpf_program__attach_tc(skel->progs.tc_proxy_protocol, ifindex, BPF_TC_INGRESS);
    if (!skel->links.tc_proxy_protocol) {
        err = -errno;
        fprintf(stderr, "ERROR: Failed to attach TC program: %s\n", strerror(-err));
        goto cleanup;
    }

    printf("Successfully attached eBPF program to %s. Press Ctrl+C to exit.\n", iface);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    while (!exiting) {
        sleep(1);
    }

cleanup:
    // ！！！ 关键：调用正确的骨架销毁函数
    bootstrap_bpf__destroy(skel);
    printf("\nDetached eBPF program and cleaned up.\n");
    return 0;
}
