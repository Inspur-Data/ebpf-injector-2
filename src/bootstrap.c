// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <bpf/libbpf.h>      // 包含 libbpf 的主头文件
#include "bootstrap.skel.h" // 包含骨架头文件

static volatile bool exiting = false;

static void sig_handler(int sig) {
    exiting = true;
}

// 这个函数保持不变
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
            }
        } else {
            int port = atoi(port_token);
            if (port > 0 && port < 65536) {
                __u16 p = (__u16)port;
                __u8 v = 1;
                bpf_map__update_elem(map, &p, sizeof(p), &v, sizeof(v), BPF_ANY);
                printf("Enabled Proxy Protocol for port %d\n", port);
            }
        }
        port_token = strtok(NULL, ",");
    }
    free(ports_copy);
}

int main(int argc, char **argv) {
    struct bootstrap_bpf *skel;
    int ifindex, err;
    char *iface;
    char *ports_str;
    
    // 关键：声明 TC hook 结构体，用于描述挂载点
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .attach_point = BPF_TC_INGRESS);

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <interface> <port_list>\n", argv[0]);
        return 1;
    }

    iface = argv[1];
    ports_str = argv[2];

    ifindex = if_nametoindex(iface);
    if (!ifindex) {
        perror("if_nametoindex");
        return 1;
    }
    
    skel = bootstrap_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "ERROR: Failed to open and load BPF skeleton\n");
        return 1;
    }

    parse_and_update_ports(skel->maps.ports_map, ports_str);

    // --- 关键：使用现代化的 TC API 进行挂载 ---
    tc_hook.ifindex = ifindex;

    // 1. 尝试销毁旧的 hook，确保环境干净
    bpf_tc_hook_destroy(&tc_hook);

    // 2. 创建新的 hook
    err = bpf_tc_hook_create(&tc_hook);
    if (err && err != -EEXIST) {
        fprintf(stderr, "Failed to create TC hook: %s\n", strerror(-err));
        goto cleanup;
    }
    
    // 3. 从骨架中获取 eBPF 程序的fd
    int prog_fd = bpf_program__fd(skel->progs.tc_proxy_protocol);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get program FD\n");
        goto cleanup;
    }

    // 4. 准备附加参数并执行附加
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .prog_fd = prog_fd);
    err = bpf_tc_attach(&tc_hook, &tc_opts);
    if (err) {
        fprintf(stderr, "Failed to attach TC program: %s\n", strerror(-err));
        goto cleanup;
    }
    // --- 挂载逻辑结束 ---

    printf("Successfully attached eBPF program to %s. Press Ctrl+C to exit.\n", iface);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    while (!exiting) {
        sleep(1);
    }

cleanup:
    printf("\nDetaching eBPF program and cleaning up...\n");
    // 关键：通过销毁 hook 来卸载程序
    bpf_tc_hook_destroy(&tc_hook);
    bootstrap_bpf__destroy(skel);
    return 0;
}
