#ifndef __COMMON_H
#define __COMMON_H

// ❌ 删除这一行，它导致了和 vmlinux.h 的冲突
// #include <stdint.h>

// 这是一个非常基础的结构体，我们直接用原始类型即可
// 在 64 位系统上，unsigned int 就是 32 位，unsigned short 就是 16 位
struct log_event {
    unsigned int src_ip;    // 对应 uint32_t / __be32
    unsigned int dst_ip;
    unsigned short src_port; // 对应 uint16_t / __be16
    unsigned short dst_port;
};

#endif /* __COMMON_H */
