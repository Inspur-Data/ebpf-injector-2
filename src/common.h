#ifndef __COMMON_H
#define __COMMON_H

#include <stdint.h>

// 这是我们将从内核发送到用户空间的日志事件结构体
struct log_event {
    uint32_t src_ip;    // 源 IP 地址
    uint32_t dst_ip;    // 目标 IP 地址
    uint16_t src_port;  // 源端口
    uint16_t dst_port;  // 目标端口
};

#endif /* __COMMON_H */
