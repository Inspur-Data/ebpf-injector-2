#ifndef __COMMON_H
#define __COMMON_H

// 定义日志数据结构
struct log_event {
    unsigned int src_ip;
    unsigned int dst_ip;
    unsigned short src_port;
    unsigned short dst_port;
};

#endif /* __COMMON_H */
