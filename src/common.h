#ifndef __COMMON_H
#define __COMMON_H

struct log_event {
    unsigned int src_ip;
    unsigned int dst_ip;
    unsigned short src_port;
    unsigned short dst_port;
    // 抓取前 64 字节，足够分析包头结构
    unsigned char payload[64];
};

#endif /* __COMMON_H */
