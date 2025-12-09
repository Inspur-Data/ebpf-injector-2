#ifndef __COMMON_H
#define __COMMON_H

struct log_event {
    unsigned int src_ip;
    unsigned int dst_ip;
    unsigned short src_port;
    unsigned short dst_port; // 用于回传 TCP 头长度，方便验证
};

#endif /* __COMMON_H */
