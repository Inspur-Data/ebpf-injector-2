#ifndef __COMMON_H
#define __COMMON_H

struct log_event {
    unsigned int src_ip;
    unsigned int dst_ip; // 实际上没用，但也得留着占位
    unsigned short src_port;
    unsigned short dst_port;
};

#endif /* __COMMON_H */
