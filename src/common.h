#ifndef __COMMON_H
#define __COMMON_H

struct log_event {
    unsigned int src_ip;    // 借用为 Debug Type
    unsigned int dst_ip;
    unsigned short src_port; // 借用为 Debug Value 1
    unsigned short dst_port; // 借用为 Debug Value 2
    unsigned char payload[64];
};

#endif /* __COMMON_H */
