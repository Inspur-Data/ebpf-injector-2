#ifndef __COMMON_H
#define __COMMON_H

struct log_event {
    unsigned int   src_ip;
    unsigned int   dst_ip;
    unsigned short src_port;
    unsigned short dst_port; // 这里存 TCP 头长度
    // 新增：存放 TCP 选项的前 12 个字节 (3个 u32)
    unsigned int   opts_w1;
    unsigned int   opts_w2;
    unsigned int   opts_w3;
};

#endif /* __COMMON_H */
