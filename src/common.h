#ifndef __COMMON_H
#define __COMMON_H

struct log_event {
    unsigned int src_ip;
    unsigned int dst_ip;
    unsigned short src_port;
    unsigned short dst_port;
    // 新增：用于存放修改后的数据包内容
    // 100字节足够覆盖 ETH(14) + IP(20) + TCP(40) + PP(12)
    unsigned char payload[100]; 
};

#endif /* __COMMON_H */
