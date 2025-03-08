#ifndef _SKT_CONV_H
#define _SKT_CONV_H

#include "skt.h"
typedef struct {
    uint32_t cid;
    char ip[INET_ADDRSTRLEN + 1];
    ikcpcb* kcp;
    struct sockaddr_in addr;
    
} skt_conv_t;

uint32_t skt_conv_gen_cid();
int skt_conv_add(uint32_t id, const char* ip, const ikcpcb* kcp, struct sockaddr_in addr);
skt_conv_t* skt_conv_get_by_cid(uint32_t cid);
skt_conv_t* skt_conv_get_by_ip(char* ip);
int skt_conv_update_ip_index(uint32_t cid, skt_conv_t* conv);
void skt_conv_del_by_cid(int cid);

#endif /* _SKT_CONV_H */

