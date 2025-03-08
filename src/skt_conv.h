#ifndef _SKT_CONV_H
#define _SKT_CONV_H

#include "skt.h"
typedef struct {
    uint32_t cid;
    char ip[INET_ADDRSTRLEN + 1];
    ikcpcb* kcp;
    struct sockaddr_in addr;
    
} skt_conv_t;

int skt_conv_add(uint32_t id, const char* ip, const ikcpcb* kcp, struct sockaddr_in addr);
skt_conv_t* skt_conv_get_by_cid(int cid);
skt_conv_t* skt_conv_get_by_ip(int ip);
void skt_conv_del(int id);
skt_conv_t* skt_conv_gen();

#endif /* _SKT_CONV_H */

