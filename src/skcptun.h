#ifndef _SKCPTUN_H
#define _SKCPTUN_H

#include "ikcp.h"
#include "skt.h"
#include "sstcp.h"
#include "ssudp.h"

typedef struct {
    skt_config_t* conf;
    sstcp_server_t* tcp_server;
    sstcp_client_t* tcp_client;
    ssudp_t* udp;
    int tun_fd;
    ikcpcb* kcp;
    int running;
} skcptun_t;

skcptun_t* skt_init(skt_config_t* conf);
int skt_start(skcptun_t* skt);
void skt_stop(skcptun_t* skt);
void skt_free(skcptun_t* skt);

#endif /* _SKCPTUN_H */