#ifndef _SKCPTUN_H
#define _SKCPTUN_H

#include "skt.h"
#include "sstcp.h"
#include "ikcp.h"

typedef struct {
    skt_config_t *conf;
    sstcp_server_t *tcp_server;
    ikcpcb *kcp;
    int udp_fd;
    uint32_t conv;
} skcptun_t;

skcptun_t* skt_init(skt_config_t* conf);
int skt_start(skcptun_t* skt);
void skt_stop(skcptun_t* skt);
void skt_free(skcptun_t* skt);

#endif /* _SKCPTUN_H */