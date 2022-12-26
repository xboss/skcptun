#ifndef _SKT_SERVER_TT_H
#define _SKT_SERVER_TT_H

#include "skt_kcp.h"

typedef struct {
    skt_kcp_conf_t *kcp_conf;
    // skt_tcp_conf_t *tcp_conf;
} skt_serv_tt_conf_t;

int skt_server_tt_init(skt_serv_tt_conf_t *conf, struct ev_loop *loop);
void skt_server_tt_free();

#endif  // SKT_SERVER_TT_H