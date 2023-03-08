#ifndef _SKT_SERVER_TT_H
#define _SKT_SERVER_TT_H

#include "skcp.h"

typedef struct skt_serv_conf_s {
    skcp_conf_t *skcp_conf;
    char *tun_ip;
    char *tun_mask;
} skt_serv_conf_t;

int skt_server_init(skt_serv_conf_t *conf, struct ev_loop *loop);
void skt_server_free();

#endif  // SKT_SERVER_TT_H