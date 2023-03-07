#ifndef _SKT_CLIENT_H
#define _SKT_CLIENT_H

#include "skcp.h"

typedef struct skt_cli_conf_s {
    skcp_conf_t *skcp_conf;
    char *tun_ip;
    char *tun_mask;
} skt_cli_conf_t;

int skt_client_init(skt_cli_conf_t *conf, struct ev_loop *loop);
void skt_client_free();

#endif