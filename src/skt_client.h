#ifndef _SKT_CLIENT_H
#define _SKT_CLIENT_H

#include <ev.h>

#include "3rd/uthash/uthash.h"
#include "skt_kcp.h"
#include "skt_tcp.h"

typedef struct skt_cli_s skt_cli_t;

struct skt_cli_conf_s {
    skt_kcp_conf_t *kcp_conf;
    skt_tcp_conf_t *tcp_conf;
};
typedef struct skt_cli_conf_s skt_cli_conf_t;

struct skt_cli_s {
    skt_cli_conf_t *conf;
    struct ev_loop *loop;
    skt_kcp_t *skt_kcp;
    skt_tcp_t *skt_tcp;
};

skt_cli_t *skt_client_init(skt_cli_conf_t *conf, struct ev_loop *loop);
void skt_client_free();

#endif