#ifndef _SKT_CLIENT_H
#define _SKT_CLIENT_H

#include <ev.h>

#include "3rd/uthash/uthash.h"
#include "skt_kcp_client.h"
#include "skt_tcp_server.h"

typedef struct skt_cli_s skt_cli_t;

struct skt_cli_conf_s {
    skt_kcp_cli_conf_t *kcp_cli_conf;
    skt_tcp_serv_conf_t *tcp_serv_conf;
};
typedef struct skt_cli_conf_s skt_cli_conf_t;

struct skt_cli_s {
    skt_cli_conf_t *conf;
    struct ev_loop *loop;
    skt_kcp_cli_t *kcp_cli;
    skt_tcp_serv_t *tcp_serv;
};

skt_cli_t *skt_client_init(skt_cli_conf_t *conf, struct ev_loop *loop);
void skt_client_free();

#endif