#ifndef _SKT_SERVER_H
#define _SKT_SERVER_H

#include <ev.h>

#include "3rd/uthash/uthash.h"
#include "skt_kcp_server.h"
#include "skt_tcp_client.h"

typedef struct skt_serv_conf_s skt_serv_conf_t;
typedef struct skt_serv_s skt_serv_t;

struct skt_serv_conf_s {
    skt_kcp_serv_conf_t *kcp_serv_conf;
    skt_tcp_cli_conf_t *tcp_cli_conf;
    char *target_addr;
    uint16_t target_port;
};

struct skt_serv_s {
    skt_serv_conf_t *conf;
    struct ev_loop *loop;
    skt_kcp_serv_t *kcp_serv;
    skt_tcp_cli_t *tcp_cli;
};

skt_serv_t *skt_server_init(skt_serv_conf_t *conf, struct ev_loop *loop);
void skt_server_free();

#endif