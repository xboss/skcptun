#ifndef _SKT_SERVER_TC_H
#define _SKT_SERVER_TC_H

#include <ev.h>

// #include "3rd/uthash/uthash.h"
#include "skt_kcp.h"
#include "skt_tcp.h"
#include "uthash.h"

typedef struct skt_serv_s skt_serv_t;

struct skt_serv_conf_s {
    skt_kcp_conf_t *kcp_conf;
    skt_tcp_conf_t *tcp_conf;
    char *target_addr;
    uint16_t target_port;
};
typedef struct skt_serv_conf_s skt_serv_conf_t;

struct skt_serv_s {
    skt_serv_conf_t *conf;
    struct ev_loop *loop;
    skt_kcp_t *skt_kcp;
    skt_tcp_t *skt_tcp;

    skcp_conn_t *ht_conn;
};

skt_serv_t *skt_server_init(skt_serv_conf_t *conf, struct ev_loop *loop);
void skt_server_free();

#endif