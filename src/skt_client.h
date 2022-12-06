#ifndef _SKT_CLIENT_H
#define _SKT_CLIENT_H

#include <ev.h>

#include "3rd/uthash/uthash.h"
#include "skt_kcp.h"
#include "skt_route.h"
#include "skt_tcp.h"

#define SKT_REMOTE_SERV_MAX_CNT 255

typedef struct skt_cli_s skt_cli_t;

struct skt_cli_conf_s {
    skt_kcp_conf_t *kcp_conf[SKT_REMOTE_SERV_MAX_CNT];
    int kcp_conf_cnt;
    skt_tcp_conf_t *tcp_conf;
};
typedef struct skt_cli_conf_s skt_cli_conf_t;

struct skt_cli_s {
    skt_cli_conf_t *conf;
    struct ev_loop *loop;
    skt_tcp_t *skt_tcp;
    skt_kcp_t *skt_kcp[SKT_REMOTE_SERV_MAX_CNT];
    // skt_kcp_t *cur_skt_kcp;
    int skt_kcp_cnt;
    skt_route_t *route;
    struct ev_timer *stat_watcher;
};

skt_cli_t *skt_client_init(skt_cli_conf_t *conf, struct ev_loop *loop);
void skt_client_free();

#endif