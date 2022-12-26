#ifndef _SKT_CLIENT_TC_H
#define _SKT_CLIENT_TC_H

#include <ev.h>

// #include "3rd/uthash/uthash.h"
#include "skt_kcp.h"
#include "skt_tcp.h"
#include "uthash.h"

typedef struct skt_cli_s skt_cli_t;

struct skt_cli_conf_s {
    skt_kcp_conf_t *kcp_conf;
    skt_tcp_conf_t *tcp_conf;
};
typedef struct skt_cli_conf_s skt_cli_conf_t;

// skt_cli_t *skt_client_init(skt_cli_conf_t *conf, struct ev_loop *loop);
// void skt_client_free();
skt_cli_t *skt_start_client(struct ev_loop *loop, const char *conf_file);

#endif