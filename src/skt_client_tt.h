#ifndef _SKT_CLIENT_TT_H
#define _SKT_CLIENT_TT_H

#include "skt_kcp.h"

typedef struct {
    skt_kcp_conf_t *kcp_conf;
    // skt_tcp_conf_t *tcp_conf;
} skt_cli_tt_conf_t;

int skt_client_tt_init(skt_cli_tt_conf_t *conf, struct ev_loop *loop);
void skt_client_tt_free();
// skt_cli_tt_t *skt_start_client_tt(struct ev_loop *loop, const char *conf_file);

#endif  // SKT_CLIENT_TT_H