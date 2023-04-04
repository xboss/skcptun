#ifndef _SKT_PROXY_CLIENT_H
#define _SKT_PROXY_CLIENT_H

#include "easy_tcp.h"
#include "skcp.h"

int skt_proxy_client_init(skcp_conf_t *skcp_conf, etcp_serv_conf_t *etcp_conf, struct ev_loop *loop);
void skt_proxy_client_free();

#endif  // SKT_PROXY_CLIENT_H