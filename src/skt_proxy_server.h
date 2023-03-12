#ifndef _SKT_PROXY_SERVER_H
#define _SKT_PROXY_SERVER_H

#include "easy_tcp.h"
#include "skcp.h"

int skt_proxy_server_init(skcp_conf_t *skcp_conf, etcp_cli_conf_t *etcp_conf, struct ev_loop *loop, char *proxy_addr,
                          uint16_t proxy_port);
void skt_proxy_server_free();

#endif  // SKT_PROXY_SERVER_H