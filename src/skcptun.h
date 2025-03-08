#ifndef _SKCPTUN_H
#define _SKCPTUN_H

#include "ikcp.h"
#include "skt.h"
#include "sstcp.h"
#include "ssudp.h"

typedef struct {
    struct ev_loop* loop;
    skt_config_t* conf;
    // sstcp_server_t* tcp_server;
    // sstcp_client_t* tcp_client;
    ssudp_t* udp;
    int tun_fd;
    ikcpcb* kcp;
    int running;

    ev_timer *timeout_watcher;
    ev_io *tun_io_watcher;
    ev_io *udp_io_watcher;
} skcptun_t;

skcptun_t* skt_init(skt_config_t* conf, struct ev_loop* loop);
// int skt_start(skcptun_t* skt);
// void skt_stop(skcptun_t* skt);
void skt_free(skcptun_t* skt);

#endif /* _SKCPTUN_H */