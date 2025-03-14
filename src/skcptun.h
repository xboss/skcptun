#ifndef _SKCPTUN_H
#define _SKCPTUN_H

#include "skt.h"
// #include "sstcp.h"
// #include "ssudp.h"
#include "skt_kcp_conn.h"
#include "skt_udp_peer.h"
#include "tun.h"

skcptun_t* skt_init(skt_config_t* conf, struct ev_loop* loop);
// int skt_start(skcptun_t* skt);
// void skt_stop(skcptun_t* skt);
void skt_free(skcptun_t* skt);
// int skt_start_tun(skcptun_t* skt);
int skt_init_tun(skcptun_t* skt);
int skt_setup_tun(skcptun_t* skt);
int skt_kcp_to_tun(skcptun_t* skt, skt_packet_t* pkt);
int skt_tun_to_kcp(skcptun_t* skt, const char* buf, int len);
void skt_update_kcp_cb(skt_kcp_conn_t* kcp_conn);
void skt_setup_kcp(skcptun_t* skt);
void skt_monitor(skcptun_t* skt);

#endif /* _SKCPTUN_H */