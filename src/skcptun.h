#ifndef _SKCPTUN_H
#define _SKCPTUN_H

#include "skt.h"
// #include "sstcp.h"
// #include "ssudp.h"
#include "skt_udp_peer.h"
#include "tun.h"

skcptun_t* skt_init(skt_config_t* conf, struct ev_loop* loop);
// int skt_start(skcptun_t* skt);
// void skt_stop(skcptun_t* skt);
void skt_free(skcptun_t* skt);
int skt_start_tun(char* tun_dev, char* tun_ip, char* tun_netmask, int tun_mtu);
int skt_kcp_to_tun(skcptun_t* skt, skt_packet_t* pkt);

#endif /* _SKCPTUN_H */