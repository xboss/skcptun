#ifndef _SKT_KCP_CONN_H
#define _SKT_KCP_CONN_H

#include "skt.h"
#include "skt_udp_peer.h"

typedef struct {
    uint32_t cid; // primary key
    uint32_t vt_ip; // key

    ikcpcb* kcp;
    skt_udp_peer_t *peer;

    UT_hash_handle hh;
} skt_kcp_conn_t;

uint32_t skt_kcp_conn_gen_cid();
skt_kcp_conn_t *skt_kcp_conn_add(uint32_t cid, uint32_t vt_ip, ikcpcb* kcp, skt_udp_peer_t *peer);
skt_kcp_conn_t *skt_kcp_conn_get_by_cid(uint32_t cid);
skt_kcp_conn_t *skt_kcp_conn_get_by_vtip(uint32_t vt_ip);
void skt_kcp_conn_del(skt_kcp_conn_t *kconn);

#endif /* _SKT_KCP_CONN_H */