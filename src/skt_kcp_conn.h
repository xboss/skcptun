#ifndef _SKT_KCP_CONN_H
#define _SKT_KCP_CONN_H

#include "skt.h"
#include "skt_udp_peer.h"

typedef struct {
    uint32_t cid;     // primary key
    uint32_t tun_ip;  // key

    ikcpcb *kcp;
    skt_udp_peer_t *peer;
    skcptun_t *skt;

    uint64_t create_time;
    uint64_t last_r_tm;  // 最后一次读操作的时间戳
    uint64_t last_w_tm;  // 最后一次写操作的时间戳

} skt_kcp_conn_t;

uint32_t skt_kcp_conn_gen_cid();
skt_kcp_conn_t *skt_kcp_conn_add(uint32_t cid, uint32_t tun_ip, const char *ticket, skt_udp_peer_t *peer,
                                 skcptun_t *skt);
skt_kcp_conn_t *skt_kcp_conn_get_by_cid(uint32_t cid);
skt_kcp_conn_t *skt_kcp_conn_get_by_tun_ip(uint32_t tun_ip);
void skt_kcp_conn_del(skt_kcp_conn_t *kcp_conn);
int skt_kcp_conn_recv(skt_kcp_conn_t *kcp_conn, const char *in, int in_len, char *out);
void skt_kcp_conn_info();
void skt_kcp_conn_iter(void (*iter)(skt_kcp_conn_t *kcp_conn));
void skt_kcp_conn_cleanup();

#endif /* _SKT_KCP_CONN_H */