#ifndef _SKCPTUN_H
#define _SKCPTUN_H

#include "skt.h"
// #include "sstcp.h"
// #include "ssudp.h"
#include "skt_kcp_conn.h"
#include "skt_udp_peer.h"
#include "tun.h"

#define SKT_KCP_HEADER_SZIE (24)
#define SKT_PKT_CMD_SZIE (1)
#define SKT_PKT_CMD_DATA (0x01u)
#define SKT_PKT_CMD_AUTH_REQ (0x02u)
#define SKT_PKT_CMD_AUTH_RESP (0x03u)
#define SKT_PKT_CMD_CLOSE (0x04u)
#define SKT_PKT_CMD_PING (0x05u)
#define SKT_PKT_CMD_PONG (0x06u)

skcptun_t* skt_init(skt_config_t* conf, struct ev_loop* loop);
// int skt_start(skcptun_t* skt);
// void skt_stop(skcptun_t* skt);
void skt_free(skcptun_t* skt);
int skt_start_tun(char* tun_dev, char* tun_ip, char* tun_netmask, int tun_mtu);

typedef struct {
    char cmd;
    char* ticket;
    char* payload;
    int payload_len;
} skt_packet_t;

int skt_pack(skcptun_t* skt, char cmd, const char* ticket, const char* payload, int payload_len, char* raw,
             int* raw_len);
int skt_unpack(skcptun_t* skt, const char* raw, int raw_len, char* cmd, char* ticket, char* payload, int* payload_len);

uint64_t skt_mstime();

#define SKT_MSTIME32 ((uint32_t)(skt_mstime() & 0xfffffffful))

#endif /* _SKCPTUN_H */