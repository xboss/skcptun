#ifndef _SKCPTUN_H
#define _SKCPTUN_H


#include "skt.h"
#include "sstcp.h"
#include "ssudp.h"

#define SKT_PKT_CMD_SZIE (1)
#define SKT_PKT_CMD_DATA (0x01u)
#define SKT_PKT_CMD_AUTH_REQ (0x02u)
#define SKT_PKT_CMD_AUTH_RESP (0x03u)
#define SKT_PKT_CMD_CLOSE (0x04u)
#define SKT_PKT_CMD_PING (0x05u)
#define SKT_PKT_CMD_PONG (0x06u)

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

typedef struct {
    char cmd;
    char *ticket;
    char *payload;
    int payload_len;
} skt_packet_t;

int skt_pack(skcptun_t* skt, char cmd, const char* ticket, const char* payload, int payload_len, char* raw, int* raw_len);
int skt_unpack(skcptun_t* skt, const char* raw, int raw_len, char* cmd, const char* ticket, char* payload, int *payload_len);

#endif /* _SKCPTUN_H */