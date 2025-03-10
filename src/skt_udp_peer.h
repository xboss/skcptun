#ifndef _SKT_UDP_PEER_H
#define _SKT_UDP_PEER_H

#include "skt.h"

// typedef enum { SKT_UDP_PEER_ST_NONE, SKT_UDP_PEER_ST_AUTHED } skt_udp_peer_status_t;

typedef struct {
    struct sockaddr_in remote_addr;
    socklen_t ra_len;
    int fd;
    struct sockaddr_in local_addr;
    socklen_t la_len;
    uint32_t cid;
    char ticket[SKT_TICKET_SIZE + 1];
} skt_udp_peer_t;

skt_udp_peer_t* skt_udp_peer_start(const char* local_ip, uint16_t local_port, const char* remote_ip,
                                   uint16_t remote_port);
// ssize_t skt_udp_peer_send(skt_udp_peer_t* peer, const void* buf, size_t len);
// ssize_t skt_udp_peer_recv(skt_udp_peer_t* peer, void* buf, size_t len);
void skt_udp_peer_free(skt_udp_peer_t* peer);

skt_udp_peer_t* skt_udp_peer_get(int fd, uint32_t remote_addr);
int skt_udp_peer_add(skt_udp_peer_t* peer);
void skt_udp_peer_del(int fd, uint32_t remote_addr);

typedef struct {
    char cmd;
    char* ticket;
    char* payload;
    int payload_len;
} skt_packet_t;

int skt_pack(skcptun_t* skt, char cmd, const char* ticket, const char* payload, int payload_len, char* raw,
             int* raw_len);
int skt_unpack(skcptun_t* skt, const char* raw, int raw_len, char* cmd, char* ticket, char* payload, int* payload_len);

#endif /* _SKT_UDP_PEER_H */