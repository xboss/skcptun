#ifndef _SKT_UDP_PEER_H
#define _SKT_UDP_PEER_H

#include "skt.h"

typedef struct {
    struct sockaddr_in remote_addr;
    socklen_t ra_len;
    int fd;
    struct sockaddr_in local_addr;
    socklen_t la_len;
    // UT_hash_handle hh;
} skt_udp_peer_t;

skt_udp_peer_t* skt_udp_peer_init(const char* local_ip, uint16_t local_port, const char* remote_ip, uint16_t remote_port);
ssize_t skt_udp_peer_send(skt_udp_peer_t* peer, const void* buf, size_t len);
ssize_t skt_udp_peer_recv(skt_udp_peer_t* peer, void* buf, size_t len);
void skt_udp_peer_free(skt_udp_peer_t* peer);

#endif /* _SKT_UDP_PEER_H */