#include "skt_udp_peer.h"


#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

skt_udp_peer_t* skt_udp_peer_init(const char* local_ip, uint16_t local_port, const char* remote_ip, uint16_t remote_port) {
    skt_udp_peer_t* peer = (skt_udp_peer_t*)malloc(sizeof(skt_udp_peer_t));
    if (!peer) {
        perror("malloc");
        return NULL;
    }

    peer->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (peer->fd < 0) {
        perror("socket");
        free(peer);
        return NULL;
    }

    memset(&peer->local_addr, 0, sizeof(peer->local_addr));
    peer->local_addr.sin_family = AF_INET;
    peer->local_addr.sin_port = htons(local_port);
    if (inet_pton(AF_INET, local_ip, &peer->local_addr.sin_addr) <= 0) {
        perror("inet_pton local");
        close(peer->fd);
        free(peer);
        return NULL;
    }

    if (bind(peer->fd, (struct sockaddr*)&peer->local_addr, sizeof(peer->local_addr)) < 0) {
        perror("bind");
        close(peer->fd);
        free(peer);
        return NULL;
    }

    memset(&peer->remote_addr, 0, sizeof(peer->remote_addr));
    peer->remote_addr.sin_family = AF_INET;
    peer->remote_addr.sin_port = htons(remote_port);
    if (inet_pton(AF_INET, remote_ip, &peer->remote_addr.sin_addr) <= 0) {
        perror("inet_pton remote");
        close(peer->fd);
        free(peer);
        return NULL;
    }

    return peer;
}

ssize_t skt_udp_peer_send(skt_udp_peer_t* peer, const void* buf, size_t len) {
    return sendto(peer->fd, buf, len, 0, (struct sockaddr*)&peer->remote_addr, sizeof(peer->remote_addr));
}

ssize_t skt_udp_peer_recv(skt_udp_peer_t* peer, void* buf, size_t len) { return recvfrom(peer->fd, buf, len, 0, (struct sockaddr*)&peer->remote_addr, &peer->ra_len); }

void skt_udp_peer_free(skt_udp_peer_t* peer) {
    if (peer) {
        close(peer->fd);
        free(peer);
    }
}
