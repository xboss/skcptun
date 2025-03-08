#include "ssudp.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

ssudp_t* ssudp_init(const char* local_ip, uint16_t local_port, const char* remote_ip, uint16_t remote_port) {
    ssudp_t* ssudp = (ssudp_t*)malloc(sizeof(ssudp_t));
    if (!ssudp) {
        perror("malloc");
        return NULL;
    }

    ssudp->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ssudp->fd < 0) {
        perror("socket");
        free(ssudp);
        return NULL;
    }

    memset(&ssudp->local_addr, 0, sizeof(ssudp->local_addr));
    ssudp->local_addr.sin_family = AF_INET;
    ssudp->local_addr.sin_port = htons(local_port);
    if (inet_pton(AF_INET, local_ip, &ssudp->local_addr.sin_addr) <= 0) {
        perror("inet_pton local");
        close(ssudp->fd);
        free(ssudp);
        return NULL;
    }

    if (bind(ssudp->fd, (struct sockaddr*)&ssudp->local_addr, sizeof(ssudp->local_addr)) < 0) {
        perror("bind");
        close(ssudp->fd);
        free(ssudp);
        return NULL;
    }

    memset(&ssudp->remote_addr, 0, sizeof(ssudp->remote_addr));
    ssudp->remote_addr.sin_family = AF_INET;
    ssudp->remote_addr.sin_port = htons(remote_port);
    if (inet_pton(AF_INET, remote_ip, &ssudp->remote_addr.sin_addr) <= 0) {
        perror("inet_pton remote");
        close(ssudp->fd);
        free(ssudp);
        return NULL;
    }

    return ssudp;
}

ssize_t ssudp_send(ssudp_t* ssudp, const void* buf, size_t len) {
    return sendto(ssudp->fd, buf, len, 0, (struct sockaddr*)&ssudp->remote_addr, sizeof(ssudp->remote_addr));
}

ssize_t ssudp_recv(ssudp_t* ssudp, void* buf, size_t len) { return recvfrom(ssudp->fd, buf, len, 0, (struct sockaddr*)&ssudp->remote_addr, &ssudp->ra_len); }

void ssudp_free(ssudp_t* ssudp) {
    if (ssudp) {
        close(ssudp->fd);
        free(ssudp);
    }
}
