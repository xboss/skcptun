#ifndef _SSUDP_H
#define _SSUDP_H

#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>

typedef struct {
    int fd;
    struct sockaddr_in local_addr;
    struct sockaddr_in remote_addr;
} ssudp_t;

ssudp_t* ssudp_init(const char* local_ip, uint16_t local_port, const char* remote_ip, uint16_t remote_port);
ssize_t ssudp_send(ssudp_t* ssudp, const void* buf, size_t len);
ssize_t ssudp_recv(ssudp_t* ssudp, void* buf, size_t len);
void ssudp_free(ssudp_t* ssudp);

#endif /* _SSUDP_H */