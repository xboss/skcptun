#ifndef _SKCP_RAW_SOCK_H
#define _SKCP_RAW_SOCK_H

#include <netinet/in.h>

typedef struct {
    int icmp_fd;
    int ipv4_fd;
    int tcp_fd;
    int udp_fd;
    struct sockaddr_in* bind_addr;
} skcp_raw_sock_t;

skcp_raw_sock_t* skcp_raw_sock_new(char* bind_ip);
int skcp_raw_sock_send(skcp_raw_sock_t* raw_sock, char* ip_packet, int len);
// int skcp_raw_sock_msend(skcp_raw_sock_t* raw_sock, char* ip_packet, int len, char* src_ip, char* dst_ip);
// int skcp_raw_sock_recv(skcp_raw_sock_t* raw_sock, char* buf);
void skcp_raw_sock_free(skcp_raw_sock_t* raw_sock);

#endif