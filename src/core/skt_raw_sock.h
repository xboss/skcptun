#ifndef _SKT_RAW_SOCK_H
#define _SKT_RAW_SOCK_H

#include <netinet/in.h>

typedef struct {
    // int icmp_fd;
    // int ipv4_fd;
    // int tcp_fd;
    // int udp_fd;
    int fd;
    struct sockaddr_in* bind_addr;
} skt_raw_sock_t;

skt_raw_sock_t* skt_raw_sock_new(char* bind_ip);
int skt_raw_sock_send(skt_raw_sock_t* raw_sock, char* ip_packet, int len, char* new_src_ip, char* new_dst_ip);
// int skt_raw_sock_msend(skt_raw_sock_t* raw_sock, char* ip_packet, int len, char* src_ip, char* dst_ip);
// int skt_raw_sock_recv(skt_raw_sock_t* raw_sock, char* buf);
void skt_raw_sock_free(skt_raw_sock_t* raw_sock);

#endif