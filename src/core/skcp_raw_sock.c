#include "skcp_raw_sock.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "skt_utils.h"

static struct sockaddr_in* bind_addr(int fd, char* bind_ip, uint16_t port) {
    struct sockaddr_in* bind_addr = malloc(sizeof(struct sockaddr_in));
    bzero(bind_addr, sizeof(struct sockaddr_in));
    bind_addr->sin_family = AF_INET;
    if (bind_ip) {
        inet_aton(bind_ip, &(bind_addr->sin_addr));
    }
    // printf(">>%s bind_addr %s\n", bind_ip, inet_ntoa(bind_addr->sin_addr));
    bind_addr->sin_port = port;  // TODO: 192.168.0.0 why?

    if (-1 == bind(fd, (struct sockaddr*)bind_addr, sizeof(struct sockaddr_in))) {
        perror("bind error");
        free(bind_addr);
        return bind_addr;
    }
    return bind_addr;
}

void skcp_raw_sock_free(skcp_raw_sock_t* raw_sock) {
    if (raw_sock == NULL) {
        return;
    }
    // if (raw_sock->icmp_fd) {
    //     close(raw_sock->icmp_fd);
    //     raw_sock->icmp_fd = 0;
    // }
    // if (raw_sock->ipv4_fd) {
    //     close(raw_sock->ipv4_fd);
    //     raw_sock->ipv4_fd = 0;
    // }
    // if (raw_sock->tcp_fd) {
    //     close(raw_sock->tcp_fd);
    //     raw_sock->tcp_fd = 0;
    // }
    if (raw_sock->fd) {
        close(raw_sock->fd);
        raw_sock->fd = 0;
    }

    if (raw_sock->bind_addr) {
        free(raw_sock->bind_addr);
        raw_sock->bind_addr = NULL;
    }

    free(raw_sock);
    raw_sock = NULL;
}

skcp_raw_sock_t* skcp_raw_sock_new(char* bind_ip) {
    skcp_raw_sock_t* raw_sock = malloc(sizeof(skcp_raw_sock_t));
    bzero(raw_sock, sizeof(skcp_raw_sock_t));
    int flag = 1;

    raw_sock->fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (raw_sock->fd == -1) {
        perror("skcp_raw_sock_new icmp error");
        skcp_raw_sock_free(raw_sock);
        return NULL;
    }

    if (setsockopt(raw_sock->fd, IPPROTO_IP, IP_HDRINCL, &flag, sizeof(flag)) < 0) {
        perror("skcp_raw_sock_new set IP_HDRINCL error");
    }
    printf("flag: %d\n", flag);

    if (bind_ip) {
        raw_sock->bind_addr = bind_addr(raw_sock->fd, bind_ip, 0);
        // printf("--- %s bind_addr %s\n", bind_ip, inet_ntoa(raw_sock->bind_addr->sin_addr));
        if (!raw_sock->bind_addr) {
            skcp_raw_sock_free(raw_sock);
            return NULL;
        }
    }

    // raw_sock->icmp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    // if (raw_sock->icmp_fd == -1) {
    //     perror("skcp_raw_sock_new icmp error");
    //     skcp_raw_sock_free(raw_sock);
    //     return NULL;
    // }

    // if (setsockopt(raw_sock->icmp_fd, IPPROTO_IP, IP_HDRINCL, &flag, sizeof(flag)) < 0) {
    //     perror("skcp_raw_sock_new set IP_HDRINCL error");
    // }
    // printf("flag: %d\n", flag);

    // if (bind_ip) {
    //     raw_sock->bind_addr = bind_addr(raw_sock->icmp_fd, bind_ip, 0);
    //     if (!raw_sock->bind_addr) {
    //         skcp_raw_sock_free(raw_sock);
    //         return NULL;
    //     }
    // }

    // raw_sock->ipv4_fd = socket(AF_INET, SOCK_RAW, IPPROTO_IPV4);
    // if (raw_sock->ipv4_fd == -1) {
    //     perror("skcp_raw_sock_new ipv4 error");
    //     skcp_raw_sock_free(raw_sock);
    //     return NULL;
    // }
    // if (setsockopt(raw_sock->ipv4_fd, IPPROTO_IP, IP_HDRINCL, &flag, sizeof(flag)) < 0) {
    //     perror("skcp_raw_sock_new set IP_HDRINCL error");
    // }
    // printf("flag: %d\n", flag);
    // if (bind_ip) {
    //     raw_sock->bind_addr = bind_addr(raw_sock->ipv4_fd, bind_ip, 0);
    //     if (!raw_sock->bind_addr) {
    //         skcp_raw_sock_free(raw_sock);
    //         return NULL;
    //     }
    // }

    // raw_sock->tcp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    // if (raw_sock->tcp_fd == -1) {
    //     perror("skcp_raw_sock_new tcp error");
    //     skcp_raw_sock_free(raw_sock);
    //     return NULL;
    // }
    // if (bind_ip) {
    //     raw_sock->bind_addr = bind_addr(raw_sock->tcp_fd, bind_ip, 0);
    //     if (!raw_sock->bind_addr) {
    //         skcp_raw_sock_free(raw_sock);
    //         return NULL;
    //     }
    // }

    // raw_sock->udp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    // if (raw_sock->udp_fd == -1) {
    //     perror("skcp_raw_sock_new udp error");
    //     skcp_raw_sock_free(raw_sock);
    //     return NULL;
    // }
    // if (bind_ip) {
    //     raw_sock->bind_addr = bind_addr(raw_sock->udp_fd, bind_ip, 0);
    //     if (!raw_sock->bind_addr) {
    //         skcp_raw_sock_free(raw_sock);
    //         return NULL;
    //     }
    // }

    return raw_sock;
}

int skcp_raw_sock_send(skcp_raw_sock_t* raw_sock, char* ip_packet, int len, char* new_src_ip, char* new_dst_ip) {
    if (!raw_sock || !ip_packet || len < 20) {
        return -1;
    }

    struct ip* ip = (struct ip*)ip_packet;
    ip->ip_id = 0;
    ip->ip_sum = 0;
    ip->ip_len = len;
    // ip->ip_src.s_addr = INADDR_ANY;
    if (new_src_ip) {
        inet_aton(new_src_ip, &ip->ip_src);
    }
    if (new_dst_ip) {
        inet_aton(new_dst_ip, &ip->ip_dst);
    }
    // printf("bind_addr %s\n", inet_ntoa(raw_sock->bind_addr->sin_addr));
    // printf("ip_src %s\n", inet_ntoa(ip->ip_src));
    if (raw_sock->bind_addr) {
        ip->ip_src = raw_sock->bind_addr->sin_addr;
    }

    struct sockaddr_in dst_addr;
    bzero(&dst_addr, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_addr = ip->ip_dst;

    int iphead_len = ip->ip_hl * 4;

    printf("ip_src %s\n", inet_ntoa(ip->ip_src));

    int s_bytes = sendto(raw_sock->fd, ip_packet, len, 0, (struct sockaddr*)&dst_addr, sizeof(dst_addr));
    if (s_bytes < 0) {
        perror("skcp_raw_sock_send sendto error");
        return -1;
    }
    LOG_D("skcp_raw_sock_send send bytes: %d", s_bytes);
    return s_bytes;

    // int s_bytes = -1;
    // int buf_len = len - iphead_len;
    // int buf_len = len;
    // char* buf = malloc(buf_len);
    // bzero(buf, buf_len);
    // // memcpy(buf, ip_packet, len);
    // // memcpy(buf, ip_packet, 20);
    // // memcpy(buf, ip_packet + 20, len - 20);
    // memcpy(buf, ip_packet + iphead_len, buf_len);
    // LOG_D("%d, %d, %d", iphead_len, buf_len, len);

    // switch (iph.ip_p) {
    // switch (ip->ip_p) {
    //     case IPPROTO_ICMP:
    //         s_bytes = sendto(raw_sock->icmp_fd, ip_packet, len, 0, (struct sockaddr*)&dst_addr, sizeof(dst_addr));
    //         break;
    //     case IPPROTO_IPV4:
    //         s_bytes = sendto(raw_sock->ipv4_fd, ip_packet + iphead_len, len - iphead_len, 0,
    //                          (struct sockaddr*)&dst_addr, sizeof(dst_addr));
    //         break;
    //     case IPPROTO_TCP:
    //         s_bytes = sendto(raw_sock->tcp_fd, ip_packet + iphead_len, len - iphead_len, 0, (struct
    //         sockaddr*)&dst_addr,
    //                          sizeof(dst_addr));
    //         break;
    //     case IPPROTO_UDP:
    //         s_bytes = sendto(raw_sock->udp_fd, ip_packet + iphead_len, len - iphead_len, 0, (struct
    //         sockaddr*)&dst_addr,
    //                          sizeof(dst_addr));
    //         break;

    //     default:
    //         LOG_W("unknow protocol 0x%x", ip->ip_p);
    //         break;
    // }
    // free(buf);
    // buf = NULL;
}

// int skcp_raw_sock_msend(skcp_raw_sock_t* raw_sock, char* ip_packet, int len, char* src_ip, char* dst_ip) {
//     if (!raw_sock || !ip_packet || len < 20) {
//         return -1;
//     }

//     struct ip* ip = (struct ip*)ip_packet;
//     ip->ip_id = 0;
//     // struct ip iph;
//     // iph.ip_hl = ip->ip_hl;
//     // iph.ip_v = ip->ip_v;
//     // iph.ip_tos = ip->ip_tos;
//     // iph.ip_len = ip->ip_len;
//     // iph.ip_id = ip->ip_id;
//     // iph.ip_off = ip->ip_off;
//     // iph.ip_ttl = ip->ip_ttl;
//     // iph.ip_p = ip->ip_p;

//     // if (src_ip) {
//     //     inet_pton(AF_INET, src_ip, &iph.ip_src);
//     // } else {
//     //     iph.ip_src = ip->ip_src;
//     // }

//     // if (dst_ip) {
//     //     inet_pton(AF_INET, dst_ip, &iph.ip_dst);
//     // } else {
//     //     iph.ip_dst = ip->ip_dst;
//     // }
//     // // Ip checksum
//     // iph.ip_sum = 0;
//     // iph.ip_sum = ip_checksum((unsigned short*)&iph, 10);
//     // memcpy(ip_packet, &iph, 20);

//     int modify = 0;
//     if (src_ip) {
//         inet_pton(AF_INET, src_ip, &ip->ip_src);
//         modify = 1;
//     }

//     if (dst_ip) {
//         inet_pton(AF_INET, dst_ip, &ip->ip_dst);
//         modify = 1;
//     }

//     if (modify) {
//         // ip checksum
//         ip->ip_sum = 0;
//         ip->ip_sum = ip_checksum((unsigned short*)ip, 10);
//     }

//     char* buf = malloc(len);
//     bzero(buf, len);
//     // memcpy(buf, ip_packet, len);
//     // memcpy(buf, ip_packet, 20);
//     memcpy(buf, ip_packet + 20, len - 20);

//     char src_ip_s[20] = {0};
//     // char dest_ip_s[20] = {0};
//     bzero(src_ip_s, 20);
//     // bzero(dest_ip, 20);
//     inet_ntop(AF_INET, ip_packet + 12, src_ip_s, sizeof(src_ip_s));
//     // inet_ntop(AF_INET, buf + 16, dest_ip, sizeof(dest_ip));
//     printf("src ip %s\n", src_ip_s);

//     struct sockaddr_in dst_addr;
//     bzero(&dst_addr, sizeof(dst_addr));
//     dst_addr.sin_family = AF_INET;
//     // dst_addr.sin_addr = iph.ip_dst;
//     dst_addr.sin_addr = ip->ip_dst;
//     int s_bytes = -1;
//     // switch (iph.ip_p) {
//     switch (ip->ip_p) {
//         case IPPROTO_ICMP:
//             s_bytes = sendto(raw_sock->icmp_fd, buf, len, 0, (struct sockaddr*)&dst_addr, sizeof(dst_addr));
//             break;
//         case IPPROTO_IPV4:
//             s_bytes = sendto(raw_sock->ipv4_fd, buf, len, 0, (struct sockaddr*)&dst_addr, sizeof(dst_addr));
//             break;
//         case IPPROTO_TCP:
//             s_bytes = sendto(raw_sock->tcp_fd, buf, len, 0, (struct sockaddr*)&dst_addr, sizeof(dst_addr));
//             break;
//         case IPPROTO_UDP:
//             s_bytes = sendto(raw_sock->udp_fd, buf, len, 0, (struct sockaddr*)&dst_addr, sizeof(dst_addr));
//             break;

//         default:
//             // LOG_W("unknow protocol 0x%x", iph.ip_p);
//             break;
//     }

//     free(buf);
//     buf = NULL;

//     if (s_bytes < 0) {
//         perror("skcp_raw_sock_msend sendto error");
//         return -1;
//     }
//     printf("send %s(%s) bytes: %d\n", dst_ip, inet_ntoa(dst_addr.sin_addr), s_bytes);
//     return s_bytes;
// }