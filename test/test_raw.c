
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
    char ip_packet[] = {0x45, 0x00, 0x00, 0x54, 0x7c, 0x3a, 0x00, 0x00, 0x40, 0x01, 0xbe, 0x7c, 0xc0, 0xa8,
                        0x01, 0x05, 0xb6, 0x3d, 0xc8, 0x07, 0x08, 0x00, 0x2c, 0x2d, 0x1e, 0x57, 0x00, 0x00,
                        0x63, 0xb6, 0xa2, 0x35, 0x00, 0x01, 0xbc, 0x8b, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                        0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                        0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
                        0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37};
    // char ip_packet[84] = {0};

    int len = sizeof(ip_packet);

    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) {
        perror("skcp_raw_sock_new icmp error");
        close(fd);
        return -1;
    }

    int flag = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &flag, sizeof(flag)) < 0) {
        perror("set IP_HDRINCL error");
    }
    printf("flag: %d\n", flag);

    struct ip* ip = (struct ip*)ip_packet;
    ip->ip_id = 0;
    ip->ip_sum = 0;
    // ip->ip_v = IPVERSION;
    // ip->ip_hl = sizeof(struct ip) >> 2;
    // ip->ip_tos = 0;
    // ip->ip_id = 0;
    // ip->ip_off = 0;
    // ip->ip_ttl = 101;
    ip->ip_p = IPPROTO_ICMP;
    ip->ip_src.s_addr = INADDR_ANY;
    inet_aton("127.0.0.1", &ip->ip_dst);
    ip->ip_len = len;  // 需要添加len

    struct sockaddr_in dst_addr;
    bzero(&dst_addr, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_len = sizeof(dst_addr);
    // dst_addr.sin_addr = iph.ip_dst;
    // dst_addr.sin_addr.s_addr = inet_addr("182.61.200.7");  // ip->ip_dst;
    dst_addr.sin_addr = ip->ip_dst;

    int iphead_len = ip->ip_hl * 4;
    printf("iphead_len: %d\n", iphead_len);

    int s_bytes = sendto(fd, ip_packet, len, 0, (struct sockaddr*)&dst_addr, sizeof(dst_addr));

    if (s_bytes < 0) {
        perror("skcp_raw_sock_send sendto error");
        return -1;
    }

    return 0;
}