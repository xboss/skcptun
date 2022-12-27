
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define RECV_LEN 2048

int main(int argc, char *argv[]) {
    int raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (raw_fd == -1) {
        perror("init_raw_sock error");
        return -1;
    }

    // int flag = 1;
    // if (setsockopt(raw_fd, IPPROTO_IP, IP_HDRINCL, &flag, sizeof(flag)) < 0) {
    //     perror("set_recv_timeout error");
    // }
    // printf("flag: %d\n", flag);

    // struct sockaddr_in servaddr;
    // bzero(&servaddr, sizeof(servaddr));
    // servaddr.sin_family = AF_INET;
    // servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    // // servaddr.sin_addr.s_addr = inet_addr("192.168.21.37");  // 192.168.21.37");
    // servaddr.sin_port = 0;
    // if (-1 == bind(raw_fd, (struct sockaddr *)&servaddr, sizeof(servaddr))) {
    //     perror("bind error");
    //     close(raw_fd);
    //     return -1;
    // }

    char src_ip[20] = {0};
    char dest_ip[20] = {0};

    // send
    printf("start send raw_fd: %d\n", raw_fd);
    unsigned char s_buf[] = {0x45, 0x00, 0x00, 0x54, 0x3e, 0xa6, 0x00, 0x00, 0x40, 0x01, 0x95, 0x8c, 0xc0, 0xa8,
                             0x15, 0x25, 0xc0, 0xa8, 0x10, 0x01, 0x08, 0x00, 0x84, 0xd9, 0x00, 0x65, 0x00, 0x08,
                             0x63, 0xaa, 0x74, 0x84, 0x00, 0x01, 0xaf, 0x86, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                             0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                             0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
                             0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37};
    struct sockaddr_in dest_addr;
    bzero(&dest_addr, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(argv[1]);
    // dest_addr.sin_port = htons(1001);

    inet_ntop(AF_INET, s_buf + 12, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, s_buf + 16, dest_ip, sizeof(dest_ip));
    printf("src_ip: %s dest_ip: %s\n", src_ip, dest_ip);
    printf("send args: raw_fd: %d, s_buf_len: %lu\n", raw_fd, sizeof(s_buf));

    int s_bytes = sendto(raw_fd, s_buf, sizeof(s_buf), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (s_bytes < 0) {
        perror("sendto error");
        return -1;
    }
    printf("send %s(%s) bytes: %d\n", argv[1], inet_ntoa(dest_addr.sin_addr), s_bytes);
    // printf("send %s(%s):%d bytes of data.\n", argv[1], inet_ntoa(dest_addr.sin_addr), datalen);

    // recv
    char raw_buf[RECV_LEN] = {0};
    struct sockaddr_in cliaddr;
    socklen_t cliaddr_len = sizeof(cliaddr);
    printf("start recv raw_fd: %d\n", raw_fd);
    int32_t bytes = recvfrom(raw_fd, raw_buf, RECV_LEN, 0, (struct sockaddr *)&cliaddr, &cliaddr_len);
    if (-1 == bytes) {
        perror("recvfrom error");
        return -1;
    }

    printf("recv bytes: %d\n", bytes);

    for (int i = 0; i < bytes; i++) {
        printf("%02x ", (raw_buf[i] & 0xFF));
        if (i % 16 == 15) printf("\n");
    }
    printf("\n");

    bzero(src_ip, 20);
    bzero(dest_ip, 20);
    inet_ntop(AF_INET, raw_buf + 12, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, raw_buf + 16, dest_ip, sizeof(dest_ip));
    printf("src_ip: %s dest_ip: %s\n", src_ip, dest_ip);

    return 0;
}