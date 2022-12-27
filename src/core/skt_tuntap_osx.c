
#include "skt_tuntap.h"

#ifdef __APPLE__

#include <arpa/inet.h>
#include <errno.h>
#include <net/if_utun.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <syslog.h>
#include <unistd.h>

static const char dev_name_prefix[] = "utun";

int skt_tuntap_open(char *dev_name, int name_len) {
    struct sockaddr_ctl sc;
    struct ctl_info ctlInfo;
    int fd;

    memset(&ctlInfo, 0, sizeof(ctlInfo));
    if (strlcpy(ctlInfo.ctl_name, UTUN_CONTROL_NAME, sizeof(ctlInfo.ctl_name)) >= sizeof(ctlInfo.ctl_name)) {
        fprintf(stderr, "UTUN_CONTROL_NAME too long");
        return -1;
    }
    fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);

    // printf("ctl_name: %s\n", ctlInfo.ctl_name);

    if (fd == -1) {
        perror("socket(SYSPROTO_CONTROL)");
        return -1;
    }
    if (ioctl(fd, CTLIOCGINFO, &ctlInfo) == -1) {
        perror("ioctl(CTLIOCGINFO)");
        close(fd);
        return -1;
    }

    sc.sc_id = ctlInfo.ctl_id;
    sc.sc_len = sizeof(sc);
    sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = AF_SYS_CONTROL;
    // sc.sc_unit = 10; /* Only have one, in this example... */

    int i = -1;
    for (i = 1; i < 255; i++) {
        sc.sc_unit = i;
        int c_rt = connect(fd, (struct sockaddr *)&sc, sizeof(sc));
        if (c_rt == 0) {
            break;
        }
        // else {
        //     perror("connect(AF_SYS_CONTROL)");
        // }
    }

    if (i < 1 || i >= 255) {
        perror("connect(AF_SYS_CONTROL)");
        close(fd);
        return -1;
    }

    i--;
    // *dev_name_id = i;

    // char dev_name[32] = {0};
    snprintf(dev_name, name_len, "%s%d", dev_name_prefix, i);
    printf("dev_name: %s\n", dev_name);

    return fd;
}

void skt_tuntap_setup(char *dev_name, char *device_ip) {
    // uint32_t dest_ip;
    // inet_pton(AF_INET, device_ip, &dest_ip);
    // printf("dest_ip: %d\n", dest_ip);
    // dest_ip++;
    // printf("dest_ip: %d\n", dest_ip);
    // char dest_ip_str[32] = {0};
    // inet_ntop(AF_INET, &dest_ip, dest_ip_str, sizeof(dest_ip_str));
    // printf("dest_ip_str: %s\n", dest_ip_str);

    char buf[256] = {0};
    snprintf(buf, sizeof(buf), "ifconfig %s %s %s", dev_name, device_ip, "192.168.2.2");  // TODO: test
    printf("run: %s\n", buf);
    system(buf);

    memset(buf, 0, 256);
    snprintf(buf, sizeof(buf), "ip route add 192.168.2.0/24 via 192.168.2.1");  // TODO: test
    printf("run: %s\n", buf);
    system(buf);
}

int skt_tuntap_read(int fd, char *buf, int len) {
    u_int32_t type;
    struct iovec iv[2];

    iv[0].iov_base = &type;
    iv[0].iov_len = sizeof(type);
    iv[1].iov_base = buf;
    iv[1].iov_len = len;

    int r = readv(fd, iv, 2);

    if (r < 0) return r;
    if (r <= sizeof(type)) return 0;
    return r - sizeof(type);
}

int skt_tuntap_write(int fd, char *buf, int len) {
    u_int32_t type = htonl(AF_INET);  // IPV4
    struct iovec iv[2];

    iv[0].iov_base = &type;
    iv[0].iov_len = sizeof(type);
    iv[1].iov_base = buf;
    iv[1].iov_len = len;

    int r = writev(fd, iv, 2);

    if (r < 0) return r;
    if (r <= sizeof(type)) return 0;

    return r - sizeof(type);

    // return write(fd, buf, len);
}

//////////////////////////////////////
//////////////// TEST ////////////////
//////////////////////////////////////

// int start_udp(int is_serv_mode, char *addr, uint16_t port) {
//     int fd = socket(AF_INET, SOCK_DGRAM, 0);
//     if (-1 == fd) {
//         printf("udp socket error");
//         return -1;
//     }
//     // struct sockaddr_in sockaddr;
//     // sockaddr.sin_family = AF_INET;
//     // sockaddr.sin_port = htons(port);
//     // sockaddr.sin_addr.s_addr = inet_addr(addr);

//     if (is_serv_mode) {
//         struct sockaddr_in servaddr;
//         bzero(&servaddr, sizeof(servaddr));
//         servaddr.sin_family = AF_INET;
//         if (NULL == addr) {
//             servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
//         } else {
//             servaddr.sin_addr.s_addr = inet_addr(addr);
//         }
//         servaddr.sin_port = htons(port);

//         if (-1 == bind(fd, (struct sockaddr *)&servaddr, sizeof(servaddr))) {
//             printf("bind error when start ucp server\n");
//             close(fd);
//             return -1;
//         }

//         printf("udp server start ok. fd: %d addr: %s port: %u\n", fd, addr, port);
//     } else {
//         printf("udp client start ok. fd: %d\n", fd);
//     }
//     return fd;
// }

// // int udp_send(int fd, struct sockaddr_in *addr, char *buf, int len) {
// //     int rt = sendto(fd, buf, len, 0, (struct sockaddr *)addr, sizeof(*addr));
// //     if (-1 == rt) {
// //         perror("udp sendto error");
// //     }
// //     return rt;
// // }

// void vpn_cli() {
//     int dev_name_id = -1;
//     int utunfd = skt_tuntap_open(&dev_name_id);

//     if (utunfd == -1) {
//         fprintf(stderr, "Unable to establish UTUN descriptor - aborting\n");
//         exit(1);
//     }

//     skt_tuntap_setup(dev_name_id, "192.168.2.1");

//     // fprintf(stderr, "Utun interface is up.. Configure IPv4 using \"ifconfig utun1 _ipA_ _ipB_\"\n");
//     // fprintf(stderr, "                       Configure IPv6 using \"ifconfig utun1 inet6 _ip6_\"\n");
//     // fprintf(stderr, "Then (e.g.) ping _ipB_ (IPv6 will automatically generate ND messages)\n");

//     // PoC - Just dump the packets...
//     for (;;) {
//         unsigned char buf[1500];
//         int len;
//         int i;

//         len = skt_tuntap_read(utunfd, (char *)buf, 1500);
//         // int src_addr_n;
//         // int dest_addr_n;

//         char src_ip[20] = {0};
//         char dest_ip[20] = {0};
//         inet_ntop(AF_INET, buf + 12, src_ip, sizeof(src_ip));
//         inet_ntop(AF_INET, buf + 16, dest_ip, sizeof(dest_ip));
//         printf("src_ip: %s dest_ip: %s\n", src_ip, dest_ip);

//         char target_ip[] = "192.168.1.5";
//         struct in_addr target_addr_n;
//         inet_pton(AF_INET, target_ip, (void *)&target_addr_n);
//         printf("target_addr_n: %d\n", target_addr_n.s_addr);

//         // *(buf + 16) = target_addr_n.s_addr; htonl
//         // memcpy(buf + 16, &target_addr_n.s_addr, sizeof(target_addr_n.s_addr));
//         // memcpy(buf + 12, &target_addr_n.s_addr, sizeof(target_addr_n.s_addr));

//         // skt_tuntap_write(utunfd, (char *)buf, len);

//         // len = read(utunfd, c, 1500);

//         // // First 4 bytes of read data are the AF: 2 for AF_INET, 1E for AF_INET6, etc..
//         for (i = 4; i < len; i++) {
//             printf("%02x ", buf[i]);
//             if ((i - 4) % 16 == 15) printf("\n");
//         }
//         printf("\n");
//     }
// }

// void run_udp_cli(char *addr, uint16_t port) {
//     int fd = start_udp(1, addr, port);
//     if (fd == -1) {
//         return;
//     }
//     struct sockaddr_in cliaddr;
//     socklen_t cliaddr_len = sizeof(cliaddr);
//     char buf[2048] = {0};
//     ssize_t bytes = -1;
//     while ((bytes = recvfrom(fd, buf, 2048, 0, (struct sockaddr *)&cliaddr, &cliaddr_len)) > 0) {
//         printf(">%s", buf);
//         sendto(fd, buf, 2048, 0, (struct sockaddr *)&cliaddr, sizeof(cliaddr));
//         memset(buf, 0, 2048);
//     }
// }

// void run_udp_serv(char *addr, uint16_t port) {
//     int fd = start_udp(0, NULL, 0);
//     if (fd == -1) {
//         return;
//     }

//     struct sockaddr_in servaddr;
//     servaddr.sin_family = AF_INET;
//     servaddr.sin_port = htons(port);
//     servaddr.sin_addr.s_addr = inet_addr(addr);
//     socklen_t servaddr_len = sizeof(servaddr);

//     struct sockaddr_in cliaddr;
//     socklen_t cliaddr_len = sizeof(cliaddr);

//     sendto(fd, "aaa", 3, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
//     char buf[2048] = {0};
//     ssize_t bytes = -1;
//     while ((bytes = recvfrom(fd, buf, 2048, 0, (struct sockaddr *)&cliaddr, &cliaddr_len)) > 0) {
//         printf(">%s", buf);
//         sendto(fd, buf, 2048, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
//         memset(buf, 0, 2048);
//     }
// }

// #define SKT_TEST_USAGE                                                                                              \
//     fprintf(stderr,                                                                                                 \
//             "Usage: %s mode\n  mode:\n    1: start vpn client\n    2: start udp server\n    3: start udp client\n", \
//             argv[0])

// // int main(int argc, char **argv) {
// //     if (argc < 2) {
// //         SKT_TEST_USAGE;
// //         return 1;
// //     }

// //     char *addr = "0.0.0.0";
// //     uint16_t port = 9090;
// //     if (strcmp(argv[1], "1") == 0) {
// //         vpn_cli();
// //     } else if (strcmp(argv[1], "2") == 0) {
// //         run_udp_serv(addr, port);
// //     } else if (strcmp(argv[1], "3") == 0) {
// //         run_udp_cli(addr, port);
// //     } else {
// //         SKT_TEST_USAGE;
// //         return 1;
// //     }

// //     /******** test udp server start ********/

// //     /******** test udp server end ********/

// //     /******** test udp client start ********/

// //     /******** test udp client end ********/

// //     return 0;
// // }

#endif /* __APPLE__ */
