
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

    snprintf(dev_name, name_len, "%s%d", dev_name_prefix, i);
    printf("dev_name: %s\n", dev_name);

    return fd;
}

void skt_tuntap_setup(char *dev_name, char *dev_ip, char *dev_mask) {
    char buf[256] = {0};
    snprintf(buf, sizeof(buf), "ifconfig %s %s %s", dev_name, dev_ip, dev_ip);
    printf("run: %s\n", buf);
    system(buf);

    struct in_addr ip_n;
    inet_aton(dev_ip, &ip_n);
    struct in_addr ip_mask;
    inet_aton(dev_mask, &ip_mask);
    ip_n.s_addr = ip_n.s_addr & ip_mask.s_addr;

    memset(buf, 0, 256);
    snprintf(buf, sizeof(buf), "route -n add -net %s -netmask %s %s", inet_ntoa(ip_n), dev_mask, dev_ip);
    printf("run: %s\n", buf);
    system(buf);

    // ifconfig utun5 mtu 1400
    memset(buf, 0, 256);
    snprintf(buf, sizeof(buf), "ifconfig %s mtu 1302", dev_name);
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

#endif /* __APPLE__ */
