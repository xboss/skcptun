#include "tun.h"

#ifdef __APPLE__

#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_utun.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/uio.h>
#include <unistd.h>

#define _OK 0
#define _ERR -1

int tun_alloc(char* dev, size_t dev_len) {
    if (dev == NULL || dev_len < IFNAMSIZ) {
        fprintf(stderr, "Invalid device name buffer\n");
        return _ERR;
    }

    struct sockaddr_ctl addr;
    struct ctl_info ctl_info;
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) {
        perror("socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)");
        return _ERR;
    }

    memset(&ctl_info, 0, sizeof(ctl_info));
    strncpy(ctl_info.ctl_name, UTUN_CONTROL_NAME, MAX_KCTL_NAME);
    if (ioctl(fd, CTLIOCGINFO, &ctl_info) < 0) {
        perror("ioctl(CTLIOCGINFO)");
        close(fd);
        return _ERR;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_id = ctl_info.ctl_id;
    addr.sc_unit = 0;  // 从0开始动态分配

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect(AF_SYS_CONTROL)");
        close(fd);
        return _ERR;
    }

    snprintf(dev, dev_len, "utun%d", addr.sc_unit);
    return fd;
}

ssize_t tun_read(int fd, void* buf, size_t len) {
    if (buf == NULL || len == 0) {
        fprintf(stderr, "Invalid buffer for reading\n");
        return _ERR;
    }
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

ssize_t tun_write(int fd, const void* buf, size_t len) {
    if (fd < 0 || buf == NULL || len == 0) {
        fprintf(stderr, "Invalid buffer for writing\n");
        return _ERR;
    }
    u_int32_t type = htonl(AF_INET);  // IPV4
    struct iovec iv[2];

    iv[0].iov_base = &type;
    iv[0].iov_len = sizeof(type);
    iv[1].iov_base = (void*)buf;
    iv[1].iov_len = len;

    int r = writev(fd, iv, 2);

    if (r < 0) return r;
    if (r <= sizeof(type)) return 0;

    return r - sizeof(type);
}

int tun_set_ip(const char* dev, const char* ip) {
    if (dev == NULL || ip == NULL) {
        fprintf(stderr, "Invalid device name or IP address\n");
        return _ERR;
    }

    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket(AF_INET, SOCK_DGRAM)");
        return _ERR;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    if (inet_pton(AF_INET, ip, &addr->sin_addr) <= 0) {
        perror("inet_pton");
        close(fd);
        return _ERR;
    }

    if (ioctl(fd, SIOCSIFADDR, &ifr) < 0) {
        perror("ioctl(SIOCSIFADDR)");
        close(fd);
        return _ERR;
    }

    close(fd);
    return _OK;
}

int tun_set_netmask(const char* dev, const char* netmask) {
    if (dev == NULL || netmask == NULL) {
        fprintf(stderr, "Invalid device name or netmask\n");
        return _ERR;
    }

    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket(AF_INET, SOCK_DGRAM)");
        return _ERR;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    if (inet_pton(AF_INET, netmask, &addr->sin_addr) <= 0) {
        perror("inet_pton");
        close(fd);
        return _ERR;
    }

    if (ioctl(fd, SIOCSIFNETMASK, &ifr) < 0) {
        perror("ioctl(SIOCSIFNETMASK)");
        close(fd);
        return _ERR;
    }

    close(fd);
    return _OK;
}

int tun_set_mtu(const char* dev, int mtu) {
    if (dev == NULL || mtu <= 0) {
        fprintf(stderr, "Invalid device name or MTU\n");
        return _ERR;
    }

    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket(AF_INET, SOCK_DGRAM)");
        return _ERR;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    ifr.ifr_mtu = mtu;

    if (ioctl(fd, SIOCSIFMTU, &ifr) < 0) {
        perror("ioctl(SIOCSIFMTU)");
        close(fd);
        return _ERR;
    }

    close(fd);
    return _OK;
}

int tun_up(const char* dev) {
    if (dev == NULL) {
        fprintf(stderr, "Invalid device name\n");
        return _ERR;
    }

    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket(AF_INET, SOCK_DGRAM)");
        return _ERR;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("ioctl(SIOCGIFFLAGS)");
        close(fd);
        return _ERR;
    }

    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("ioctl(SIOCSIFFLAGS)");
        close(fd);
        return _ERR;
    }

    close(fd);
    return _OK;
}

#endif /* __APPLE__ */