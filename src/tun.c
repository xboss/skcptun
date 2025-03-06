#if (defined(__linux__) || defined(__linux))
#include "tun.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "ladder.h"
int tun_alloc(char* dev, size_t dev_len) {
    if (dev == NULL || dev_len < IFNAMSIZ) {
        fprintf(stderr, "Invalid device name buffer\n");
        return _ERR;
    }

    struct ifreq ifr;
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("Opening /dev/net/tun");
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if ((err = ioctl(fd, TUNSETIFF, (void*)&ifr)) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return _ERR;
    }

    strncpy(dev, ifr.ifr_name, dev_len);
    return fd;
}

ssize_t tun_read(int fd, void* buf, size_t len) {
    if (buf == NULL || len == 0) {
        fprintf(stderr, "Invalid buffer for reading\n");
        return _ERR;
    }
    return read(fd, buf, len);
}

ssize_t tun_write(int fd, const void* buf, size_t len) {
    if (fd < 0 || buf == NULL || len == 0) {
        fprintf(stderr, "Invalid buffer for writing\n");
        return _ERR;
    }
    return write(fd, buf, len);
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

#endif