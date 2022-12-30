#if (defined(__linux__) || defined(__linux))

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <unistd.h>

#include "skt_tuntap.h"

int skt_tuntap_open(char *dev_name, int name_len) {
    struct ifreq ifr;
    int fd;
    char *clonedev = "/dev/net/tun";

    /* open the clone device */
    if ((fd = open(clonedev, O_RDWR)) < 0) {
        return -1;
    }

    /* preparation of the struct ifr, of type "struct ifreq" */
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; /* IFF_TUN or IFF_TAP, plus maybe IFF_NO_PI */

    /* try to create the device */
    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        close(fd);
        return -1;
    }

    snprintf(dev_name, name_len, "%s", ifr.ifr_name);
    printf("dev_name: %s\n", dev_name);

    return fd;
}

void skt_tuntap_setup(char *dev_name, char *device_ip) {
    char buf[256] = {0};
    snprintf(buf, sizeof(buf), "ip addr add %s/24 dev %s", device_ip, dev_name);
    printf("run: %s\n", buf);
    system(buf);

    // TODO: ifconfig tun0 netmask 255.255.255.0
    memset(buf, 0, 256);
    snprintf(buf, sizeof(buf), "ifconfig %s netmask 255.255.255.0", dev_name);
    printf("run: %s\n", buf);
    system(buf);

    // ifconfig utun5 mtu 1400
    memset(buf, 0, 256);
    snprintf(buf, sizeof(buf), "ifconfig %s mtu 1302", dev_name);  // 192.168.2.1");  // TODO: test
    printf("run: %s\n", buf);
    system(buf);

    memset(buf, 0, 256);
    snprintf(buf, sizeof(buf), "ip link set %s up", dev_name);
    printf("run: %s\n", buf);
    system(buf);
}

int skt_tuntap_read(int fd, char *buf, int len) { return read(fd, buf, len); }

int skt_tuntap_write(int fd, char *buf, int len) { return write(fd, buf, len); }

#endif
