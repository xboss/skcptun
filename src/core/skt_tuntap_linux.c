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

    /* Arguments taken by the function:
     *
     * char *dev: the name of an interface (or '\0'). MUST have enough
     *   space to hold the interface name if '\0' is passed
     * int flags: interface flags (eg, IFF_TUN etc.)
     */

    /* open the clone device */
    if ((fd = open(clonedev, O_RDWR)) < 0) {
        return -1;
    }

    /* preparation of the struct ifr, of type "struct ifreq" */
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; /* IFF_TUN or IFF_TAP, plus maybe IFF_NO_PI */

    // if (*dev_name) {
    //     /* if a device name was specified, put it in the structure; otherwise,
    //      * the kernel will try to allocate the "next" device of the
    //      * specified type */
    //     strncpy(ifr.ifr_name, dev_name, IFNAMSIZ);
    // }

    /* try to create the device */
    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        close(fd);
        return -1;
    }

    // strcpy(dev, ifr.ifr_name);
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

    memset(buf, 0, 256);
    snprintf(buf, sizeof(buf), "ip link set %s up", dev_name);
    printf("run: %s\n", buf);
    system(buf);
}

int skt_tuntap_read(int fd, char *buf, int len) { return read(fd, buf, len); }

int skt_tuntap_write(int fd, char *buf, int len) {
    // u_int32_t type = htonl(AF_INET);  // IPV4
    // struct iovec iv[2];

    // iv[0].iov_base = &type;
    // iv[0].iov_len = sizeof(type);
    // iv[1].iov_base = buf;
    // iv[1].iov_len = len;

    // int r = writev(fd, iv, 2);

    // if (r < 0) return r;
    // if (r <= sizeof(type)) return 0;

    // return r - sizeof(type);
    return write(fd, buf, len);
}

#endif
