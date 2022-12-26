#if (defined(__linux__) || defined(__linux))

#include <linux/if.h>
#include <linux/if_tun.h>

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

    ifr.ifr_flags = IFF_TUN; /* IFF_TUN or IFF_TAP, plus maybe IFF_NO_PI */

    // if (*dev_name) {
    //     /* if a device name was specified, put it in the structure; otherwise,
    //      * the kernel will try to allocate the "next" device of the
    //      * specified type */
    //     strncpy(ifr.ifr_name, dev_name, IFNAMSIZ);
    // }

    /* try to create the device */
    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        close(fd);
        return -1;
    }

    // strcpy(dev, ifr.ifr_name);
    snprintf(dev_name, name_len, "%s", ifr.ifr_name);
    printf("dev_name: %s\n", dev_name);

    return fd;
}

void skt_tuntap_setup(char *dev_name, char *device_ip) {
    // char buf[256] = {0};
    // snprintf(buf, sizeof(buf), "ifconfig %s%d %s %s", dev_name_prefix, dev_name_id, device_ip, device_ip);
    // printf("run: %s\n", buf);
    // system(buf);

    // memset(buf, 0, 256);
    // snprintf(buf, sizeof(buf), "ip route add 192.168.2.0/24 via 192.168.2.1");  // TODO: test
    // printf("run: %s\n", buf);
    // system(buf);
}

int skt_tuntap_read(int fd, char *buf, int len) { return read(fd, buf, len); }

int skt_tuntap_write(int fd, char *buf, int len) { return write(fd, buf, len); }

#endif
