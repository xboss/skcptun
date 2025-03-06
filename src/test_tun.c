#include <stdio.h>
#include <unistd.h>
#include <net/if.h>

#include "tun.h"

int main() {
    char dev[IFNAMSIZ];
    int tun_fd = tun_alloc(dev, sizeof(dev));
    if (tun_fd < 0) {
        fprintf(stderr, "Failed to allocate TUN device\n");
        return 1;
    }
    printf("TUN device allocated with name: %s and file descriptor: %d\n", dev, tun_fd);

    if (tun_set_ip(dev, "10.0.0.1") < 0) {
        fprintf(stderr, "Failed to set IP address\n");
        close(tun_fd);
        return 1;
    }
    printf("TUN device IP set to 10.0.0.1\n");

    if (tun_set_netmask(dev, "255.255.255.0") < 0) {
        fprintf(stderr, "Failed to set netmask\n");
        close(tun_fd);
        return 1;
    }
    printf("TUN device netmask set to 255.255.255.0\n");

    if (tun_set_mtu(dev, 1500) < 0) {
        fprintf(stderr, "Failed to set MTU\n");
        close(tun_fd);
        return 1;
    }
    printf("TUN device MTU set to 1500\n");

    if (tun_up(dev) < 0) {
        fprintf(stderr, "Failed to bring up TUN device\n");
        close(tun_fd);
        return 1;
    }
    printf("TUN device %s is up\n", dev);

    char buffer[1500];
    while (1) {
        ssize_t nread = tun_read(tun_fd, buffer, sizeof(buffer));
        if (nread < 0) {
            fprintf(stderr, "Failed to read from TUN device\n");
            break;
        }
        printf("Read %zd bytes from TUN device\n", nread);

        // Echo the data back
        // if (tun_write(tun_fd, buffer, nread) < 0) {
        //     fprintf(stderr, "Failed to write to TUN device\n");
        //     break;
        // }
    }

    close(tun_fd);
    return 0;
}
