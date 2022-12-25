
#include "skt_tuntap.h"

#ifdef __APPLE__

#include <errno.h>
#include <net/if_utun.h>
#include <stdio.h>
#include <stdlib.h>  // exit, etc.
#include <string.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

// #define DEV_NAME_PREFIX "utun"
const char dev_name_prefix[] = "utun";

int skt_tuntap_open(int *dev_name_id) {
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
    *dev_name_id = i;

    char dev_name[32] = {0};
    snprintf(dev_name, sizeof(dev_name), "%s%d", dev_name_prefix, i);
    printf("dev_name: %s\n", dev_name);

    // If the connect is successful, a tun%d device will be created, where "%d"
    // is our unit number -1
    // if (connect(fd, (struct sockaddr *)&sc, sizeof(sc)) == -1) {
    //     perror("connect(AF_SYS_CONTROL)");
    //     close(fd);
    //     return -1;
    // }
    return fd;
}

void skt_tuntap_setup(int dev_name_id, char *device_ip) {
    char buf[256];
    snprintf(buf, sizeof(buf), "ifconfig %s%d %s %s", dev_name_prefix, dev_name_id, device_ip, device_ip);
    printf("run: %s", buf);
    system(buf);
}

int main(int argc, char **argv) {
    int dev_name_id = -1;
    int utunfd = skt_tuntap_open(&dev_name_id);

    if (utunfd == -1) {
        fprintf(stderr, "Unable to establish UTUN descriptor - aborting\n");
        exit(1);
    }

    skt_tuntap_setup(dev_name_id, "192.168.2.1");

    fprintf(stderr, "Utun interface is up.. Configure IPv4 using \"ifconfig utun1 _ipA_ _ipB_\"\n");
    fprintf(stderr, "                       Configure IPv6 using \"ifconfig utun1 inet6 _ip6_\"\n");
    fprintf(stderr, "Then (e.g.) ping _ipB_ (IPv6 will automatically generate ND messages)\n");

    // PoC - Just dump the packets...
    for (;;) {
        unsigned char c[1500];
        int len;
        int i;

        len = read(utunfd, c, 1500);

        // First 4 bytes of read data are the AF: 2 for AF_INET, 1E for AF_INET6, etc..
        for (i = 4; i < len; i++) {
            printf("%02x ", c[i]);
            if ((i - 4) % 16 == 15) printf("\n");
        }
        printf("\n");
    }

    return (0);
}

#endif /* __APPLE__ */
