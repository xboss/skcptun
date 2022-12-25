
#include "skt_tuntap_osx.h"

#ifdef __APPLE__

// #include <arpa/inet.h>
// #include <errno.h>
// #include <fcntl.h>
// #include <stdlib.h>
// #include <string.h>
// #include <unistd.h>

// #define SKT_OSX_TAPDEVICE_SIZE 32

// // void tun_close(skt_tuntap_dev_t *device);
// void skt_tuntap_close(skt_tuntap_dev_t *tuntap) { close(tuntap->fd); }

// int skt_tuntap_open(skt_tuntap_dev_t *device /* ignored */, char *dev, const char *address_mode, /* static or dhcp */
//                     char *device_ip, char *device_mask, const char *device_mac, int mtu) {
//     int i;
//     char tap_device[SKT_OSX_TAPDEVICE_SIZE];

//     for (i = 0; i < 255; i++) {
//         snprintf(tap_device, sizeof(tap_device), "/dev/tap%d", i);

//         device->fd = open(tap_device, O_RDWR);
//         if (device->fd > 0) {
//             LOG_I("Succesfully open %s", tap_device);
//             break;
//         }
//     }

//     if (device->fd < 0) {
//         LOG_E("Unable to open any tap devices errno: %d %s", errno, strerror(errno));
//         return -1;
//     } else {
//         char buf[256];
//         FILE *fd;

//         device->ip_addr = inet_addr(device_ip);

//         if (device_mac && device_mac[0] != '\0') {
//             // FIXME - this is not tested. might be wrong syntax for OS X
//             // set the hw address before bringing the if up
//             snprintf(buf, sizeof(buf), "ifconfig tap%d ether %s", i, device_mac);
//             system(buf);
//         }

//         snprintf(buf, sizeof(buf), "ifconfig tap%d %s netmask %s mtu %d up", i, device_ip, device_mask, mtu);
//         system(buf);

//         LOG_I("Interface tap%d up and running (%s/%s)", i, device_ip, device_mask);

//         // read MAC address
//         snprintf(buf, sizeof(buf), "ifconfig tap%d |grep ether|cut -c 8-24", i);
//         // traceEvent(TRACE_INFO, "%s", buf);

//         fd = popen(buf, "r");
//         if (fd < 0) {
//             skt_tuntap_close(device);
//             return -1;
//         } else {
//             int a, b, c, d, e, f;

//             buf[0] = 0;
//             fgets(buf, sizeof(buf), fd);
//             pclose(fd);

//             if (buf[0] == '\0') {
//                 LOG_W("Unable to read tap%d interface MAC address", i);
//                 exit(0);
//             }

//             LOG_I("Interface tap%d [MTU %d] mac %s", i, mtu, buf);
//             if (sscanf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", &a, &b, &c, &d, &e, &f) == 6) {
//                 device->mac_addr[0] = a, device->mac_addr[1] = b;
//                 device->mac_addr[2] = c, device->mac_addr[3] = d;
//                 device->mac_addr[4] = e, device->mac_addr[5] = f;
//             }
//         }
//     }

//     // read_mac(dev, device->mac_addr);

//     return (device->fd);
// }

// int skt_tuntap_read(skt_tuntap_dev_t *tuntap, unsigned char *buf, int len) { return (read(tuntap->fd, buf, len)); }

// int skt_tuntap_write(skt_tuntap_dev_t *tuntap, unsigned char *buf, int len) { return (write(tuntap->fd, buf, len)); }

// // // fill out the ip_addr value from the interface, called to pick up dynamic address changes
// // void skt_tuntap_get_address(skt_tuntap_dev_t *tuntap) {
// //     // no action
// // }

// int main(int argc, char *argv[]) {
//     skt_tuntap_dev_t device;
//     int fd = skt_tuntap_open(&device, NULL, NULL, "192.168.2.1", "255.255.255.0", NULL, 1400);

//     return 0;
// }

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/kern_event.h>
#include <sys/socket.h>
#include <unistd.h>

#define UTUN_CONTROL_NAME "com.apple.net.utun_control"
#define UTUN_OPT_IFNAME 2

int open_tun_socket() {
    struct sockaddr_ctl addr;
    struct ctl_info info;
    char ifname[20];
    socklen_t ifname_len = sizeof(ifname);
    int fd = -1;
    int err = 0;

    fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) return fd;

    bzero(&info, sizeof(info));
    strncpy(info.ctl_name, UTUN_CONTROL_NAME, MAX_KCTL_NAME);

    err = ioctl(fd, CTLIOCGINFO, &info);
    if (err != 0) goto on_error;

    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_id = info.ctl_id;
    addr.sc_unit = 0;

    err = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (err != 0) {
        printf("connect error %d %s\n", errno, strerror(errno));
        goto on_error;
    }

    // TODO: forward ifname (we just expect it to be utun0 for now...)
    err = getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &ifname_len);
    if (err != 0) goto on_error;

    printf("dev: %s\n", ifname);

    // There is to close the socket,But in this case I don't need it.
    // err = fcntl(fd, F_SETFL, O_NONBLOCK);
    // if (err != 0) goto on_error;

    // fcntl(fd, F_SETFD, FD_CLOEXEC);
    // if (err != 0) goto on_error;

on_error:
    if (err != 0) {
        close(fd);
        return err;
    }

    return fd;
}

int main(int argc, char *argv[]) {
    int tun_fd = open_tun_socket();
    printf("tun_fd: %d\n", tun_fd);

    if (tun_fd < 0) {
        perror("Allocating interface");
        exit(1);
    }

    int nread = 0;
    char buffer[1500];
    while (1) {
        nread = read(tun_fd, buffer, sizeof(buffer));
        if (nread < 0) {
            perror("Reading from interface");
            close(tun_fd);
            exit(1);
        }

        printf("Read %d bytes from tun/tap device\n", nread);
    }
    // while (result > 0) {
    // }
}

#endif /* __APPLE__ */
