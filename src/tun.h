#ifndef TUN_H
#define TUN_H

#include <sys/types.h>

int tun_alloc(char *dev, size_t dev_len);
ssize_t tun_read(int fd, void *buf, size_t len);
ssize_t tun_write(int fd, const void *buf, size_t len);
int tun_set_ip(const char *dev, const char *ip);
int tun_set_netmask(const char *dev, const char *netmask);
int tun_set_mtu(const char *dev, int mtu);
int tun_up(const char *dev);

#endif // TUN_H
