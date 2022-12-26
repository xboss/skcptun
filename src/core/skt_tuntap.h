#ifndef _SKT_TUNTAP_H
#define _SKT_TUNTAP_H

// #include "skt_utils.h"

int skt_tuntap_open();
void skt_tuntap_setup(int dev_name_id, char *device_ip);
int skt_tuntap_read(int fd, char *buf, int len);
int skt_tuntap_write(int fd, char *buf, int len);

#endif  // SKT_TUNTAP_H
