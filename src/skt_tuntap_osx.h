#ifndef _SKT_TUNTAP_OSX_H
#define _SKT_TUNTAP_OSX_H

#include "skt_utils.h"

#ifdef WIN32
#define SKT_IFNAMSIZ 64
#else
#define SKT_IFNAMSIZ 16 /* 15 chars * NULL */
#endif

#define SKT_MAC_SIZE 6

typedef struct {
    int fd;
    int if_idx;
    uint8_t mac_addr[SKT_MAC_SIZE];
    uint32_t ip_addr;
    uint32_t device_mask;
    uint16_t mtu;
    char dev_name[SKT_IFNAMSIZ];
} skt_tuntap_dev_t;

#endif  // SKT_TUNTAP_OSX_H