#ifndef _SKT_H
#define _SKT_H

#include <arpa/inet.h>
#include <net/if.h>

#include "crypto.h"
#include "sslog.h"

// #if !defined(INET_ADDRSTRLEN)
// #define INET_ADDRSTRLEN 16
// #endif  // INET_ADDRSTRLEN

#define _OK 0
#define _ERR -1

#define SKT_MODE_LOCAL 0
#define SKT_MODE_REMOTE 1
#define SKT_TICKET_SIZE (32)

typedef struct {
    char ctrl_server_ip[INET_ADDRSTRLEN];
    unsigned short ctrl_server_port;
    char udp_local_ip[INET_ADDRSTRLEN];
    unsigned short udp_local_port;
    char udp_remote_ip[INET_ADDRSTRLEN];
    unsigned short udp_remote_port;
    unsigned char key[AES_128_KEY_SIZE + 1];
    unsigned char iv[AES_BLOCK_SIZE + 1];
    char ticket[SKT_TICKET_SIZE + 1];
    int mode;
    // int send_timeout;  // 发送超时时间（毫秒）
    // int recv_timeout;  // 接收超时时间（毫秒）
    int read_buf_size;
    char* log_file;
    int log_level;

    // tun config
    char tun_dev[IFNAMSIZ + 1];
    char tun_ip[INET_ADDRSTRLEN + 1];
    char tun_netmask[INET_ADDRSTRLEN + 1];

    // kcp config
    int mtu;
    int interval;
    int nodelay;
    int resend;
    int nc;
    int sndwnd;
    int rcvwnd;
} skt_config_t;

#endif /* _SKT_H */