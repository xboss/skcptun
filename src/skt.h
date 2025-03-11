#ifndef _SKT_H
#define _SKT_H

#include <arpa/inet.h>
#include <assert.h>
#include <ev.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "crypto.h"
#include "ikcp.h"
#include "sslog.h"
#include "uthash.h"

// #if !defined(INET_ADDRSTRLEN)
// #define INET_ADDRSTRLEN 16
// #endif  // INET_ADDRSTRLEN

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

#define _OK 0
#define _ERR -1

#define SKT_MODE_LOCAL 0
#define SKT_MODE_REMOTE 1
#define SKT_TICKET_SIZE (32)
#define SKT_MTU (1500)

#define SKT_KCP_HEADER_SZIE (24)
#define SKT_PKT_CMD_SZIE (1)
#define SKT_PKT_CMD_DATA (0x01u)
#define SKT_PKT_CMD_AUTH_REQ (0x02u)
#define SKT_PKT_CMD_AUTH_RESP (0x03u)
// #define SKT_PKT_CMD_CLOSE (0x04u)
#define SKT_PKT_CMD_PING (0x05u)
#define SKT_PKT_CMD_PONG (0x06u)

typedef struct {
    char ctrl_server_ip[INET_ADDRSTRLEN + 1];
    unsigned short ctrl_server_port;
    char udp_local_ip[INET_ADDRSTRLEN + 1];
    unsigned short udp_local_port;
    char udp_remote_ip[INET_ADDRSTRLEN + 1];
    unsigned short udp_remote_port;
    unsigned char key[AES_128_KEY_SIZE + 1];
    unsigned char iv[AES_BLOCK_SIZE + 1];
    char ticket[SKT_TICKET_SIZE + 1]; /* TODO: multi ticket */
    int mode;
    int timeout;  // ms
    // int send_timeout;  // 发送超时时间（毫秒）
    // int recv_timeout;  // 接收超时时间（毫秒）
    char* log_file;
    int log_level;

    // tun config
    char tun_dev[IFNAMSIZ + 1];
    char tun_ip[INET_ADDRSTRLEN + 1];
    // uint32_t tun_ip;
    char tun_netmask[INET_ADDRSTRLEN + 1];
    // uint32_t tun_netmask;
    int tun_mtu;

    // kcp config
    int kcp_mtu;
    int interval;
    int nodelay;
    int resend;
    int nc;
    int sndwnd;
    int rcvwnd;
} skt_config_t;

typedef struct {
    struct ev_loop* loop;
    skt_config_t* conf;
    int udp_fd;
    int tun_fd;
    uint32_t local_cid;
    int running;

    ev_timer* timeout_watcher;
    ev_timer* kcp_update_watcher;
    ev_io* tun_io_watcher;
    ev_io* udp_io_watcher;
} skcptun_t;

////////////////////////////////
// tools
////////////////////////////////

inline uint64_t skt_mstime() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t millisecond = (tv.tv_sec * 1000000l + tv.tv_usec) / 1000l;
    return millisecond;
}
#define SKT_MSTIME32 ((uint32_t)(skt_mstime() & 0xfffffffful))

inline void skt_print_hex(const char* label, const unsigned char* data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

#endif /* _SKT_H */