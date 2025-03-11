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
    char udp_local_ip[INET_ADDRSTRLEN + 1];
    unsigned short udp_local_port;
    char udp_remote_ip[INET_ADDRSTRLEN + 1];
    unsigned short udp_remote_port;
    unsigned char key[AES_128_KEY_SIZE + 1];
    unsigned char iv[AES_BLOCK_SIZE + 1];
    char ticket[SKT_TICKET_SIZE + 1]; /* TODO: multi ticket */
    int mode;
    int timeout;  // ms
    char log_file[256];
    int log_level;

    // tun config
    char tun_dev[IFNAMSIZ + 1];
    char tun_ip[INET_ADDRSTRLEN + 1];
    char tun_mask[INET_ADDRSTRLEN + 1];
    int tun_mtu;

    // kcp config
    int kcp_mtu;
    int kcp_interval;
    int kcp_nodelay;
    int kcp_resend;
    int kcp_nc;
    int kcp_sndwnd;
    int kcp_rcvwnd;
    int speed_mode;
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

inline void skt_print_iaddr(const char* label, struct sockaddr_in addr) {
    char remote_ip[INET_ADDRSTRLEN + 1] = {0};
    unsigned int remote_port = ntohs(addr.sin_port);
    inet_ntop(AF_INET, &addr.sin_addr, remote_ip, sizeof(addr));
    printf("%s %s:%d\n", label, remote_ip, remote_port);
}

// 检查系统是否为大端
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define SKT_IS_LITTLE_ENDIAN 1
#else
#define SKT_IS_LITTLE_ENDIAN 0
#endif

// 将64位整数从主机字节序转换为网络字节序
inline uint64_t skt_htonll(uint64_t value) {
    if (SKT_IS_LITTLE_ENDIAN) {
        return ((value & 0xFF00000000000000ull) >> 56) | ((value & 0x00FF000000000000ull) >> 40) |
               ((value & 0x0000FF0000000000ull) >> 24) | ((value & 0x000000FF00000000ull) >> 8) |
               ((value & 0x00000000FF000000ull) << 8) | ((value & 0x0000000000FF0000ull) << 24) |
               ((value & 0x000000000000FF00ull) << 40) | ((value & 0x00000000000000FFull) << 56);
    } else {
        // 如果已经是大端，则无需转换
        return value;
    }
}

// 将64位整数从网络字节序转换为主机字节序
inline uint64_t skt_ntohll(uint64_t value) {
    // 由于htonll和ntohll实际上是相反的操作，可以复用htonll的逻辑
    return skt_htonll(value);
}

#endif /* _SKT_H */