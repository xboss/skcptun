#ifndef _SKCPTUN_H
#define _SKCPTUN_H

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "crypto.h"
#include "ikcp.h"
// #include "packet_queue.h"
#include "sslog.h"
#include "tun.h"
#include "uthash.h"

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

#define _OK 0
#define _ERR -1

#define SKT_MODE_LOCAL 0
#define SKT_MODE_REMOTE 1
#define SKT_TICKET_SIZE (32)
#define SKT_MTU (1500)
#define SKT_KEEPALIVE (1000 * 60)

#define SKT_KCP_HEADER_SZIE (24)
#define SKT_PKT_CMD_SZIE (1)
#define SKT_PKT_CMD_DATA (0x01u)
// #define SKT_PKT_CMD_AUTH_REQ (0x02u)
// #define SKT_PKT_CMD_AUTH_RESP (0x03u)
// #define SKT_PKT_CMD_CLOSE (0x04u)
#define SKT_PKT_CMD_PING (0x05u)
#define SKT_PKT_CMD_PONG (0x06u)

#define SKT_ASSIGN_KCP_MTU(_mtu) (_mtu - SKT_PKT_CMD_SZIE - SKT_TICKET_SIZE);
#define SKT_ASSIGN_TUN_MTU(_mtu) (_mtu - SKT_PKT_CMD_SZIE - SKT_TICKET_SIZE - SKT_KCP_HEADER_SZIE);

typedef struct {
    char udp_local_ip[INET_ADDRSTRLEN + 1];
    unsigned short udp_local_port;
    char udp_remote_ip[INET_ADDRSTRLEN + 1];
    unsigned short udp_remote_port;
    unsigned char key[AES_128_KEY_SIZE + 1];
    unsigned char iv[AES_BLOCK_SIZE + 1];
    char ticket[SKT_TICKET_SIZE + 1]; /* TODO: multi ticket */
    int mode;
    char log_file[256];
    int log_level;

    // tun config
    char tun_dev[IFNAMSIZ + 1];
    char tun_ip[INET_ADDRSTRLEN + 1];
    char tun_mask[INET_ADDRSTRLEN + 1];
    int tun_mtu;

    int mtu;
    int keepalive;      // ms
    int ping_interval;  // ms

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

typedef struct skcptun_s skcptun_t;

typedef struct {
    char cmd;
    char* ticket;
    char* payload;
    int payload_len;
} skt_packet_t;

typedef struct {
    uint32_t addr;
    int fd;
    struct sockaddr_in remote_addr;
    struct sockaddr_in local_addr;
    uint32_t cid;
    uint64_t last_r_tm;  // 最后一次读操作的时间戳
    uint64_t last_w_tm;  // 最后一次写操作的时间戳
    skcptun_t* skt;
    UT_hash_handle hh_addr;
} skt_udp_peer_t;

typedef struct {
    uint32_t cid;     // primary key
    uint32_t tun_ip;  // key

    ikcpcb* kcp;
    skt_udp_peer_t* peer;
    skcptun_t* skt;

    uint64_t create_time;
    uint64_t last_r_tm;  // 最后一次读操作的时间戳
    uint64_t last_w_tm;  // 最后一次写操作的时间戳
    UT_hash_handle hh_cid;
    UT_hash_handle hh_tun_ip;
} skt_kcp_conn_t;

struct skcptun_s {
    skt_config_t* conf;
    int udp_fd;
    int tun_fd;
    uint32_t tun_ip_addr;
    uint32_t local_cid;
    struct sockaddr_in remote_addr;
    int running;
    uint64_t last_cllect_tm;
    uint64_t last_ping_tm;
    int (*on_cmd_ping)(skcptun_t* skt, skt_packet_t* pkt, skt_udp_peer_t* peer);
    int (*on_cmd_pong)(skcptun_t* skt, skt_packet_t* pkt, skt_udp_peer_t* peer);
    // int (*on_cmd_auth_req)(skcptun_t* skt, skt_packet_t* pkt, skt_udp_peer_t* peer);
    // int (*on_cmd_auth_resp)(skcptun_t* skt, skt_packet_t* pkt, skt_udp_peer_t* peer);
    void (*on_timeout)(skcptun_t* skt);
};

////////////////////////////////
// skcptun API
////////////////////////////////

skcptun_t* skt_init(skt_config_t* conf);
void skt_free(skcptun_t* skt);
int skt_init_tun(skcptun_t* skt);
int skt_setup_tun(skcptun_t* skt);
void skt_update_kcp_cb(skt_kcp_conn_t* kcp_conn);
void skt_setup_kcp(skcptun_t* skt);
void skt_close_kcp_conn(skt_kcp_conn_t* kcp_conn);
void skt_monitor(skcptun_t* skt);
skt_udp_peer_t* skt_udp_start(const char* local_ip, uint16_t local_port, const char* remote_ip, uint16_t remote_port,
                              skcptun_t* skt);
int skt_run(skcptun_t* skt);

////////////////////////////////
// skcptun udp peer API
////////////////////////////////

skt_udp_peer_t* skt_udp_peer_get(uint32_t remote_addr);
int skt_udp_peer_add(int fd, struct sockaddr_in remote_addr, skcptun_t* skt);
void skt_udp_peer_del(uint32_t remote_addr);
void skt_udp_peer_info();
void skt_udp_peer_iter(void (*iter)(skt_udp_peer_t* peer));
void skt_udp_peer_cleanup();
int skt_pack(skcptun_t* skt, char cmd, const char* ticket, const char* payload, size_t payload_len, char* raw,
             size_t* raw_len);
int skt_unpack(skcptun_t* skt, const char* raw, size_t raw_len, char* cmd, char* ticket, char* payload,
               size_t* payload_len);

////////////////////////////////
// skcptun kcp connection API
////////////////////////////////

uint32_t skt_kcp_conn_gen_cid();
skt_kcp_conn_t* skt_kcp_conn_add(uint32_t cid, uint32_t tun_ip, const char* ticket, skt_udp_peer_t* peer,
                                 skcptun_t* skt);
skt_kcp_conn_t* skt_kcp_conn_get_by_cid(uint32_t cid);
skt_kcp_conn_t* skt_kcp_conn_get_by_tun_ip(uint32_t tun_ip);
void skt_kcp_conn_del(skt_kcp_conn_t* kcp_conn);
void skt_kcp_conn_info();
void skt_kcp_conn_iter(void (*iter)(skt_kcp_conn_t* kcp_conn));
void skt_kcp_conn_cleanup();

////////////////////////////////
// tools
////////////////////////////////

inline int skt_set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        perror("Error getting file flags");
        return _ERR;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("Error setting file to non-blocking mode");
        return _ERR;
    }
    return _OK;
}

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
    _LOG("%s %s:%d", label, remote_ip, remote_port);
}

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define SKT_IS_LITTLE_ENDIAN 1
#else
#define SKT_IS_LITTLE_ENDIAN 0
#endif

inline uint64_t skt_htonll(uint64_t value) {
    if (SKT_IS_LITTLE_ENDIAN) {
        return ((value & 0xFF00000000000000ull) >> 56) | ((value & 0x00FF000000000000ull) >> 40) |
               ((value & 0x0000FF0000000000ull) >> 24) | ((value & 0x000000FF00000000ull) >> 8) |
               ((value & 0x00000000FF000000ull) << 8) | ((value & 0x0000000000FF0000ull) << 24) |
               ((value & 0x000000000000FF00ull) << 40) | ((value & 0x00000000000000FFull) << 56);
    } else {
        return value;
    }
}

inline uint64_t skt_ntohll(uint64_t value) { return skt_htonll(value); }

#endif /* _SKCPTUN_H */