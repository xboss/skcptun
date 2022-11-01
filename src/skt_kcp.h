#ifndef _SKT_KCP_H
#define _SKT_KCP_H

#include <arpa/inet.h>
#include <ev.h>

#include "3rd/kcp/ikcp.h"
#include "3rd/uthash/uthash.h"
#include "skt_utils.h"

#define SKT_KCP_CMD_CONN 0x01
#define SKT_KCP_CMD_CONN_ACK 0x02
#define SKT_KCP_CMD_CLOSE 0x03
// #define SKT_KCP_CMD_CLOSE_ACK 0x04
#define SKT_KCP_CMD_DATA 0x05
#define SKT_KCP_CMD_PING 0x06
// #define SKT_KCP_CMD_PONG 0x07

#define SKT_KCP_CONF_FIELD \
    int mtu;               \
    int interval;          \
    int nodelay;           \
    int resend;            \
    int nc;                \
    int sndwnd;            \
    int rcvwnd;

typedef enum {
    SKT_KCP_CONN_ST_ON = 1,
    SKT_KCP_CONN_ST_READY,
    SKT_KCP_CONN_ST_OFF,
    SKT_KCP_CONN_ST_CAN_OFF,
} SKT_KCP_CONN_ST;

typedef struct skt_kcp_cli_s skt_kcp_cli_t;
typedef struct skt_kcp_serv_s skt_kcp_serv_t;

struct skt_kcp_conn_s {
    char *htkey;
    uint32_t sess_id;
    uint64_t estab_tm;
    uint64_t last_r_tm;  // 最后一次读操作的时间戳
    uint64_t last_w_tm;  // 最后一次写操作的时间戳
    struct sockaddr_in cliaddr;
    ikcpcb *kcp;
    skt_kcp_cli_t *cli;
    skt_kcp_serv_t *serv;
    int tcp_fd;
    SKT_KCP_CONN_ST status;
    waiting_buf_t *waiting_buf_q;  // 待发送消息的队列头
    UT_hash_handle hh;
};
typedef struct skt_kcp_conn_s skt_kcp_conn_t;

int skt_kcp_recv(skt_kcp_conn_t *conn, char *buf, int len);

#endif