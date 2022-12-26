#ifndef _SKT_TCP_H
#define _SKT_TCP_H

#include <arpa/inet.h>
#include <ev.h>

// #include "3rd/uthash/uthash.h"
// #include "3rd/uthash/utlist.h"
#include "skt_utils.h"
#include "uthash.h"
#include "utlist.h"

#define TCP_WAITIMG_BUF_SZ 2048

typedef struct skt_tcp_conn_s skt_tcp_conn_t;
typedef struct skt_tcp_s skt_tcp_t;
typedef struct skt_tcp_conf_s skt_tcp_conf_t;
typedef struct waiting_buf_s waiting_buf_t;

typedef enum {
    SKT_TCP_MODE_SERV = 1,
    SKT_TCP_MODE_CLI,
} SKT_TCP_MODE;

typedef enum {
    SKT_TCP_CONN_ST_ON = 1,
    SKT_TCP_CONN_ST_READY,
    SKT_TCP_CONN_ST_OFF,
    SKT_TCP_CONN_ST_CAN_OFF,
} SKT_TCP_CONN_ST;

struct skt_tcp_conf_s {
    char *serv_addr;
    uint16_t serv_port;
    int backlog;
    int r_keepalive;  // 单位：秒
    int w_keepalive;  // 单位：秒
    long recv_timeout;
    long send_timeout;
    uint32_t r_buf_size;
    SKT_TCP_MODE mode;

    void (*recv_cb)(skt_tcp_conn_t *conn, const char *buf, int len);
    void (*timeout_cb)(skt_tcp_conn_t *conn);
    void (*accept_cb)(skt_tcp_conn_t *conn);
    void (*close_cb)(skt_tcp_conn_t *conn);
};

struct skt_tcp_conn_s {
    int fd;  // key

    uint64_t last_r_tm;  // 最后一次读操作的时间戳
    uint64_t last_w_tm;  // 最后一次写操作的时间戳

    uint32_t r_keepalive;  // 单位：秒
    uint32_t w_keepalive;  // 单位：秒

    uint32_t r_buf_size;

    SKT_TCP_CONN_ST status;
    skt_tcp_t *skt_tcp;

    uint32_t sess_id;
    struct sockaddr_in kcp_cli_addr;

    waiting_buf_t *waiting_buf_q;  // 待发送消息的队列头

    struct ev_io *r_watcher;
    struct ev_io *w_watcher;
    ev_timer *timeout_watcher;

    UT_hash_handle hh;
};

struct skt_tcp_s {
    skt_tcp_conn_t *conn_ht;
    int listenfd;
    struct ev_loop *loop;
    struct ev_io *accept_watcher;
    skt_tcp_conf_t *conf;
};

skt_tcp_t *skt_tcp_init(skt_tcp_conf_t *conf, struct ev_loop *loop);
void skt_tcp_free(skt_tcp_t *tcp);
int skt_tcp_send(skt_tcp_conn_t *conn, char *buf, int len);
skt_tcp_conn_t *skt_tcp_get_conn(skt_tcp_t *tcp, int fd);
void skt_tcp_close_conn(skt_tcp_conn_t *conn);
skt_tcp_conn_t *skt_tcp_connect(skt_tcp_t *tcp, char *addr, uint16_t port);

#endif