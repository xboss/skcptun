#ifndef _SKT_TCP_SERVER_H
#define _SKT_TCP_SERVER_H

#include <arpa/inet.h>
#include <ev.h>
#include <stdint.h>

#include "3rd/uthash/uthash.h"
#include "skt_tcp.h"

typedef struct skt_tcp_serv_s skt_tcp_serv_t;
typedef struct skt_tcp_serv_conn_s skt_tcp_serv_conn_t;
typedef struct skt_tcp_serv_conf_s skt_tcp_serv_conf_t;

struct skt_tcp_serv_conf_s {
    char *serv_addr;
    uint16_t serv_port;
    int backlog;
    size_t tcp_r_buf_size;
    int r_keepalive;    // 单位：秒
    int w_keepalive;    // 单位：秒
    long recv_timeout;  // 单位：秒
    long send_timeout;  // 单位：秒

    int (*recv_cb)(skt_tcp_serv_conn_t *conn, char *buf, int len);
    void (*timeout_cb)(skt_tcp_serv_conn_t *conn);
    void (*accept_conn_cb)(skt_tcp_serv_conn_t *conn);
    void (*close_conn_cb)(skt_tcp_serv_conn_t *conn);
};

struct skt_tcp_serv_conn_s {
    int fd;              // key
    uint64_t last_r_tm;  // 最后一次读操作的时间戳
    uint64_t last_w_tm;  // 最后一次写操作的时间戳
    struct ev_io *r_watcher;
    ev_timer *timeout_watcher;
    skt_tcp_serv_t *serv;
    SKT_TCP_CONN_ST status;
    uint32_t sess_id;

    UT_hash_handle hh;
};

struct skt_tcp_serv_s {
    skt_tcp_serv_conn_t *conn_ht;
    int listenfd;
    struct ev_loop *loop;
    struct ev_io *accept_watcher;
    skt_tcp_serv_conf_t *conf;
};

skt_tcp_serv_t *skt_tcp_server_init(skt_tcp_serv_conf_t *conf, struct ev_loop *loop);
void skt_tcp_server_free(skt_tcp_serv_t *serv);
ssize_t skt_tcp_server_send(skt_tcp_serv_t *serv, int fd, char *buf, int len);
skt_tcp_serv_conn_t *skt_tcp_server_get_conn(skt_tcp_serv_t *serv, int fd);
void skt_tcp_server_close_conn(skt_tcp_serv_t *serv, int fd);

#endif
