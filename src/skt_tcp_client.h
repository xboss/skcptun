#ifndef _SKT_TCP_CLIENT_H
#define _SKT_TCP_CLIENT_H

#include <arpa/inet.h>
#include <ev.h>

#include "3rd/uthash/uthash.h"
#include "skt_tcp.h"

typedef struct skt_tcp_cli_conn_s skt_tcp_cli_conn_t;
typedef struct skt_tcp_cli_s skt_tcp_cli_t;
typedef struct skt_tcp_cli_conf_s skt_tcp_cli_conf_t;

struct skt_tcp_cli_conf_s {
    int r_keepalive;  // 单位：秒
    int w_keepalive;  // 单位：秒
    long recv_timeout;
    long send_timeout;
    uint r_buf_size;

    int (*recv_cb)(skt_tcp_cli_conn_t *conn, char *buf, int len);
    void (*close_cb)(skt_tcp_cli_conn_t *conn);
};

struct skt_tcp_cli_conn_s {
    int fd;  // key
    char *addr;
    uint16_t port;
    uint64_t last_r_tm;    // 最后一次读操作的时间戳
    uint64_t last_w_tm;    // 最后一次写操作的时间戳
    uint32_t r_keepalive;  // 单位：秒
    uint32_t w_keepalive;  // 单位：秒
    uint r_buf_size;
    SKT_TCP_CONN_ST status;
    skt_tcp_cli_t *tcp_cli;
    uint32_t sess_id;
    struct sockaddr_in kcp_cli_addr;
    waiting_buf_t *waiting_buf_q;  // 待发送消息的队列头
    struct ev_io *r_watcher;
    struct ev_io *w_watcher;
    UT_hash_handle hh;
};

struct skt_tcp_cli_s {
    skt_tcp_cli_conn_t *conn_ht;
    struct ev_loop *loop;
    skt_tcp_cli_conf_t *conf;
};

skt_tcp_cli_t *skt_tcp_client_init(skt_tcp_cli_conf_t *conf, struct ev_loop *loop);
skt_tcp_cli_conn_t *skt_tcp_client_create_conn(skt_tcp_cli_t *cli, char *addr, uint16_t port);
ssize_t skt_tcp_client_send(skt_tcp_cli_t *cli, int fd, char *buf, int len);
skt_tcp_cli_conn_t *skt_tcp_client_get_conn(skt_tcp_cli_t *cli, int fd);
void skt_tcp_client_close_conn(skt_tcp_cli_t *cli, int fd);
void skt_tcp_client_free(skt_tcp_cli_t *cli);

#endif