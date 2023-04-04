#ifndef _EASY_TCP_H
#define _EASY_TCP_H

#include <arpa/inet.h>
#include <ev.h>

#include "uthash.h"

/* -------------------------------------------------------------------------- */
/*                               EasyTCP Common                               */
/* -------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------- */
/*                               EasyTCP Server                               */
/* -------------------------------------------------------------------------- */

typedef struct etcp_serv_s etcp_serv_t;

typedef struct etcp_serv_conf_s {
    char *serv_addr;
    uint16_t serv_port;
    int backlog;
    size_t r_buf_size;
    int r_keepalive;       // 单位：秒
    int w_keepalive;       // 单位：秒
    long recv_timeout;     // 单位：秒
    long send_timeout;     // 单位：秒
    int timeout_interval;  // 单位：秒

    int (*on_accept)(int fd);
    void (*on_recv)(int fd, char *buf, int len);
    void (*on_close)(int fd);
} etcp_serv_conf_t;

typedef struct {
    int fd;
    etcp_serv_t *serv;
    void *user_data;
    uint64_t last_r_tm;  // 最后一次读操作的时间戳
    uint64_t last_w_tm;  // 最后一次写操作的时间戳
    struct ev_io *r_watcher;
    struct ev_timer *timeout_watcher;
    UT_hash_handle hh;
} etcp_serv_conn_t;

struct etcp_serv_s {
    etcp_serv_conf_t *conf;
    int serv_fd;
    struct sockaddr_in servaddr;
    etcp_serv_conn_t *conn_ht;
    struct ev_loop *loop;
    struct ev_io *accept_watcher;
    // struct ev_io *r_watcher;
    // struct ev_io *w_watcher;
    void *user_data;
};

#define ETCP_SERV_DEF_CONF(vconf)                     \
    do {                                              \
        memset((vconf), 0, sizeof(etcp_serv_conf_t)); \
        (vconf)->serv_addr = NULL;                    \
        (vconf)->serv_port = 8888;                    \
        (vconf)->backlog = 1024;                      \
        (vconf)->r_buf_size = 1024;                   \
        (vconf)->recv_timeout = 5;                    \
        (vconf)->send_timeout = 5;                    \
        (vconf)->timeout_interval = 1;                \
        (vconf)->r_keepalive = 60;                    \
        (vconf)->w_keepalive = 60;                    \
    } while (0)

etcp_serv_t *etcp_init_server(etcp_serv_conf_t *conf, struct ev_loop *loop, void *user_data);
void etcp_free_server(etcp_serv_t *serv);
int etcp_server_send(etcp_serv_t *serv, int fd, char *buf, size_t len);
void etcp_server_close_conn(etcp_serv_t *serv, int fd, int silent);
etcp_serv_conn_t *etcp_server_get_conn(etcp_serv_t *serv, int fd);

/* -------------------------------------------------------------------------- */
/*                               EasyTCP Client                               */
/* -------------------------------------------------------------------------- */

typedef struct etcp_send_buf_s etcp_send_buf_t;
typedef struct etcp_cli_s etcp_cli_t;

typedef struct etcp_cli_conf_s {
    size_t r_buf_size;
    int r_keepalive;    // 单位：秒
    int w_keepalive;    // 单位：秒
    long recv_timeout;  // 单位：秒
    long send_timeout;  // 单位：秒
    // int timeout_interval;  // 单位：秒

    void (*on_recv)(int fd, char *buf, int len);
    void (*on_close)(int fd);
} etcp_cli_conf_t;

typedef struct {
    int fd;
    struct sockaddr_in addr;
    etcp_cli_t *cli;
    // uint16_t port;
    uint64_t last_r_tm;  // 最后一次读操作的时间戳
    uint64_t last_w_tm;  // 最后一次写操作的时间戳
    void *user_data;

    etcp_send_buf_t *send_buf;
    struct ev_io *r_watcher;
    struct ev_io *w_watcher;
    // struct ev_timer *timeout_watcher;
    UT_hash_handle hh;
} etcp_cli_conn_t;

struct etcp_cli_s {
    etcp_cli_conf_t *conf;
    etcp_cli_conn_t *conn_ht;
    struct ev_loop *loop;
    void *user_data;
};

#define ETCP_CLI_DEF_CONF(vconf)                     \
    do {                                             \
        memset((vconf), 0, sizeof(etcp_cli_conf_t)); \
        (vconf)->r_buf_size = 1024;                  \
        (vconf)->recv_timeout = 5;                   \
        (vconf)->send_timeout = 5;                   \
        (vconf)->r_keepalive = 60;                   \
        (vconf)->w_keepalive = 60;                   \
    } while (0)

etcp_cli_t *etcp_init_client(etcp_cli_conf_t *conf, struct ev_loop *loop, void *user_data);
void etcp_free_client(etcp_cli_t *cli);
int etcp_client_send(etcp_cli_t *cli, int fd, char *buf, size_t len);
int etcp_client_create_conn(etcp_cli_t *cli, char *addr, uint16_t port, void *user_data);
void etcp_client_close_conn(etcp_cli_t *cli, int fd, int silent);
etcp_cli_conn_t *etcp_client_get_conn(etcp_cli_t *cli, int fd);

#endif  // EASY_TCP_H