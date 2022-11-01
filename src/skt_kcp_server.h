#ifndef _SKT_KCP_SERVER_H
#define _SKT_KCP_SERVER_H

#include "skt_kcp.h"

struct skt_kcp_serv_conf_s {
    char *addr;
    uint16_t port;
    char *key;

    SKT_KCP_CONF_FIELD

    int r_buf_size;
    int kcp_buf_size;
    int estab_timeout;     // 单位：秒
    int r_keepalive;       // 单位：秒
    int w_keepalive;       // 单位：秒
    int timeout_interval;  // 单位：秒
};
typedef struct skt_kcp_serv_conf_s skt_kcp_serv_conf_t;

struct skt_kcp_serv_s {
    int fd;
    struct sockaddr_in servaddr;
    skt_kcp_serv_conf_t *conf;
    skt_kcp_conn_t *conn_ht;

    struct ev_loop *loop;
    struct ev_io *r_watcher;
    struct ev_timer *kcp_update_watcher;
    struct ev_timer *timeout_watcher;

    void *data;

    void (*conn_timeout_cb)(skt_kcp_conn_t *kcp_conn);
    void (*new_conn_cb)(skt_kcp_conn_t *kcp_conn);
    int (*kcp_recv_cb)(skt_kcp_conn_t *kcp_conn, char *buf, int len);
    char *(*encrypt_cb)(const char *in, int in_len, int *out_len);
    char *(*decrypt_cb)(const char *in, int in_len, int *out_len);
};

skt_kcp_serv_t *skt_kcp_server_init(skt_kcp_serv_conf_t *conf, struct ev_loop *loop, void *data);
void skt_kcp_server_free(skt_kcp_serv_t *serv);
void skt_kcp_server_close_conn(skt_kcp_serv_t *serv, uint32_t sess_id, struct sockaddr_in *kcp_cli_addr);
int skt_kcp_server_send(skt_kcp_serv_t *serv, uint32_t sess_id, char *buf, int len, struct sockaddr_in *kcp_cli_addr);
skt_kcp_conn_t *skt_kcp_server_get_conn(skt_kcp_serv_t *serv, uint32_t sess_id, struct sockaddr_in *kcp_cli_addr);

#endif