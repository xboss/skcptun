#ifndef _SKT_KCP_CLIENT_H
#define _SKT_KCP_CLIENT_H

#include "skt_kcp.h"

struct skt_kcp_cli_conf_s {
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
typedef struct skt_kcp_cli_conf_s skt_kcp_cli_conf_t;

struct skt_kcp_cli_s {
    int fd;
    struct sockaddr_in servaddr;
    skt_kcp_cli_conf_t *conf;
    skt_kcp_conn_t *conn_ht;
    uint32_t cur_sess_id;

    struct ev_loop *loop;
    struct ev_io *r_watcher;
    struct ev_timer *kcp_update_watcher;
    struct ev_timer *timeout_watcher;

    void *data;

    void (*conn_timeout_cb)(skt_kcp_conn_t *kcp_conn);
    void (*conn_close_cb)(skt_kcp_conn_t *kcp_conn);
    int (*kcp_recv_cb)(skt_kcp_conn_t *kcp_conn, char *buf, int len);
    char *(*encrypt_cb)(const char *in, int in_len, int *out_len);
    char *(*decrypt_cb)(const char *in, int in_len, int *out_len);
};

skt_kcp_cli_t *skt_kcp_client_init(skt_kcp_cli_conf_t *conf, struct ev_loop *loop, void *data);
void skt_kcp_client_free(skt_kcp_cli_t *cli);
skt_kcp_conn_t *skt_kcp_client_new_conn(skt_kcp_cli_t *cli);

void skt_kcp_client_close_conn(skt_kcp_cli_t *cli, uint32_t sess_id);
int skt_kcp_client_send(skt_kcp_cli_t *cli, uint32_t sess_id, char *buf, int len);
skt_kcp_conn_t *skt_kcp_client_get_conn(skt_kcp_cli_t *cli, uint32_t sess_id);

#endif