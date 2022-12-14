#ifndef _SKT_KCP_H
#define _SKT_KCP_H

#include <arpa/inet.h>
#include <ev.h>

#include "skcp.h"
#include "skt_utils.h"

#define SKT_KCP_TAG_NM 0
#define SKT_KCP_TAG_HT 1

typedef struct skt_kcp_conn_s skt_kcp_conn_t;
typedef struct skt_kcp_s skt_kcp_t;

struct skt_kcp_conf_s {
    skcp_conf_t *skcp_conf;
    char *addr;
    uint16_t port;
    char *key;
    int r_buf_size;
    int kcp_buf_size;
    int timeout_interval;  // 单位：秒
};
typedef struct skt_kcp_conf_s skt_kcp_conf_t;

struct skt_kcp_s {
    int fd;
    struct sockaddr_in servaddr;
    skt_kcp_conf_t *conf;
    skcp_t *skcp;
    SKCP_MODE mode;

    struct ev_loop *loop;
    struct ev_io *r_watcher;
    struct ev_io *w_watcher;
    struct ev_timer *kcp_update_watcher;
    struct ev_timer *timeout_watcher;

    void *data;

    // char iv[33];
    // char iv_tmp[33];

    void (*new_conn_cb)(skcp_conn_t *kcp_conn);
    void (*conn_close_cb)(skt_kcp_conn_t *kcp_conn);
    int (*kcp_recv_data_cb)(skcp_conn_t *kcp_conn, char *buf, int len);
    int (*kcp_recv_ctrl_cb)(skcp_conn_t *kcp_conn, char *buf, int len);
    char *(*encrypt_cb)(skt_kcp_t *skt_kcp, const char *in, int in_len, int *out_len);
    char *(*decrypt_cb)(skt_kcp_t *skt_kcp, const char *in, int in_len, int *out_len);
};

struct skt_kcp_conn_s {
    struct sockaddr_in dest_addr;
    skt_kcp_t *skt_kcp;
    // char iv[33];
    int tcp_fd;
    int tag;
};

#define SKT_GET_KCP_CONN(vskcp_conn) ((skt_kcp_conn_t *)((vskcp_conn)->user_data))

skt_kcp_t *skt_kcp_init(skt_kcp_conf_t *conf, struct ev_loop *loop, void *data, SKCP_MODE mode);
void skt_kcp_free(skt_kcp_t *skt_kcp);
void skt_kcp_gen_htkey(char *htkey, int key_len, uint32_t sess_id, struct sockaddr_in *sock_addr);
skcp_conn_t *skt_kcp_new_conn(skt_kcp_t *skt_kcp, uint32_t sess_id, struct sockaddr_in *sock_addr);
void skt_kcp_close_conn(skt_kcp_t *skt_kcp, char *htkey);
int skt_kcp_send_data(skt_kcp_t *skt_kcp, char *htkey, const char *buf, int len);
int skt_kcp_send_ctrl(skt_kcp_t *skt_kcp, char *htkey, const char *buf, int len);
skcp_conn_t *skt_kcp_get_conn(skt_kcp_t *skt_kcp, char *htkey);

#endif