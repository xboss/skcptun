#ifndef _SKCP_H
#define _SKCP_H

#include <arpa/inet.h>
#include <ev.h>

#include "ikcp.h"

#define SKCP_MAX_CONNS 1024
#define SKCP_IV_LEN 32
#define SKCP_KEY_LEN 32
#define SKCP_TICKET_LEN 32

typedef enum {
    SKCP_CONN_ST_ON = 1,
    SKCP_CONN_ST_OFF,
    // SKCP_CONN_ST_READY,
    // SKCP_CONN_ST_CAN_OFF,
} SKCP_CONN_ST;

typedef enum {
    SKCP_MODE_SERV = 1,
    SKCP_MODE_CLI,
} SKCP_MODE;

// typedef enum {
//     SKCP_MSG_TYPE_DATA = 1,
//     SKCP_MSG_TYPE_CID_ACK,
// } SKCP_MSG_TYPE;

typedef struct skcp_s skcp_t;
typedef struct {
    skcp_t *skcp;
    void *user_data;
    uint32_t id;
    uint64_t last_r_tm;  // 最后一次读操作的时间戳
    uint64_t last_w_tm;  // 最后一次写操作的时间戳
    uint64_t estab_tm;
    ikcpcb *kcp;
    SKCP_CONN_ST status;
    struct sockaddr_in dest_addr;
    char ticket[SKCP_TICKET_LEN + 1];
    char iv[SKCP_IV_LEN + 1];
    struct ev_timer *kcp_update_watcher;
    struct ev_timer *timeout_watcher;
} skcp_conn_t;

typedef struct {
    int mtu;
    int interval;
    int nodelay;
    int resend;
    int nc;
    int sndwnd;
    int rcvwnd;

    int estab_timeout;  // 单位：秒
    int r_keepalive;    // 单位：秒
    int w_keepalive;    // 单位：秒

    char *addr;
    uint16_t port;
    int r_buf_size;
    int kcp_buf_size;
    int timeout_interval;  // 单位：秒
    uint32_t max_conn_cnt;
    char key[SKCP_KEY_LEN + 1];
    char ticket[SKCP_TICKET_LEN + 1];

    void (*on_accept)(uint32_t cid);
    // void (*on_recv)(uint32_t cid, char *buf, int len, SKCP_MSG_TYPE msg_type);
    void (*on_recv_cid)(uint32_t cid);
    void (*on_recv_data)(uint32_t cid, char *buf, int len);
    void (*on_close)(uint32_t cid);
    int (*on_check_ticket)(char *ticket, int len);
} skcp_conf_t;

#define SKCP_DEF_CONF(vconf)                     \
    do {                                         \
        memset((vconf), 0, sizeof(skcp_conf_t)); \
        (vconf)->interval = 10;                  \
        (vconf)->mtu = 1400;                     \
        (vconf)->rcvwnd = 128;                   \
        (vconf)->sndwnd = 128;                   \
        (vconf)->nodelay = 1;                    \
        (vconf)->resend = 2;                     \
        (vconf)->nc = 1;                         \
        (vconf)->r_keepalive = 600;              \
        (vconf)->w_keepalive = 600;              \
        (vconf)->estab_timeout = 100;            \
        (vconf)->addr = NULL;                    \
        (vconf)->port = 1111;                    \
        (vconf)->r_buf_size = 1500;              \
        (vconf)->kcp_buf_size = 2048;            \
        (vconf)->timeout_interval = 1;           \
        (vconf)->max_conn_cnt = SKCP_MAX_CONNS;  \
    } while (0)

typedef struct {
    skcp_conn_t **conns;  // array: id->skcp_conn_t
    uint32_t max_cnt;
    uint32_t remain_cnt;
    uint32_t *remain_id_stack;  // array: remain conn_id stack
    uint32_t remain_idx;
} skcp_conn_slots_t;

struct skcp_s {
    skcp_conf_t *conf;
    skcp_conn_slots_t *conn_slots;
    SKCP_MODE mode;
    int fd;
    struct sockaddr_in servaddr;
    struct ev_loop *loop;
    struct ev_io *r_watcher;
    struct ev_io *w_watcher;
    void *user_data;
};

skcp_t *skcp_init(skcp_conf_t *conf, struct ev_loop *loop, void *user_data, SKCP_MODE mode);
void skcp_free(skcp_t *skcp);
int skcp_req_cid(skcp_t *skcp, const char *ticket, int len);
int skcp_send(skcp_t *skcp, uint32_t cid, const char *buf, int len);
void skcp_close_conn(skcp_t *skcp, uint32_t cid);
skcp_conn_t *skcp_get_conn(skcp_t *skcp, uint32_t cid);

#endif