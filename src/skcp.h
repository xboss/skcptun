#ifndef _SKCP_H
#define _SKCP_H

#include "3rd/kcp/ikcp.h"
#include "3rd/uthash/uthash.h"

typedef enum {
    SKCP_CONN_ST_ON = 1,
    SKCP_CONN_ST_READY,
    SKCP_CONN_ST_OFF,
    SKCP_CONN_ST_CAN_OFF,
} SKCP_CONN_ST;

typedef enum {
    SKCP_MODE_SERV = 1,
    SKCP_MODE_CLI,
} SKCP_MODE;

typedef struct skcp_s skcp_t;
typedef struct skcp_conn_s skcp_conn_t;
typedef struct waiting_buf_s waiting_buf_t;

struct skcp_conf_s {
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
    int (*output)(const char *buf, int len, skcp_conn_t *conn);
};
typedef struct skcp_conf_s skcp_conf_t;

struct skcp_conn_s {
    char *htkey;
    skcp_t *skcp;
    void *user_data;
    IUINT32 sess_id;
    IUINT64 last_r_tm;  // 最后一次读操作的时间戳
    IUINT64 last_w_tm;  // 最后一次写操作的时间戳
    IUINT64 estab_tm;
    ikcpcb *kcp;
    SKCP_CONN_ST status;
    waiting_buf_t *waiting_buf_q;  // 待发送消息的队列头
    UT_hash_handle hh;
};

struct skcp_s {
    skcp_conf_t *conf;
    skcp_conn_t *conn_ht;
    IUINT32 cur_sess_id;
    SKCP_MODE mode;
    // void *user_data;
};
typedef struct skcp_s skcp_t;

skcp_t *skcp_init(skcp_conf_t *conf, SKCP_MODE mode);
void skcp_free(skcp_t *skcp);
IUINT32 skcp_gen_sess_id(skcp_t *skcp);
skcp_conn_t *skcp_create_conn(skcp_t *skcp, char *htkey, IUINT32 sess_id, IUINT64 now, void *user_data);
void skcp_close_conn(skcp_conn_t *conn);
skcp_conn_t *skcp_get_conn(skcp_t *skcp, char *htkey);
int skcp_send(skcp_conn_t *conn, const char *buffer, int len);
int skcp_send_ping(skcp_conn_t *conn, IUINT64 now);
int skcp_send_pong(skcp_conn_t *conn, IUINT64 tm, IUINT64 now);
void skcp_update_all(skcp_t *skcp, IUINT32 current);
void skcp_update(skcp_conn_t *conn, IUINT32 current);
int skcp_input(skcp_conn_t *conn, const char *data, long size);
IUINT32 skcp_get_sess_id(const void *data);
/**
 * 检查超时
 *
 * @param conn
 * @param now
 * @return int
 * 0 表示没有超时
 * -1 表示estab timeout
 * -2 表示关闭可关闭的连接
 * -3 表示keepalive超时
 */
int skcp_check_timeout(skcp_conn_t *conn, IUINT64 now);
/**
 * 接收数据
 *
 * @param conn
 * @param buffer
 * @param len
 * @return int
 * >=0 表示成功，返回发送字节数
 * -1 表示错误
 * -2 表示创建连接
 * -3 表示收到connect ack 命令
 * -4 表示收到close 命令
 * -6 表示收到PONG命令
 * -5 表示收到PING命令
 */
int skcp_recv(skcp_conn_t *conn, char *buffer, int len);

#endif