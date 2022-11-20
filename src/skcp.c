#include "skcp.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "3rd/uthash/utlist.h"

#define SKCP_CMD_CONN 0x01
#define SKCP_CMD_CONN_ACK 0x02
#define SKCP_CMD_CLOSE 0x03
// #define SKCP_CMD_CLOSE_ACK 0x04
#define SKCP_CMD_DATA 0x05
#define SKCP_CMD_PING 0x06
#define SKCP_CMD_PONG 0x07

#define SKCP_FREE(p)  \
    do {              \
        if (p) {      \
            free(p);  \
            p = NULL; \
        }             \
    } while (0);

/************************************************/

int skcp_append_wait_buf(skcp_conn_t *conn, const char *buffer, int len) {
    if (len > KCP_WAITIMG_BUF_SZ) {
        return -1;
    }
    size_t wb_sz = sizeof(waiting_buf_t);
    waiting_buf_t *msg = (waiting_buf_t *)malloc(wb_sz);
    memset(msg, 0, wb_sz);
    memcpy(msg->buf, buffer, len);
    msg->len = len;
    DL_APPEND(conn->waiting_buf_q, msg);
    return len;
}

skcp_conn_t *skcp_get_conn(skcp_t *skcp, char *htkey) {
    skcp_conn_t *conn = NULL;
    if (skcp->conn_ht) {
        HASH_FIND_STR(skcp->conn_ht, htkey, conn);
    }
    return conn;
}

static int add_conn(skcp_conn_t *conn) {
    if (NULL == conn) {
        return -1;
    }

    if (NULL == skcp_get_conn(conn->skcp, conn->htkey)) {
        // TODO: strlen(conn->htkey)有隐患
        int len = strlen(conn->htkey);
        len = len > SKCP_HTKEY_LEN ? SKCP_HTKEY_LEN : len;
        HASH_ADD_KEYPTR(hh, conn->skcp->conn_ht, conn->htkey, len, conn);
    }

    return 0;
}

static int del_conn(skcp_conn_t *conn) {
    if (NULL == conn) {
        return -1;
    }
    HASH_DEL(conn->skcp->conn_ht, conn);
    return 0;
}

static int kcp_output(const char *buf, int len, ikcpcb *kcp, void *user) {
    skcp_conn_t *conn = (skcp_conn_t *)user;
    return conn->skcp->conf->output(buf, len, conn);
}

static int kcp_send_raw(skcp_conn_t *conn, const char *buf, int len, char cmd) {
    char *raw_buf = NULL;
    int raw_len = 0;
    int has_payload = SKCP_CMD_DATA == cmd || SKCP_CMD_PING == cmd || SKCP_CMD_PONG == cmd;
    if (has_payload) {
        raw_len = len + 1;
        raw_buf = malloc(raw_len);
        snprintf(raw_buf, raw_len, "%c", cmd);
        char *p = raw_buf + 1;
        memcpy(p, buf, len);
    } else {
        // char s[2] = {0};
        // s[0] = cmd;
        // raw_buf = s;
        // raw_len = 1;
        srand((unsigned)time(NULL));
        int jam = rand() % (RAND_MAX - 10000000) + 10000000;
        char s[10] = {0};
        snprintf(s, 10, "%c%d", cmd, jam);
        raw_len = strlen(s);
        raw_buf = s;
    }

    int rt = ikcp_send(conn->kcp, raw_buf, raw_len);
    if (has_payload) {
        SKCP_FREE(raw_buf);
    }
    if (rt < 0) {
        // 发送失败
        return -1;
    }
    ikcp_update(conn->kcp, clock());  // TODO: 跨平台

    return rt;
}

static void close_conn(skcp_conn_t *conn, int close_cmd_flg) {
    if (conn->skcp->conn_ht) {
        del_conn(conn);
    }

    if (!close_cmd_flg) {
        int rt = kcp_send_raw(conn, NULL, 0, SKCP_CMD_CLOSE);
    }

    conn->status = SKCP_CONN_ST_OFF;

    if (conn->htkey) {
        SKCP_FREE(conn->htkey);
    }

    if (conn->waiting_buf_q) {
        waiting_buf_t *wbtmp, *item;
        DL_FOREACH_SAFE(conn->waiting_buf_q, item, wbtmp) {
            DL_DELETE(conn->waiting_buf_q, item);
            SKCP_FREE(item);
        }
        conn->waiting_buf_q = NULL;
    }

    if (conn->kcp) {
        ikcp_release(conn->kcp);
        conn->kcp = NULL;
    }

    conn->sess_id = 0;  // TODO: for test
    SKCP_FREE(conn);
}

static int parse_recv_data(skcp_conn_t *conn, char *in_buf, char *out_buf, int len) {
    if (len < 1) {
        return -1;
    }

    char cmd = *in_buf;
    if (SKCP_CMD_CONN == cmd) {
        if (SKCP_CONN_ST_READY != conn->status) {
            return -1;
        }

        kcp_send_raw(conn, NULL, 0, SKCP_CMD_CONN_ACK);
        conn->status = SKCP_CONN_ST_ON;
        return -2;  // accept connection
    } else if (SKCP_CMD_CONN_ACK == cmd) {
        if (SKCP_CONN_ST_READY != conn->status) {
            return -1;
        }

        conn->status = SKCP_CONN_ST_ON;
        return -3;
    } else if (SKCP_CMD_CLOSE == cmd) {
        close_conn(conn, 1);
        return -4;
    } else if (SKCP_CMD_PING == cmd) {
        memcpy(out_buf, in_buf + 1, len - 1);  // TODO: 返回长度，否则可能会有越界的问题
        return -5;
    } else if (SKCP_CMD_PONG == cmd) {
        memcpy(out_buf, in_buf + 1, len - 1);  // TODO: 返回长度，否则可能会有越界的问题
        return -6;
    } else if (SKCP_CMD_DATA == cmd) {
        memcpy(out_buf, in_buf + 1, len - 1);
        return len - 1;
    }

    return -1;
}

/************************************************/

void skcp_update(skcp_conn_t *conn, IUINT32 current) { ikcp_update(conn->kcp, current); }
void skcp_update_all(skcp_t *skcp, IUINT32 current) {
    skcp_conn_t *conn, *tmp;
    HASH_ITER(hh, skcp->conn_ht, conn, tmp) { ikcp_update(conn->kcp, current); }
}

int skcp_input(skcp_conn_t *conn, const char *data, long size) {
    int rt = ikcp_input(conn->kcp, data, size);
    ikcp_update(conn->kcp, clock());  // TODO: 跨平台
    return rt;
}
IUINT32 skcp_get_sess_id(const void *data) { return ikcp_getconv(data); }

int skcp_recv(skcp_conn_t *conn, char *buffer, int len) {
    char *recv_buf = malloc(len);
    int recv_len = ikcp_recv(conn->kcp, recv_buf, len);
    ikcp_update(conn->kcp, clock());  // TODO: 跨平台
    recv_len = recv_len == -1 ? 0 : recv_len;
    if (recv_len > 0) {
        recv_len = parse_recv_data(conn, recv_buf, buffer, recv_len);
    }
    SKCP_FREE(recv_buf);
    return recv_len;
}

int skcp_send(skcp_conn_t *conn, const char *buffer, int len) { return kcp_send_raw(conn, buffer, len, SKCP_CMD_DATA); }

int skcp_send_ping(skcp_conn_t *conn, IUINT64 now) {
    char buf[22] = {0};
    snprintf(buf, 22, "%llu", now);
    return kcp_send_raw(conn, buf, strlen(buf), SKCP_CMD_PING);
}

int skcp_send_pong(skcp_conn_t *conn, IUINT64 tm, IUINT64 now) {
    char buf[44] = {0};
    snprintf(buf, 44, "%llu %llu", tm, now);
    return kcp_send_raw(conn, buf, strlen(buf), SKCP_CMD_PONG);
}

IUINT32 skcp_gen_sess_id(skcp_t *skcp) {
    skcp->cur_sess_id++;
    return skcp->cur_sess_id;
}

skcp_conn_t *skcp_create_conn(skcp_t *skcp, char *htkey, IUINT32 sess_id, IUINT64 now, void *user_data) {
    skcp_conn_t *conn = malloc(sizeof(skcp_conn_t));
    conn->sess_id = sess_id;
    conn->last_r_tm = conn->last_w_tm = conn->estab_tm = now;
    conn->skcp = skcp;
    conn->status = SKCP_CONN_ST_READY;
    conn->user_data = user_data;
    conn->waiting_buf_q = NULL;
    conn->htkey = htkey;

    ikcpcb *kcp = ikcp_create(conn->sess_id, conn);
    skcp_conf_t *conf = skcp->conf;
    kcp->output = kcp_output;
    ikcp_wndsize(kcp, conf->sndwnd, conf->rcvwnd);
    ikcp_nodelay(kcp, conf->nodelay, conf->interval, conf->nodelay, conf->nc);
    ikcp_setmtu(kcp, conf->mtu);
    conn->kcp = kcp;

    if (skcp->mode == SKCP_MODE_CLI) {
        kcp_send_raw(conn, NULL, 0, SKCP_CMD_CONN);
    }

    add_conn(conn);

    return conn;
}

void skcp_close_conn(skcp_conn_t *conn) { close_conn(conn, 0); }

int skcp_check_timeout(skcp_conn_t *conn, IUINT64 now) {
    skcp_t *skcp = conn->skcp;
    if (SKCP_CONN_ST_READY == conn->status) {
        // 连接管理
        if ((now - conn->estab_tm) >= skcp->conf->estab_timeout * 1000l) {
            // 超时
            close_conn(conn, 0);
            return -1;
        }
    } else {
        if (SKCP_CONN_ST_CAN_OFF == conn->status) {
            close_conn(conn, 0);
            return -2;
        } else {
            if ((now - conn->last_r_tm) >= skcp->conf->r_keepalive * 1000l) {
                // 超时
                return -3;
            }
        }
    }
    return 0;
}

skcp_t *skcp_init(skcp_conf_t *conf, SKCP_MODE mode) {
    skcp_t *skcp = malloc(sizeof(skcp_t));
    skcp->conf = conf;
    skcp->conn_ht = NULL;
    skcp->cur_sess_id = 0;
    skcp->mode = mode;
    return skcp;
}
void skcp_free(skcp_t *skcp) {
    skcp->conf = NULL;
    SKCP_FREE(skcp);
}
