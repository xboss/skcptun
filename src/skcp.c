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
// #define SKCP_CMD_PONG 0x07

#define SKCP_FREE(p)  \
    do {              \
        if (p) {      \
            free(p);  \
            p = NULL; \
        }             \
    } while (0);

struct waiting_buf_s {
    char buf[2048];
    int len;
    waiting_buf_t *next, *prev;
};
/****** private ******/

static void append_wait_buf(skcp_conn_t *conn, const char *buffer, int len) {
    size_t wb_sz = sizeof(waiting_buf_t);
    waiting_buf_t *msg = (waiting_buf_t *)malloc(wb_sz);
    memset(msg, 0, wb_sz);
    memcpy(msg->buf, buffer, len);
    msg->len = len;
    DL_APPEND(conn->waiting_buf_q, msg);
}

skcp_conn_t *skcp_get_conn(skcp_t *skcp, char *htkey) {
    skcp_conn_t *conn = NULL;
    if (skcp->conn_ht) {
        HASH_FIND_STR(skcp->conn_ht, htkey, conn);
    }
    return conn;
}

// static int add_conn(char *key, skcp_conn_t *conn) {
//     if (NULL == conn) {
//         return -1;
//     }

//     if (NULL == get_conn(conn->skcp, key)) {
//         int l = strlen(key) + 1;
//         conn->htkey = malloc(l);  // TODO: free it
//         memset(conn->htkey, 0, l);
//         memcpy(conn->htkey, key, l);
//         HASH_ADD_KEYPTR(hh, conn->skcp->conn_ht, conn->htkey, l - 1, conn);
//     }

//     // int cnt = HASH_COUNT(conn->skcp->conn_ht);
//     return 0;
// }

static int add_conn(skcp_conn_t *conn) {
    if (NULL == conn) {
        return -1;
    }

    if (NULL == skcp_get_conn(conn->skcp, conn->htkey)) {
        // TODO: strlen(conn->htkey)有隐患
        HASH_ADD_KEYPTR(hh, conn->skcp->conn_ht, conn->htkey, strlen(conn->htkey), conn);
    }

    // int cnt = HASH_COUNT(conn->skcp->conn_ht);
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
    if (SKCP_CMD_DATA == cmd) {
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
        char s[34] = {0};
        snprintf(s, 34, "%c%d", cmd, jam);
        raw_len = strlen(s);
        raw_buf = s;
    }

    int rt = ikcp_send(conn->kcp, raw_buf, raw_len);
    if (SKCP_CMD_DATA == cmd) {
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

    // LOG_D("close_conn sess_id:%u", conn->sess_id);
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
            // close_conn(serv, conn->sess_id, &conn->cliaddr, 0);
            return -1;
        }

        kcp_send_raw(conn, NULL, 0, SKCP_CMD_CONN_ACK);
        conn->status = SKCP_CONN_ST_ON;
        // conn->serv->new_conn_cb(conn);
        return -2;  // accept connection
    } else if (SKCP_CMD_CONN_ACK == cmd) {
        if (SKCP_CONN_ST_READY != conn->status) {
            // close_conn(cli, conn->sess_id, 0);
            return -1;
        }

        conn->status = SKCP_CONN_ST_ON;
        // LOG_D("cmd conn_ack sess_id:%u", conn->sess_id);

        if (conn->waiting_buf_q) {
            // LOG_D("skt_kcp_client_send send waiting buf sess_id: %d", conn->sess_id);
            waiting_buf_t *wbtmp, *item;
            DL_FOREACH_SAFE(conn->waiting_buf_q, item, wbtmp) {
                ssize_t rt = kcp_send_raw(conn, item->buf, item->len, SKCP_CMD_DATA);
                if (rt < 0) {
                    // LOG_E("skt_kcp_client_send write error sess_id:%d rt:%zd", conn->sess_id, rt);
                    return -1;
                }
                DL_DELETE(conn->waiting_buf_q, item);
                SKCP_FREE(item);
            }
            conn->waiting_buf_q = NULL;
        }

        return -3;
    } else if (SKCP_CMD_CLOSE == cmd) {
        close_conn(conn, 1);
        return -4;
    } else if (SKCP_CMD_PING == cmd) {
        // TODO:
        return -5;
    } else if (SKCP_CMD_DATA == cmd) {
        // LOG_D("cmd conn_data sess_id:%u", conn->sess_id);
        // char *p = in_buf + 1;
        memcpy(out_buf, in_buf + 1, len - 1);
        return len - 1;
    }

    // LOG_E("parse_recv_data error cmd:%c", cmd);
    return -1;
}

/****** public ******/

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
        // ikcp_update(conn->kcp, clock());
    }
    SKCP_FREE(recv_buf);
    return recv_len;
}

int skcp_send(skcp_conn_t *conn, const char *buffer, int len) {
    if (SKCP_CONN_ST_READY == conn->status) {
        append_wait_buf(conn, buffer, len);
        return len;
    }

    if (SKCP_CONN_ST_ON != conn->status) {
        return -1;
    }

    if (conn->waiting_buf_q) {
        waiting_buf_t *wbtmp, *item;
        DL_FOREACH_SAFE(conn->waiting_buf_q, item, wbtmp) {
            ssize_t rt = kcp_send_raw(conn, item->buf, item->len, SKCP_CMD_DATA);
            if (rt < 0) {
                return rt;
            }
            DL_DELETE(conn->waiting_buf_q, item);
            SKCP_FREE(item);
        }
        conn->waiting_buf_q = NULL;
    }

    return kcp_send_raw(conn, buffer, len, SKCP_CMD_DATA);
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

// void skcp_check_timeout(skcp_t *skcp, IUINT64 now) {
//     skcp_conn_t *conn, *tmp;
//     HASH_ITER(hh, skcp->conn_ht, conn, tmp) {
//         if (SKCP_CONN_ST_READY == conn->status) {
//             // 连接管理
//             if ((now - conn->estab_tm) >= skcp->conf->estab_timeout * 1000l) {
//                 // 超时
//                 // LOG_D("estab_timeout sess_id:%u", conn->sess_id);
//                 close_conn(conn, 0);
//             }
//         } else {
//             if (SKCP_CONN_ST_CAN_OFF == conn->status) {
//                 close_conn(conn, 0);
//             } else {
//                 if ((now - conn->last_r_tm) >= skcp->conf->r_keepalive * 1000l) {
//                     // 超时
//                     // LOG_D("conn_timeout_cb sess_id:%u", conn->sess_id);
//                     close_conn(conn, 0);
//                 }
//             }
//         }
//     }
// }

int skcp_check_timeout(skcp_conn_t *conn, IUINT64 now) {
    skcp_t *skcp = conn->skcp;
    if (SKCP_CONN_ST_READY == conn->status) {
        // 连接管理
        if ((now - conn->estab_tm) >= skcp->conf->estab_timeout * 1000l) {
            // 超时
            // LOG_D("estab_timeout sess_id:%u", conn->sess_id);
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
                // LOG_D("conn_timeout_cb sess_id:%u", conn->sess_id);
                // close_conn(conn, 0);
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
    // skcp_conn_t *conn, *tmp;
    // HASH_ITER(hh, skcp->conn_ht, conn, tmp) {
    //     close_conn(conn, 0);  // TODO: free it
    //     conn = NULL;
    // }
    // skcp->conn_ht = NULL;

    skcp->conf = NULL;
    SKCP_FREE(skcp);
}
