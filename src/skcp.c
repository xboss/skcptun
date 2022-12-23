#include "skcp.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "3rd/uthash/utlist.h"
#include "skcp_protocol.h"

#define SKCP_FREEIF(p) \
    do {               \
        if (p) {       \
            free(p);   \
            p = NULL;  \
        }              \
    } while (0)

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

static int kcp_send_raw(skcp_conn_t *conn, const char *buf, int len) {
    // char *raw_buf = NULL;
    // int raw_len = 0;
    // int has_payload = SKCP_CMD_DATA == cmd || SKCP_CMD_PING == cmd || SKCP_CMD_PONG == cmd;
    // if (has_payload) {
    //     raw_len = len + 1;
    //     raw_buf = malloc(raw_len);
    //     snprintf(raw_buf, raw_len, "%c", cmd);
    //     char *p = raw_buf + 1;
    //     memcpy(p, buf, len);
    // } else {
    //     // char s[2] = {0};
    //     // s[0] = cmd;
    //     // raw_buf = s;
    //     // raw_len = 1;
    //     srand((unsigned)time(NULL));
    //     int jam = rand() % (RAND_MAX - 10000000) + 10000000;
    //     char s[10] = {0};
    //     snprintf(s, 10, "%c%d", cmd, jam);
    //     raw_len = strlen(s);
    //     raw_buf = s;
    // }

    int rt = ikcp_send(conn->kcp, buf, len);
    if (rt < 0) {
        // 发送失败
        return -1;
    }
    ikcp_update(conn->kcp, clock());  // TODO: 跨平台

    return rt;
}

// static void close_conn(skcp_conn_t *conn, int is_send_close_cmd) {
static void close_conn(skcp_conn_t *conn) {
    printf("debug: close_conn htkey: %s\n", conn->htkey);
    if (conn->skcp->conn_ht) {
        del_conn(conn);
    }

    // if (is_send_close_cmd) {
    //     skcp_cmd_close_t *cmd_close;
    //     SKCP_BUILD_CMD_CLOSE(cmd_close);
    //     int close_len = 0;
    //     char *close_buf = skcp_encode_cmd_close(cmd_close, &close_len);
    //     SKCP_FREEIF(cmd_close);
    //     if (close_buf) {
    //         printf("debug: close_conn htkey: %s\n", conn->htkey);
    //         kcp_send_raw(conn, close_buf, close_len);
    //         SKCP_FREEIF(close_buf);
    //     }
    // }

    conn->status = SKCP_CONN_ST_OFF;

    if (conn->htkey) {
        SKCP_FREEIF(conn->htkey);
    }

    if (conn->waiting_buf_q) {
        waiting_buf_t *wbtmp, *item;
        DL_FOREACH_SAFE(conn->waiting_buf_q, item, wbtmp) {
            DL_DELETE(conn->waiting_buf_q, item);
            SKCP_FREEIF(item);
        }
        conn->waiting_buf_q = NULL;
    }

    if (conn->kcp) {
        ikcp_release(conn->kcp);
        conn->kcp = NULL;
    }

    conn->sess_id = 0;  // TODO: for test
    SKCP_FREEIF(conn);
}

// static int handle_cmd_conn(skcp_conn_t *conn, skcp_cmd_conn_t *cmd) {
//     if (!cmd) {
//         return -1;
//     }

//     if (SKCP_CONN_ST_READY != conn->status) {
//         return -1;
//     }

//     if ((cmd->flg & SKCP_CMD_CONN_NEED_ENCRYPT) == SKCP_CMD_CONN_NEED_ENCRYPT) {
//         int iv_len = cmd->payload_len > sizeof(conn->iv) ? sizeof(conn->iv) : cmd->payload_len;
//         memcpy(conn->iv, cmd->payload, iv_len);
//     }

//     skcp_cmd_conn_ack_t *ack;
//     SKCP_BUILD_CMD_CONN_ACK(ack, 0, cmd->payload_len, cmd->payload);
//     char *ack_buf;
//     int ack_buf_len = encode_cmd_conn_ack(ack, &ack_buf);
//     if (ack_buf_len <= 0) {
//         SKCP_FREEIF(ack);
//         return -1;
//     }
//     kcp_send_raw(conn, ack_buf, ack_buf_len);
//     conn->status = SKCP_CONN_ST_ON;

//     return 0;
// }

static int parse_recv(skcp_conn_t *conn, char *in_buf, char *out_buf, int len, int *op_type) {
    if (len < SKCP_CMD_HEADER_LEN) {
        return -1;
    }
    int rt = 0;
    skcp_cmd_header_t header;
    SKCP_DECODE_CMD_HEADER(header, in_buf);
    if (SKCP_CMD_CONN == header.type) {
        *op_type = 1;
        if (SKCP_CONN_ST_READY != conn->status) {
            return -1;
        }
        skcp_cmd_t *cmd_conn = skcp_decode_cmd(in_buf, len);
        if (!cmd_conn) {
            return -1;
        }
        if (cmd_conn->header.payload_len > 0) {
            memcpy(out_buf, cmd_conn->payload, cmd_conn->header.payload_len);
            rt = cmd_conn->header.payload_len;
        }

        skcp_cmd_t *ack;
        SKCP_BUILD_CMD(ack, SKCP_CMD_CONN_ACK, 0x00, cmd_conn->header.payload_len, cmd_conn->payload);
        SKCP_FREEIF(cmd_conn);

        int ack_buf_len = 0;
        char *ack_buf = skcp_encode_cmd(ack, &ack_buf_len);
        SKCP_FREEIF(ack);
        if (!ack_buf) {
            return -1;
        }
        kcp_send_raw(conn, ack_buf, ack_buf_len);

        printf("send conn ack %d\n", ack_buf_len);

        SKCP_FREEIF(ack_buf);
        conn->status = SKCP_CONN_ST_ON;

    } else if (SKCP_CMD_CONN_ACK == header.type) {
        printf("recv conn ack start \n");
        *op_type = 2;
        if (SKCP_CONN_ST_READY != conn->status) {
            return -1;
        }
        skcp_cmd_t *cmd_conn_ack = skcp_decode_cmd(in_buf, len);
        if (!cmd_conn_ack) {
            return -1;
        }

        if (cmd_conn_ack->header.payload_len > 0) {
            memcpy(out_buf, cmd_conn_ack->payload, cmd_conn_ack->header.payload_len);
            rt = cmd_conn_ack->header.payload_len;
        }

        printf("recv conn ack %d\n", len);

        SKCP_FREEIF(cmd_conn_ack);
        conn->status = SKCP_CONN_ST_ON;
    } else if (SKCP_CMD_CLOSE == header.type) {
        *op_type = 3;
        close_conn(conn);
        // conn->status = SKCP_CONN_ST_CAN_OFF;
    } else if (SKCP_CMD_DATA == header.type) {
        *op_type = 4;
        skcp_cmd_t *cmd_data = skcp_decode_cmd(in_buf, len);
        if (!cmd_data) {
            return -1;
        }
        if (cmd_data->header.payload_len > 0) {
            memcpy(out_buf, cmd_data->payload, cmd_data->header.payload_len);
            rt = cmd_data->header.payload_len;
        }
        SKCP_FREEIF(cmd_data);
    } else if (SKCP_CMD_CTRL == header.type) {
        *op_type = 5;
        skcp_cmd_t *cmd_ctrl = skcp_decode_cmd(in_buf, len);
        if (!cmd_ctrl) {
            return -1;
        }
        if (cmd_ctrl->header.payload_len > 0) {
            memcpy(out_buf, cmd_ctrl->payload, cmd_ctrl->header.payload_len);
            rt = cmd_ctrl->header.payload_len;
        }
        SKCP_FREEIF(cmd_ctrl);
    } else {
        *op_type = 0;
    }
    return rt;
}

static int send_cmd(skcp_conn_t *conn, const char *buf, int len, char type) {
    skcp_cmd_t *cmd;
    SKCP_BUILD_CMD(cmd, type, 0x00, len, (char *)buf);
    int cmd_len = 0;
    char *cmd_buf = skcp_encode_cmd(cmd, &cmd_len);
    SKCP_FREEIF(cmd);
    if (!cmd_buf) {
        return -1;
    }
    int rt = kcp_send_raw(conn, cmd_buf, cmd_len);
    SKCP_FREEIF(cmd_buf);
    return rt;
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

int skcp_recv(skcp_conn_t *conn, char *buf, int buf_len, int *op_type) {
    char *recv_buf = malloc(buf_len);
    int recv_len = 0;
    // irecv:
    recv_len = ikcp_recv(conn->kcp, recv_buf, buf_len);
    if (recv_len < 0) {
        if (recv_len == -3) {
            fprintf(stderr, "warn: ikcp_recv peeksize > len, %d\n", buf_len);
        }
        recv_len = 0;
    }

    ikcp_update(conn->kcp, clock());  // TODO: 跨平台
    if (recv_len > 0) {
        recv_len = parse_recv(conn, recv_buf, buf, recv_len, op_type);
    }
    SKCP_FREEIF(recv_buf);
    return recv_len;
}

int skcp_send_data(skcp_conn_t *conn, const char *buf, int len) { return send_cmd(conn, buf, len, SKCP_CMD_DATA); }

int skcp_send_ctrl(skcp_conn_t *conn, const char *buf, int len) { return send_cmd(conn, buf, len, SKCP_CMD_CTRL); }

// int skcp_send_ping(skcp_conn_t *conn, IUINT64 now) {
//     char buf[22] = {0};
//     snprintf(buf, 22, "%llu", now);
//     return kcp_send_raw(conn, buf, strlen(buf), SKCP_CMD_PING);
// }

// int skcp_send_pong(skcp_conn_t *conn, IUINT64 tm, IUINT64 now) {
//     char buf[44] = {0};
//     snprintf(buf, 44, "%llu %llu", tm, now);
//     return kcp_send_raw(conn, buf, strlen(buf), SKCP_CMD_PONG);
// }

IUINT32 skcp_gen_sess_id(skcp_t *skcp) {
    skcp->cur_sess_id++;
    return skcp->cur_sess_id;
}

skcp_conn_t *skcp_create_conn(skcp_t *skcp, char *htkey, IUINT32 sess_id, IUINT64 now, void *user_data,
                              char *conn_param, int conn_param_len) {
    skcp_conn_t *conn = malloc(sizeof(skcp_conn_t));
    conn->sess_id = sess_id;
    conn->last_r_tm = conn->last_w_tm = conn->estab_tm = now;
    conn->skcp = skcp;
    conn->status = SKCP_CONN_ST_READY;
    conn->user_data = user_data;
    conn->waiting_buf_q = NULL;
    conn->htkey = htkey;
    // memset(conn->iv, 0, sizeof(conn->iv));

    ikcpcb *kcp = ikcp_create(conn->sess_id, conn);
    skcp_conf_t *conf = skcp->conf;
    kcp->output = kcp_output;
    ikcp_wndsize(kcp, conf->sndwnd, conf->rcvwnd);
    ikcp_nodelay(kcp, conf->nodelay, conf->interval, conf->nodelay, conf->nc);
    ikcp_setmtu(kcp, conf->mtu);
    conn->kcp = kcp;

    if (skcp->mode == SKCP_MODE_CLI) {
        skcp_cmd_t *cmd_conn;
        // char flg = 0x00;
        // if (conn_param && conn_param_len > 0) {
        //     flg = SKCP_CMD_CONN_NEED_ENCRYPT;
        // }
        SKCP_BUILD_CMD(cmd_conn, SKCP_CMD_CONN, 0x00, conn_param_len, conn_param);
        int conn_len = 0;
        char *conn_buf = skcp_encode_cmd(cmd_conn, &conn_len);
        SKCP_FREEIF(cmd_conn);
        if (!conn_buf) {
            ikcp_release(conn->kcp);
            conn->kcp = NULL;
            SKCP_FREEIF(conn);
            return NULL;
        }
        kcp_send_raw(conn, conn_buf, conn_len);
        SKCP_FREEIF(conn_buf);
    }

    add_conn(conn);

    return conn;
}

void skcp_close_conn(skcp_conn_t *conn) {
    // close_conn(conn, 1);
    if (NULL == conn) {
        return;
    }
    skcp_cmd_t *cmd_close;
    SKCP_BUILD_CMD(cmd_close, SKCP_CMD_CLOSE, 0x00, 0, NULL);
    int close_len = 0;
    char *close_buf = skcp_encode_cmd(cmd_close, &close_len);
    SKCP_FREEIF(cmd_close);
    if (close_buf) {
        // printf("debug: send close cmd htkey: %s\n", conn->htkey);
        kcp_send_raw(conn, close_buf, close_len);
        SKCP_FREEIF(close_buf);
    }

    if (SKCP_CONN_ST_ON == conn->status || SKCP_CONN_ST_READY == conn->status) {
        conn->status = SKCP_CONN_ST_CAN_OFF;
    }
}

int skcp_check_timeout(skcp_conn_t *conn, IUINT64 now) {
    skcp_t *skcp = conn->skcp;
    if (SKCP_CONN_ST_READY == conn->status) {
        // 连接管理
        if ((now - conn->estab_tm) >= skcp->conf->estab_timeout * 1000l) {
            // 超时
            skcp_close_conn(conn);
            return -1;
        }
    } else {
        if (SKCP_CONN_ST_CAN_OFF == conn->status) {
            close_conn(conn);
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
    SKCP_FREEIF(skcp);
}
