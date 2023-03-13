#include "skt_proxy_client.h"

#include "skt_protocol.h"
#include "skt_utils.h"
#include "uthash.h"

// typedef struct {
//     int fd;  // key
//     uint32_t cid;
//     UT_hash_handle hh;
// } skt_fd_cid_ht_t;

typedef struct {
    struct ev_loop *loop;
    uint32_t cid;
    skcp_t *skcp;
    etcp_serv_t *etcp;
    struct ev_timer *bt_watcher;
    // skt_fd_cid_ht_t *fd_cid_ht;
} skt_serv_t;
// typedef struct skt_serv_s skt_serv_t;

static skt_serv_t *g_ctx = NULL;

#define SKT_MSG_HEADER_MAX 16
#define SKT_MSG_CMD_ACCEPT 'A'
#define SKT_MSG_CMD_DATA 'D'
#define SKT_MSG_SEPARATOR '\n'

/* -------------------------------------------------------------------------- */
/*                                 Private API                                */
/* -------------------------------------------------------------------------- */

// inline static skt_fd_cid_ht_t *add_fd_cid_ht(int fd, uint32_t cid) {
//     skt_fd_cid_ht_t *fc = NULL;
//     HASH_FIND_INT(g_ctx->fd_cid_ht, &fd, fc);
//     if (fc == NULL) {
//         fc = (skt_fd_cid_ht_t *)malloc(sizeof(skt_fd_cid_ht_t));
//         fc->fd = fd;
//         HASH_ADD_INT(g_ctx->fd_cid_ht, fd, fc);
//     }
//     fc->cid = cid;
//     return fc;
// }

// inline static skt_fd_cid_ht_t *find_fd_cid_ht(uint32_t fd) {
//     skt_fd_cid_ht_t *fc = NULL;
//     HASH_FIND_INT(g_ctx->fd_cid_ht, &fd, fc);
//     return fc;
// }

// inline static void del_fd_cid_ht(skt_fd_cid_ht_t *fc) {
//     if (!g_ctx->fd_cid_ht || !fc) {
//         return;
//     }
//     HASH_DEL(g_ctx->fd_cid_ht, fc);
//     FREE_IF(fc);
// }

// inline static void del_all_fd_cid_ht() {
//     skt_fd_cid_ht_t *fc, *tmp;
//     HASH_ITER(hh, g_ctx->fd_cid_ht, fc, tmp) {
//         HASH_DEL(g_ctx->fd_cid_ht, fc);
//         FREE_IF(fc);
//     }
// }

/* ---------------------------- EasyTCP callback ---------------------------- */

static int on_tcp_accept(int fd) {
    LOG_D("tcp server accept fd: %d", fd);

    if (g_ctx->cid <= 0) {
        LOG_E("tun_read_cb g_ctx->cid error : %u", g_ctx->cid);
        return 1;
    }

    char msg[SKT_MSG_HEADER_MAX] = {};  // format: "cmd(1B)\nfd"
    snprintf(msg, SKT_MSG_HEADER_MAX, "%c\n%d", SKT_MSG_CMD_ACCEPT, fd);

    char *seg_raw = NULL;
    int seg_raw_len = 0;
    SKT_ENCODE_SEG(seg_raw, 0, SKT_SEG_DATA, msg, strlen(msg), seg_raw_len);
    int rt = skcp_send(g_ctx->skcp, g_ctx->cid, seg_raw, seg_raw_len);
    FREE_IF(seg_raw);
    if (rt < 0) {
        LOG_E("skcp_send error cid: %u", g_ctx->cid);
        return 1;
    }

    return 0;
}
static void on_tcp_recv(int fd, char *buf, int len) {
    char header[SKT_MSG_HEADER_MAX] = {};
    snprintf(header, SKT_MSG_HEADER_MAX, "%c\n%d\n", SKT_MSG_CMD_DATA, fd);
    int header_len = strlen(header);
    int msg_len = header_len + len;
    char *msg = (char *)calloc(1, msg_len);  // format: "cmd(1B)\nfd\ndata"
    memcpy(msg, header, header_len);
    memcpy(msg + header_len, buf, len);

    char *seg_raw = NULL;
    int seg_raw_len = 0;
    SKT_ENCODE_SEG(seg_raw, 0, SKT_SEG_DATA, msg, msg_len, seg_raw_len);
    int rt = skcp_send(g_ctx->skcp, g_ctx->cid, seg_raw, seg_raw_len);
    FREE_IF(seg_raw);
    if (rt < 0) {
        LOG_E("skcp_send error cid: %u", g_ctx->cid);
        return;
    }
}
static void on_tcp_close(int fd) { LOG_D("tcp server on_close fd: %d", fd); }

/* ------------------------------ skcp callback ----------------------------- */

static void skcp_on_recv_cid(uint32_t cid) {
    LOG_D("client on_recv cid: %u", cid);
    g_ctx->cid = cid;
}
static void skcp_on_recv_data(uint32_t cid, char *buf, int len) {
    // char src_ip[20] = {0};
    // char dest_ip[20] = {0};
    // inet_ntop(AF_INET, buf + 12, src_ip, sizeof(src_ip));
    // inet_ntop(AF_INET, buf + 16, dest_ip, sizeof(dest_ip));
    // printf("kcp_recv_data_cb src_ip: %s dest_ip: %s\n", src_ip, dest_ip);
    LOG_D("client on_recv cid: %u len: %d", cid, len);

    skt_seg_t *seg = NULL;
    SKT_DECODE_SEG(seg, buf, len);
    if (!SKT_CHECK_SEG_HEADER(seg)) {
        LOG_E("client on_recv decode seg error cid: %u len: %d", cid, len);
        FREE_IF(seg);
        return;
    }

    LOG_D("client on_recv seg type: %x", seg->type);

    if ((seg->flg & SKT_SEG_FLG_AUTH) == SKT_SEG_FLG_AUTH) {
        // TODO: auth ticket
    }

    if (seg->type == SKT_SEG_PONG) {
        // TODO: 忽略
    }

    if (seg->type == SKT_SEG_DATA) {
        if (seg->payload_len <= 0) {
            LOG_E("client on_recv seg payload error  cid: %u len: %d, type: %x", cid, len, seg->type);
            FREE_IF(seg);
            return;
        }

        char cmd = '\0';
        int tr_fd = 0;
        char *pdata = NULL;
        int pdata_len = 0;
        if (parse_skt_msg(seg->payload, seg->payload_len, &cmd, &tr_fd, &pdata, &pdata_len) != 0) {
            LOG_E("client on_recv parse_skt_msg error cid: %u len: %d, type: %x cmd: %c", cid, len, seg->type, cmd);
            FREE_IF(seg);
            return;
        }

        if (cmd != SKT_MSG_CMD_DATA || !pdata || pdata_len <= 0) {
            LOG_E("client on_recv cmd or data error cid: %u len: %d, type: %x cmd: %c", cid, len, seg->type, cmd);
            FREE_IF(seg);
            return;
        }

        int w_len = etcp_server_send(g_ctx->etcp, tr_fd, pdata, pdata_len);
        FREE_IF(seg);
        if (w_len <= 0) {
            LOG_E("client on_recv etcp_server_send error cid: %u len: %d cmd: %c", cid, len, cmd);
            return;
        }
        return;
    }

    // LOG_D(">>>>> kcp_recv_data_cb len: %d src_ip: %s dest_ip: %s", w_len, src_ip, dest_ip);
    FREE_IF(seg);
    return;
}

static void skcp_on_close(uint32_t cid) {
    LOG_D("skcp_on_close cid: %u", cid);
    g_ctx->cid = 0;
    return;
}

//////////////////////

static void beat_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents) {
    if (EV_ERROR & revents) {
        LOG_E("init_cb got invalid event");
        return;
    }

    skcp_t *skcp = (skcp_t *)watcher->data;

    if (g_ctx->cid <= 0) {
        skcp_req_cid(skcp, skcp->conf->ticket, strlen(skcp->conf->ticket));
        LOG_I("skcp_req_cid by beat_cb");
        return;
    }

    // ping
    char *ping_seg_raw = NULL;
    int ping_seg_raw_len = 0;
    SKT_ENCODE_SEG(ping_seg_raw, 0, SKT_SEG_PING, NULL, 0, ping_seg_raw_len);
    int rt = skcp_send(g_ctx->skcp, g_ctx->cid, ping_seg_raw, ping_seg_raw_len);
    FREE_IF(ping_seg_raw);
    if (rt < 0) {
        LOG_E("client send ping error cid: %u", g_ctx->cid);
        return;
    }
}

/* -------------------------------------------------------------------------- */
/*                                 Public API                                 */
/* -------------------------------------------------------------------------- */

int skt_proxy_client_init(skcp_conf_t *skcp_conf, etcp_serv_conf_t *etcp_conf, struct ev_loop *loop) {
    g_ctx = (skt_serv_t *)calloc(1, sizeof(skt_serv_t));
    g_ctx->loop = loop;

    g_ctx->etcp = etcp_init_server(etcp_conf, loop, NULL);
    if (NULL == g_ctx->etcp) {
        skt_proxy_client_free();
        return -1;
    }

    g_ctx->etcp->conf->on_accept = on_tcp_accept;
    g_ctx->etcp->conf->on_recv = on_tcp_recv;
    g_ctx->etcp->conf->on_close = on_tcp_close;

    g_ctx->skcp = skcp_init(skcp_conf, loop, g_ctx, SKCP_MODE_CLI);
    if (NULL == g_ctx->skcp) {
        skt_proxy_client_free();
        return -1;
    };

    g_ctx->skcp->conf->on_close = skcp_on_close;
    g_ctx->skcp->conf->on_recv_cid = skcp_on_recv_cid;
    g_ctx->skcp->conf->on_recv_data = skcp_on_recv_data;

    g_ctx->cid = 0;

    // 定时
    g_ctx->bt_watcher = malloc(sizeof(ev_timer));
    g_ctx->bt_watcher->data = g_ctx->skcp;
    ev_init(g_ctx->bt_watcher, beat_cb);
    ev_timer_set(g_ctx->bt_watcher, 0, 1);
    ev_timer_start(g_ctx->loop, g_ctx->bt_watcher);

    return 0;
}

void skt_proxy_client_free() {
    if (!g_ctx) {
        return;
    }

    if (g_ctx->bt_watcher) {
        ev_timer_stop(g_ctx->loop, g_ctx->bt_watcher);
        FREE_IF(g_ctx->bt_watcher);
    }

    if (g_ctx->cid > 0) {
        skcp_close_conn(g_ctx->skcp, g_ctx->cid);
    }

    if (g_ctx->etcp) {
        etcp_free_server(g_ctx->etcp);
    }

    if (g_ctx->skcp) {
        skcp_free(g_ctx->skcp);
    }

    FREE_IF(g_ctx);
}