#include "skt_proxy_client.h"

#include "skt_protocol.h"
#include "skt_switcher.h"
#include "skt_utils.h"
#include "uthash.h"

typedef struct {
    struct ev_loop *loop;
    // uint32_t cid;
    // skcp_t *skcp;
    skt_channel_t *chan;
    etcp_serv_t *etcp;
    struct ev_timer *bt_watcher;
    // skt_fd_cid_ht_t *fd_cid_ht;
} skt_serv_t;
// typedef struct skt_serv_s skt_serv_t;

static skt_serv_t *g_ctx = NULL;

/* -------------------------------------------------------------------------- */
/*                                 Private API                                */
/* -------------------------------------------------------------------------- */

/* ---------------------------- EasyTCP callback ---------------------------- */

static int on_tcp_accept(int fd) {
    LOG_D("tcp server accept fd: %d", fd);

    if (g_ctx->chan->cid <= 0) {
        LOG_E("on_tcp_accept g_ctx->cid error : %u", g_ctx->chan->cid);
        return 1;
    }

    char msg[SKT_MSG_HEADER_MAX] = {};  // format: "cmd(1B)\nfd"
    snprintf(msg, SKT_MSG_HEADER_MAX, "%c\n%d", SKT_MSG_CMD_ACCEPT, fd);

    char *seg_raw = NULL;
    int seg_raw_len = 0;
    SKT_ENCODE_SEG(seg_raw, 0, SKT_SEG_DATA, msg, strlen(msg), seg_raw_len);
    int rt = skcp_send(g_ctx->chan->skcp, g_ctx->chan->cid, seg_raw, seg_raw_len);
    FREE_IF(seg_raw);
    if (rt < 0) {
        LOG_E("skcp_send error cid: %u", g_ctx->chan->cid);
        return 1;
    }
    // LOG_I("on_tcp_accept msg: %s", msg);

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

    LOG_D("on_tcp_recv header: %s len: %d", header, len);

    char *seg_raw = NULL;
    int seg_raw_len = 0;
    SKT_ENCODE_SEG(seg_raw, 0, SKT_SEG_DATA, msg, msg_len, seg_raw_len);
    FREE_IF(msg);
    int rt = skcp_send(g_ctx->chan->skcp, g_ctx->chan->cid, seg_raw, seg_raw_len);
    FREE_IF(seg_raw);
    if (rt < 0) {
        LOG_E("skcp_send error cid: %u", g_ctx->chan->cid);
        return;
    }
}
static void on_tcp_close(int fd) {
    LOG_D("tcp server on_close fd: %d", fd);
    if (g_ctx->chan->cid <= 0) {
        LOG_E("on_tcp_close g_ctx->cid error : %u", g_ctx->chan->cid);
        return;
    }

    char msg[SKT_MSG_HEADER_MAX] = {};  // format: "cmd(1B)\nfd"
    snprintf(msg, SKT_MSG_HEADER_MAX, "%c\n%d", SKT_MSG_CMD_CLOSE, fd);
    char *seg_raw = NULL;
    int seg_raw_len = 0;
    SKT_ENCODE_SEG(seg_raw, 0, SKT_SEG_DATA, msg, strlen(msg), seg_raw_len);
    int rt = skcp_send(g_ctx->chan->skcp, g_ctx->chan->cid, seg_raw, seg_raw_len);
    FREE_IF(seg_raw);
    if (rt < 0) {
        LOG_E("skcp_send error cid: %u", g_ctx->chan->cid);
        return;
    }
    // LOG_I("on_tcp_close msg: %s", msg);
}

/* ------------------------------ skcp callback ----------------------------- */

static void on_pong(skcp_t *skcp, skt_seg_t *seg) {
    uint64_t snd_time = skt_ntohll(*(uint64_t *)seg->payload);
    uint64_t now = getmillisecond();
    if (snd_time <= 0 || snd_time > now) {
        LOG_E("send time %llu error in pong msg", snd_time);
        return;
    }
    size_t rtt = now - snd_time;
    skt_switcher_update(skcp->fd, SKT_SW_UP_T_RTT, 0, rtt);
    g_ctx->chan = skt_switch();
}

static void skcp_on_recv_cid(skcp_t *skcp, uint32_t cid) {
    LOG_D("client on_recv cid: %u", cid);
    skt_switcher_update(skcp->fd, SKT_SW_UP_T_CID, cid, 0);
}
static void skcp_on_recv_data(skcp_t *skcp, uint32_t cid, char *buf, int len) {
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
        FREE_IF(seg);
        return;
    }

    if (seg->type == SKT_SEG_PONG) {
        on_pong(skcp, seg);
        FREE_IF(seg);
        return;
    }

    if (seg->type == SKT_SEG_DATA) {
        if (seg->payload_len <= 0) {
            LOG_E("client on_recv seg payload error  cid: %u len: %d, type: %x", cid, len, seg->type);
            FREE_IF(seg);
            return;
        }

        char cmd = '\0';
        int cfd = 0;
        char *pdata = NULL;
        int pdata_len = 0;
        if (parse_skt_msg(seg->payload, seg->payload_len, &cmd, &cfd, &pdata, &pdata_len) != 0) {
            LOG_E("client on_recv parse_skt_msg error cid: %u len: %d, type: %x cmd: %c", cid, len, seg->type, cmd);
            FREE_IF(seg);
            return;
        }

        if (cmd == SKT_MSG_CMD_CLOSE) {
            etcp_server_close_conn(g_ctx->etcp, cfd, 1);
            FREE_IF(seg);
            return;
        }

        if (cmd != SKT_MSG_CMD_DATA || !pdata || pdata_len <= 0) {
            LOG_E("client on_recv cmd or data error cid: %u len: %d, type: %x cmd: %c", cid, len, seg->type, cmd);
            FREE_IF(seg);
            return;
        }

        int w_len = etcp_server_send(g_ctx->etcp, cfd, pdata, pdata_len);
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

static void skcp_on_close(skcp_t *skcp, uint32_t cid) {
    LOG_D("skcp_on_close cid: %u", cid);
    skt_switcher_update(skcp->fd, SKT_SW_UP_T_CID, 0, 0);
    return;
}

//////////////////////

static void beat_cb_iter_fn(skt_channel_t *chan) {
    if (chan->cid <= 0) {
        skcp_req_cid(chan->skcp, chan->skcp->conf->ticket, strlen(chan->skcp->conf->ticket));
        LOG_I("skcp_req_cid by beat_cb");
        return;
    }

    // ping
    uint64_t now = skt_htonll(getmillisecond());
    char *ping_seg_raw = NULL;
    int ping_seg_raw_len = 0;
    SKT_ENCODE_SEG(ping_seg_raw, 0, SKT_SEG_PING, &now, sizeof(now), ping_seg_raw_len);
    int rt = skcp_send(chan->skcp, chan->cid, ping_seg_raw, ping_seg_raw_len);
    FREE_IF(ping_seg_raw);
    if (rt < 0) {
        LOG_E("client send ping error fd: %d cid: %u", chan->fd, chan->cid);
        return;
    }
    skt_switcher_update(chan->skcp->fd, SKT_SW_UP_T_SND, 0, 0);
}

static void beat_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents) {
    if (EV_ERROR & revents) {
        LOG_E("init_cb got invalid event");
        return;
    }

    // skcp_t *skcp = (skcp_t *)watcher->data;
    skt_switcher_iter(beat_cb_iter_fn);
}

static void free_iter_fn(skt_channel_t *chan) {
    if (chan && chan->skcp) {
        skcp_free(chan->skcp);
    }
}
/* -------------------------------------------------------------------------- */
/*                                 Public API                                 */
/* -------------------------------------------------------------------------- */

int skt_proxy_client_init(skcp_conf_t **skcp_conf_arr, size_t skcp_conf_sz, etcp_serv_conf_t *etcp_conf,
                          struct ev_loop *loop) {
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

    skt_switcher_init();

    for (size_t i = 0; i < skcp_conf_sz; i++) {
        skcp_conf_t *skcp_conf = skcp_conf_arr[i];
        skcp_t *skcp = skcp_init(skcp_conf, loop, g_ctx, SKCP_MODE_CLI);
        if (NULL == skcp) {
            skt_proxy_client_free();
            return -1;
        };

        skcp->conf->on_close = skcp_on_close;
        skcp->conf->on_recv_cid = skcp_on_recv_cid;
        skcp->conf->on_recv_data = skcp_on_recv_data;

        skt_switcher_add(skcp);
    }

    g_ctx->chan = skt_switch();
    // g_ctx->skcp = chan->skcp;

    // g_ctx->skcp = skcp_init(skcp_conf, loop, g_ctx, SKCP_MODE_CLI);
    // if (NULL == g_ctx->skcp) {
    //     skt_proxy_client_free();
    //     return -1;
    // };

    // g_ctx->skcp->conf->on_close = skcp_on_close;
    // g_ctx->skcp->conf->on_recv_cid = skcp_on_recv_cid;
    // g_ctx->skcp->conf->on_recv_data = skcp_on_recv_data;

    // g_ctx->cid = 0;

    // 定时
    g_ctx->bt_watcher = malloc(sizeof(ev_timer));
    // g_ctx->bt_watcher->data = g_ctx->skcp;
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

    skt_switcher_iter(free_iter_fn);

    if (g_ctx->etcp) {
        etcp_free_server(g_ctx->etcp);
    }

    skt_switcher_free();

    FREE_IF(g_ctx);
}