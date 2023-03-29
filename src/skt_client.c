#include "skt_client.h"

#include <netinet/ip.h>
#include <unistd.h>

#include "skt_protocol.h"
#include "skt_switcher.h"
#include "skt_tuntap.h"
#include "skt_utils.h"

struct skt_cli_s {
    char *tun_ip;
    char *tun_mask;
    struct ev_loop *loop;
    // skcp_t *skcp;
    // uint32_t cid;
    skt_channel_t *chan;
    struct ev_timer *bt_watcher;
    struct ev_io *r_watcher;
    // struct ev_io *w_watcher;
    int tun_fd;
};
typedef struct skt_cli_s skt_cli_t;

static skt_cli_t *g_ctx = NULL;

//////////////////////

static void tun_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    if (EV_ERROR & revents) {
        LOG_E("tun_read_cb got invalid event");
        return;
    }
    // skcp_t *skcp = (skcp_t *)(watcher->data);

    char buf[1500];
    int len = skt_tuntap_read(g_ctx->tun_fd, buf, 1500);
    if (len <= 0) {
        LOG_E("skt_tuntap_read error tun_fd: %d", g_ctx->tun_fd);
        return;
    }

    if (g_ctx->chan->cid <= 0) {
        LOG_E("tun_read_cb g_ctx->cid error : %u", g_ctx->chan->cid);
        return;
    }

    char *seg_raw = NULL;
    int seg_raw_len = 0;
    SKT_ENCODE_SEG(seg_raw, 0, SKT_SEG_DATA, buf, len, seg_raw_len);
    int rt = skcp_send(g_ctx->chan->skcp, g_ctx->chan->cid, seg_raw, seg_raw_len);
    FREE_IF(seg_raw);
    if (rt < 0) {
        LOG_E("skcp_send error cid: %u", g_ctx->chan->cid);
        return;
    }

    // struct ip *ip = (struct ip *)buf;
    // char src_ip[20] = {0};
    // char dest_ip[20] = {0};
    // inet_ntop(AF_INET, &(ip->ip_src.s_addr), src_ip, sizeof(src_ip));
    // inet_ntop(AF_INET, &(ip->ip_dst.s_addr), dest_ip, sizeof(dest_ip));
    // LOG_D("tun_read_cb src_ip: %s dest_ip: %s", src_ip, dest_ip);

    // if (g_ctx->data_conn) {
    //     int rt = skt_kcp_send_data(skt_kcp, g_ctx->data_conn->htkey, buf, len);
    //     if (rt < 0) {
    //         LOG_E("skt_kcp_send_data error htkey: %s", g_ctx->data_conn->htkey);
    //         return;
    //     }
    //     // LOG_D("<<<<<< tun_read_cb send ok len: %d", len);
    // }
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
        int w_len = skt_tuntap_write(g_ctx->tun_fd, seg->payload, seg->payload_len);
        FREE_IF(seg);
        if (w_len < 0) {
            LOG_E("skt_tuntap_write error tun_fd: %d", g_ctx->tun_fd);
            return;
        }
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

    skt_switcher_iter(beat_cb_iter_fn);
}

static int init_vpn_cli() {
    char dev_name[32] = {0};
    int utunfd = skt_tuntap_open(dev_name, 32);

    if (utunfd == -1) {
        LOG_E("open tuntap error");
        return -1;
    }

    // 设置为非阻塞
    setnonblock(utunfd);

    skt_tuntap_setup(dev_name, g_ctx->tun_ip, g_ctx->tun_mask);

    return utunfd;
}

static void free_iter_fn(skt_channel_t *chan) {
    if (chan && chan->skcp) {
        skcp_free(chan->skcp);
    }
}

//////////////////////

void skt_client_free() {
    if (NULL == g_ctx) {
        return;
    }

    if (g_ctx->r_watcher) {
        ev_io_stop(g_ctx->loop, g_ctx->r_watcher);
        FREE_IF(g_ctx->r_watcher);
    }

    if (g_ctx->bt_watcher) {
        ev_timer_stop(g_ctx->loop, g_ctx->bt_watcher);
        FREE_IF(g_ctx->bt_watcher);
    }

    if (g_ctx->tun_fd >= 0) {
        close(g_ctx->tun_fd);
        g_ctx->tun_fd = -1;
    }

    skt_switcher_iter(free_iter_fn);

    skt_switcher_free();

    FREE_IF(g_ctx);
}

int skt_client_init(skcp_conf_t **skcp_conf_arr, size_t skcp_conf_sz, struct ev_loop *loop, char *tun_ip,
                    char *tun_mask) {
    g_ctx = malloc(sizeof(skt_cli_t));
    g_ctx->tun_ip = tun_ip;
    g_ctx->tun_mask = tun_mask;
    g_ctx->loop = loop;

    g_ctx->tun_fd = init_vpn_cli();
    if (g_ctx->tun_fd < 0) {
        skt_client_free();
        return -1;
    }

    // g_ctx->skcp = skcp_init(skcp_conf, loop, g_ctx, SKCP_MODE_CLI);
    // if (NULL == g_ctx->skcp) {
    //     skt_client_free();
    //     return -1;
    // };

    // g_ctx->skcp->conf->on_close = skcp_on_close;
    // g_ctx->skcp->conf->on_recv_cid = skcp_on_recv_cid;
    // g_ctx->skcp->conf->on_recv_data = skcp_on_recv_data;

    // g_ctx->cid = 0;

    skt_switcher_init();

    for (size_t i = 0; i < skcp_conf_sz; i++) {
        skcp_conf_t *skcp_conf = skcp_conf_arr[i];
        skcp_t *skcp = skcp_init(skcp_conf, loop, g_ctx, SKCP_MODE_CLI);
        if (NULL == skcp) {
            skt_client_free();
            return -1;
        };

        skcp->conf->on_close = skcp_on_close;
        skcp->conf->on_recv_cid = skcp_on_recv_cid;
        skcp->conf->on_recv_data = skcp_on_recv_data;

        skt_switcher_add(skcp);
    }

    g_ctx->chan = skt_switch();

    // 定时
    g_ctx->bt_watcher = malloc(sizeof(ev_timer));
    // g_ctx->bt_watcher->data = g_ctx->skcp;
    ev_init(g_ctx->bt_watcher, beat_cb);
    ev_timer_set(g_ctx->bt_watcher, 0, 1);
    ev_timer_start(g_ctx->loop, g_ctx->bt_watcher);

    // 设置tun读事件循环
    g_ctx->r_watcher = malloc(sizeof(struct ev_io));
    // g_ctx->r_watcher->data = g_ctx->skcp;
    ev_io_init(g_ctx->r_watcher, tun_read_cb, g_ctx->tun_fd, EV_READ);
    ev_io_start(g_ctx->loop, g_ctx->r_watcher);

    // // 设置tun写事件循环
    // g_ctx->w_watcher = malloc(sizeof(struct ev_io));
    // g_ctx->w_watcher->data = skt_kcp;
    // ev_io_init(g_ctx->w_watcher, tun_write_cb, g_ctx->tun_fd, EV_WRITE);
    // ev_io_start(g_ctx->loop, g_ctx->w_watcher);

    return 0;
}
