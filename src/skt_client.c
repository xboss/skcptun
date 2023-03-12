#include "skt_client.h"

#include <netinet/ip.h>
#include <unistd.h>

#include "skt_protocol.h"
#include "skt_tuntap.h"
#include "skt_utils.h"

struct skt_cli_s {
    skt_cli_conf_t *conf;
    struct ev_loop *loop;
    skcp_t *skcp;
    uint32_t cid;
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
    skcp_t *skcp = (skcp_t *)(watcher->data);

    char buf[1500];
    int len = skt_tuntap_read(g_ctx->tun_fd, buf, 1500);
    if (len <= 0) {
        LOG_E("skt_tuntap_read error tun_fd: %d", g_ctx->tun_fd);
        return;
    }

    if (g_ctx->cid <= 0) {
        LOG_E("tun_read_cb g_ctx->cid error : %u", g_ctx->cid);
        return;
    }

    char *seg_raw = NULL;
    int seg_raw_len = 0;
    SKT_ENCODE_SEG(seg_raw, 0, SKT_SEG_DATA, buf, len, seg_raw_len);
    int rt = skcp_send(g_ctx->skcp, g_ctx->cid, seg_raw, seg_raw_len);
    FREE_IF(seg_raw);
    if (rt < 0) {
        LOG_E("skcp_send error cid: %u", g_ctx->cid);
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

//////////////////////

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

static int init_vpn_cli() {
    char dev_name[32] = {0};
    int utunfd = skt_tuntap_open(dev_name, 32);

    if (utunfd == -1) {
        LOG_E("open tuntap error");
        return -1;
    }

    // 设置为非阻塞
    setnonblock(utunfd);

    skt_tuntap_setup(dev_name, g_ctx->conf->tun_ip, g_ctx->conf->tun_mask);

    return utunfd;
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

    if (g_ctx->cid > 0) {
        skcp_close_conn(g_ctx->skcp, g_ctx->cid);
    }

    if (g_ctx->skcp) {
        skcp_free(g_ctx->skcp);
        g_ctx->skcp = NULL;
    }

    FREE_IF(g_ctx);
}

int skt_client_init(skt_cli_conf_t *conf, struct ev_loop *loop) {
    g_ctx = malloc(sizeof(skt_cli_t));
    g_ctx->conf = conf;
    g_ctx->loop = loop;

    g_ctx->tun_fd = init_vpn_cli();
    if (g_ctx->tun_fd < 0) {
        skt_client_free();
        return -1;
    }

    g_ctx->skcp = skcp_init(conf->skcp_conf, loop, g_ctx, SKCP_MODE_CLI);
    if (NULL == g_ctx->skcp) {
        skt_client_free();
        return -1;
    };

    conf->skcp_conf->on_close = skcp_on_close;
    conf->skcp_conf->on_recv_cid = skcp_on_recv_cid;
    conf->skcp_conf->on_recv_data = skcp_on_recv_data;

    g_ctx->cid = 0;

    // 定时
    g_ctx->bt_watcher = malloc(sizeof(ev_timer));
    g_ctx->bt_watcher->data = g_ctx->skcp;
    ev_init(g_ctx->bt_watcher, beat_cb);
    ev_timer_set(g_ctx->bt_watcher, 0, 1);
    ev_timer_start(g_ctx->loop, g_ctx->bt_watcher);

    // 设置tun读事件循环
    g_ctx->r_watcher = malloc(sizeof(struct ev_io));
    g_ctx->r_watcher->data = g_ctx->skcp;
    ev_io_init(g_ctx->r_watcher, tun_read_cb, g_ctx->tun_fd, EV_READ);
    ev_io_start(g_ctx->loop, g_ctx->r_watcher);

    // // 设置tun写事件循环
    // g_ctx->w_watcher = malloc(sizeof(struct ev_io));
    // g_ctx->w_watcher->data = skt_kcp;
    // ev_io_init(g_ctx->w_watcher, tun_write_cb, g_ctx->tun_fd, EV_WRITE);
    // ev_io_start(g_ctx->loop, g_ctx->w_watcher);

    return 0;
}
