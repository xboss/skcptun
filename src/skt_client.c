#include "skt_client.h"

#include <limits.h>

#include "skt_cipher.h"
#include "skt_utils.h"

static skt_cli_t *g_cli = NULL;
static skcp_conn_t *stat_conns[SKT_REMOTE_SERV_MAX_CNT] = {0};
static char *iv = "667b02a85c61c786def4521b060265e8";  // TODO: 动态生成

static void stat_rtt(skcp_conn_t *conn, const char *kcp_recv_buf) {
    skt_kcp_conn_t *kcp_conn = (skt_kcp_conn_t *)conn->user_data;
    skt_kcp_stat_t *stat = kcp_conn->skt_kcp->stat;

    stat->rtt_cnt = stat->rtt_cnt >= INT_MAX ? 0 : stat->rtt_cnt + 1;
    if (stat->rtt_cnt >= 1000000) {
        stat->rtt_cnt = 0;
        stat->max_rtt = 0;
        stat->min_rtt = INT_MAX;
        stat->avg_rtt = 0;
        stat->sum_rtt = 0;
    }
    stat->rtt_cnt++;

    char *pEnd = NULL;
    uint64_t pitm = strtoull(kcp_recv_buf, &pEnd, 10);
    uint64_t potm = strtoull(pEnd, NULL, 10);
    uint64_t now = getmillisecond();
    uint64_t rtt = now - pitm;
    stat->sum_rtt += rtt;
    stat->avg_rtt = stat->sum_rtt / stat->rtt_cnt;
    stat->max_rtt = rtt > stat->max_rtt ? rtt : stat->max_rtt;
    stat->min_rtt = rtt < stat->min_rtt ? rtt : stat->min_rtt;
    stat->last_rtt = rtt;

    LOG_D("stat_rtt pitm: %lld now: %lld", pitm, now);
    LOG_D("stat_rtt kcp_recv_buf: %s", kcp_recv_buf);

    LOG_D("stat_rtt htkey: %s min_rtt: %d max_rtt: %d avg_rtt: %d crrent_rtt: %d ", conn->htkey, stat->min_rtt,
          stat->max_rtt, stat->avg_rtt, stat->last_rtt);
    // if (stat->last_rtt > stat->avg_rtt) {
    //     LOG_I("stat sess_id: %u min_rtt: %d max_rtt: %d avg_rtt: %d crrent_rtt: %d", conn->sess_id, stat->min_rtt,
    //           stat->max_rtt, stat->avg_rtt, stat->last_rtt);
    // }
}

static void tcp_accept_cb(skt_tcp_conn_t *tcp_conn) {
    LOG_D("tcp serv accept_conn_cb fd:%d", tcp_conn->fd);

    // skt_route_entity_t *entity = NULL;
    // SKT_ROUTE_NEW_ENTITY(entity, tcp_conn->fd, kcp_conn->htkey, kcp_conn, tcp_conn, NULL);
    skt_route_entity_t *entity = skt_route_switch(g_cli->route, g_cli->skt_kcp, g_cli->skt_kcp_cnt);
    if (!entity) {
        LOG_E("tcp serv accept_conn_cb skt_route_switch error fd:%d", tcp_conn->fd);
        return;
    }

    skcp_conn_t *kcp_conn = skt_kcp_new_conn(entity->skt_kcp, 0, &entity->skt_kcp->servaddr);
    if (NULL == kcp_conn) {
        return;
    }

    entity->tcp_fd = tcp_conn->fd;
    entity->htkey = kcp_conn->htkey;

    if (skt_route_add(g_cli->route, entity) != 0) {
        LOG_E("tcp serv accept_conn_cb skt_route_add error fd:%d", tcp_conn->fd);
        return;
    }

    return;
}
static void tcp_close_cb(skt_tcp_conn_t *tcp_conn) {
    // if (NULL == g_cli->cur_skt_kcp) {
    //     return;
    // }

    // char htkey[SKCP_HTKEY_LEN] = {0};
    // skt_kcp_gen_htkey(htkey, SKCP_HTKEY_LEN, tcp_conn->sess_id, NULL);
    // skcp_conn_t *kcp_conn = skt_kcp_get_conn(g_cli->cur_skt_kcp, htkey);
    skt_route_entity_t *entity = skt_route_t2k(g_cli->route, tcp_conn->fd);
    if (NULL == entity) {
        LOG_E("tcp_close_cb entity error");
        return;
    }
    skcp_conn_t *kcp_conn = skt_kcp_get_conn(entity->skt_kcp, entity->htkey);

    if (NULL == kcp_conn) {
        return;
    }

    skt_kcp_close_conn(kcp_conn);

    return;
}

static void tcp_recv_cb(skt_tcp_conn_t *tcp_conn, const char *buf, int len) {
    // char htkey[SKCP_HTKEY_LEN] = {0};
    // skt_kcp_gen_htkey(htkey, SKCP_HTKEY_LEN, tcp_conn->sess_id, NULL);
    // skcp_conn_t *kcp_conn = skt_kcp_get_conn(g_cli->cur_skt_kcp, htkey);
    skt_route_entity_t *entity = skt_route_t2k(g_cli->route, tcp_conn->fd);
    if (NULL == entity) {
        LOG_E("tcp_recv_cb entity error");
        return;
    }
    skcp_conn_t *kcp_conn = skt_kcp_get_conn(entity->skt_kcp, entity->htkey);
    if (NULL == kcp_conn) {
        LOG_D("tcp_recv_cb kcp_conn is NULL fd:%u", tcp_conn->fd);
        return;
    }

    LOG_D("tcp_recv_cb tcpfd: %d htkey: %s kcpfd: %d", tcp_conn->fd, kcp_conn->htkey, entity->skt_kcp->fd);
    int rt = skt_kcp_send(entity->skt_kcp, kcp_conn->htkey, buf, len);
    if (rt < 0) {
        skt_kcp_close_conn(kcp_conn);
        skt_tcp_close_conn(tcp_conn);
        return;
    }

    return;
}

//////////////////////

static int kcp_recv_cb(skcp_conn_t *kcp_conn, char *buf, int len) {
    // TODO: stat
    if (kcp_conn->tag == SKCP_CONN_TAG_STAT) {
        if (len <= 6) {
            LOG_E("kcp_recv_cb stat len: %d", len);
            return SKT_ERROR;
        }
        char *p = buf + 5;
        stat_rtt(kcp_conn, p);
        return SKT_OK;
    }

    // for (int i = 0; i < g_cli->skt_kcp_cnt; i++) {
    //     LOG_D("kcp_recv_cb stat htkey:%s %s", stat_conns[i]->htkey, kcp_conn->htkey);
    //     if (strcmp(stat_conns[i]->htkey, kcp_conn->htkey) == 0) {
    //         stat_rtt(kcp_conn, buf);
    //     }
    // }

    // char htkey[SKCP_HTKEY_LEN] = {0};
    // skt_kcp_gen_htkey(htkey, SKCP_HTKEY_LEN, kcp_conn->sess_id, NULL);

    // skt_tcp_conn_t *tcp_conn = skt_tcp_get_conn(g_cli->skt_tcp, ((skt_kcp_conn_t *)(kcp_conn->user_data))->tcp_fd);
    skt_route_entity_t *entity = skt_route_k2t(g_cli->route, kcp_conn->htkey);
    if (NULL == entity) {
        LOG_E("kcp_recv_cb entity error");
        return SKT_ERROR;
    }
    skt_tcp_conn_t *tcp_conn = skt_tcp_get_conn(g_cli->skt_tcp, entity->tcp_fd);
    if (NULL == tcp_conn) {
        skt_kcp_close_conn(kcp_conn);
        return SKT_ERROR;
    }

    // LOG_D("kcp_recv_cb tcpfd: %d htkey: %s kcpfd: %d", tcp_conn->fd, kcp_conn->htkey,
    //       ((skt_kcp_conn_t *)(kcp_conn->user_data))->skt_kcp->fd);

    ssize_t rt = skt_tcp_send(tcp_conn, buf, len);
    if (rt < 0) {
        skt_kcp_close_conn(kcp_conn);
        skt_tcp_close_conn(tcp_conn);
        return SKT_ERROR;
    }

    return SKT_OK;
}

static void kcp_close_cb(skcp_conn_t *kcp_conn) {
    LOG_D("kcp_close_cb");

    if (NULL == g_cli->skt_tcp) {
        return;
    }

    // 处理stat连接
    if (kcp_conn->tag != SKCP_CONN_TAG_NORM) {
        return;
    }

    // skt_tcp_conn_t *tcp_conn = skt_tcp_get_conn(g_cli->skt_tcp, kcp_conn->tcp_fd);
    skt_route_entity_t *entity = skt_route_k2t(g_cli->route, kcp_conn->htkey);
    if (NULL == entity) {
        LOG_E("kcp_close_cb entity error");
        return;
    }
    skt_tcp_conn_t *tcp_conn = skt_tcp_get_conn(g_cli->skt_tcp, entity->tcp_fd);
    if (NULL == tcp_conn) {
        return;
    }
    skt_tcp_close_conn(tcp_conn);

    return;
}

static char *kcp_encrypt_cb(skt_kcp_t *skt_kcp, const char *in, int in_len, int *out_len) {
    int padding_size = in_len;
    char *after_padding_buf = (char *)in;
    if (in_len % 16 != 0) {
        after_padding_buf = skt_cipher_padding(in, in_len, &padding_size);
    }
    *out_len = padding_size;

    char *out_buf = malloc(padding_size);
    memset(out_buf, 0, padding_size);
    skt_aes_cbc_encrpyt(after_padding_buf, &out_buf, padding_size, skt_kcp->conf->key, iv);
    if (in_len % 16 != 0) {
        FREE_IF(after_padding_buf);
    }
    return out_buf;
}

static char *kcp_decrypt_cb(skt_kcp_t *skt_kcp, const char *in, int in_len, int *out_len) {
    int padding_size = in_len;
    char *after_padding_buf = (char *)in;
    if (in_len % 16 != 0) {
        after_padding_buf = skt_cipher_padding(in, in_len, &padding_size);
    }
    *out_len = padding_size;

    char *out_buf = malloc(padding_size);
    memset(out_buf, 0, padding_size);
    skt_aes_cbc_decrpyt(after_padding_buf, &out_buf, padding_size, skt_kcp->conf->key, iv);
    if (in_len % 16 != 0) {
        FREE_IF(after_padding_buf);
    }
    return out_buf;
}

// stat 回调
static void stat_cb(struct ev_loop *loop, ev_timer *watcher, int revents) {
    if (EV_ERROR & revents) {
        LOG_E("stat_cb got invalid event");
        return;
    }
    // skt_kcp_t *skt_kcp = (skt_kcp_t *)(watcher->data);

    // char *buf = NULL;
    const int len = 32;
    char buf[len] = {0};
    snprintf(buf, len, "stat %llu", getmillisecond());
    LOG_D("stat_cb buf:%s", buf);
    for (int i = 0; i < g_cli->skt_kcp_cnt; i++) {
        skt_kcp_t *skt_kcp = g_cli->skt_kcp[i];
        int rt = skt_kcp_send(skt_kcp, stat_conns[i]->htkey, buf, len);
        if (rt < 0) {
            LOG_E("stat_cb kcp_send error rt: %d", rt);
            skt_kcp->stat->last_rtt = INT_MAX;
            continue;
        }
        LOG_D("stat_cb send rt:%d", rt);
    }

    // int rt = skt_kcp_send(((skt_kcp_conn_t *)(kcp_conn->user_data))->skt_kcp, kcp_conn->htkey, buf, len);
}

//////////////////////

void skt_client_free() {
    if (NULL == g_cli) {
        return;
    }

    if (g_cli->stat_watcher) {
        ev_timer_stop(g_cli->loop, g_cli->stat_watcher);
        FREE_IF(g_cli->stat_watcher);
    }

    for (int i = 0; i < g_cli->skt_kcp_cnt; i++) {
        if (g_cli->skt_kcp[i]) {
            skt_kcp_free(g_cli->skt_kcp[i]);
            g_cli->skt_kcp[i] = NULL;
        }
    }

    if (g_cli->skt_tcp) {
        skt_tcp_free(g_cli->skt_tcp);
        g_cli->skt_tcp = NULL;
    }

    if (g_cli->route) {
        skt_route_free(g_cli->route);
    }

    FREE_IF(g_cli);
}

skt_cli_t *skt_client_init(skt_cli_conf_t *conf, struct ev_loop *loop) {
    conf->tcp_conf->accept_cb = tcp_accept_cb;
    conf->tcp_conf->close_cb = tcp_close_cb;
    conf->tcp_conf->recv_cb = tcp_recv_cb;
    conf->tcp_conf->timeout_cb = NULL;
    conf->tcp_conf->mode = SKT_TCP_MODE_SERV;

    g_cli = malloc(sizeof(skt_cli_t));
    g_cli->conf = conf;
    g_cli->loop = loop;

    skt_tcp_t *tcp_serv = skt_tcp_init(conf->tcp_conf, loop);
    if (NULL == tcp_serv) {
        LOG_E("start tcp server error addr:%s port:%u", conf->tcp_conf->serv_addr, conf->tcp_conf->serv_port);
        skt_client_free();
        return NULL;
    }
    g_cli->skt_tcp = tcp_serv;

    g_cli->skt_kcp_cnt = conf->kcp_conf_cnt;
    memset(g_cli->skt_kcp, 0, SKT_REMOTE_SERV_MAX_CNT);
    for (int i = 0; i < conf->kcp_conf_cnt; i++) {
        skt_kcp_t *skt_kcp = skt_kcp_init(conf->kcp_conf[i], loop, g_cli, SKCP_MODE_CLI);
        if (NULL == skt_kcp) {
            skt_client_free();
            return NULL;
        };
        // skt_kcp->conn_timeout_cb = NULL;
        skt_kcp->new_conn_cb = NULL;
        skt_kcp->conn_close_cb = kcp_close_cb;
        skt_kcp->kcp_recv_cb = kcp_recv_cb;
        if (conf->kcp_conf[i]->key != NULL) {
            skt_kcp->encrypt_cb = kcp_encrypt_cb;
            skt_kcp->decrypt_cb = kcp_decrypt_cb;
        } else {
            skt_kcp->encrypt_cb = NULL;
            skt_kcp->decrypt_cb = NULL;
        }

        g_cli->skt_kcp[i] = skt_kcp;

        stat_conns[i] = skt_kcp_new_conn(skt_kcp, 0, &skt_kcp->servaddr);
        stat_conns[i]->tag = SKCP_CONN_TAG_STAT;
        LOG_D("skt_client_init kcpfd: %d %s %u", skt_kcp->fd, skt_kcp->conf->addr, skt_kcp->conf->port);
    }

    // 设置stat定时循环
    g_cli->stat_watcher = malloc(sizeof(ev_timer));
    // g_cli->stat_watcher->data = skt_kcp;
    ev_init(g_cli->stat_watcher, stat_cb);
    ev_timer_set(g_cli->stat_watcher, 0, 1);
    ev_timer_start(g_cli->loop, g_cli->stat_watcher);
    LOG_D("start stat_watcher");

    // g_cli->cur_skt_kcp = g_cli->skt_kcp[0];

    g_cli->route = skt_route_init();

    // skt_kcp_t *skt_kcp = skt_kcp_init(conf->kcp_conf, loop, g_cli, SKCP_MODE_CLI);
    // if (NULL == skt_kcp) {
    //     FREE_IF(g_cli);
    //     return NULL;
    // };
    // // skt_kcp->conn_timeout_cb = NULL;
    // skt_kcp->new_conn_cb = NULL;
    // skt_kcp->conn_close_cb = kcp_close_cb;
    // skt_kcp->kcp_recv_cb = kcp_recv_cb;
    // if (conf->kcp_conf->key != NULL) {
    //     skt_kcp->encrypt_cb = kcp_encrypt_cb;
    //     skt_kcp->decrypt_cb = kcp_decrypt_cb;
    // } else {
    //     skt_kcp->encrypt_cb = NULL;
    //     skt_kcp->decrypt_cb = NULL;
    // }

    // g_cli->skt_kcp = skt_kcp;

    return g_cli;
}
