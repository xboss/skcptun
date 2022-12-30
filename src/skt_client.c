#include "skt_client.h"

#include <limits.h>

#include "skt_cipher.h"
#include "skt_utils.h"

static skt_cli_t *g_cli = NULL;
static char *iv = "667b02a85c61c786def4521b060265e8";  // TODO: 动态生成

static void reset_stat_rtt() {
    // LOG_I("reset stat rtt rtt_cnt: %u", g_cli->rtt_cnt);
    g_cli->rtt_cnt = 0;
    g_cli->max_rtt = 0;
    g_cli->min_rtt = INT_MAX;
    g_cli->avg_rtt = 0;
    g_cli->sum_rtt = 0;
}
static void stat_rtt(skcp_conn_t *conn, const char *buf) {
    // g_cli->rtt_cnt = g_cli->rtt_cnt >= INT_MAX ? 0 : g_cli->rtt_cnt + 1;
    if (g_cli->rtt_cnt >= 100000000) {
        reset_stat_rtt();
    }
    g_cli->rtt_cnt++;

    char *pEnd = NULL;
    uint64_t itm = strtoull(buf + 2, &pEnd, 10);
    uint64_t otm = strtoull(pEnd, NULL, 10);
    uint64_t now = getmillisecond();
    uint64_t rtt = now - itm;
    g_cli->sum_rtt += rtt;
    g_cli->avg_rtt = g_cli->sum_rtt / g_cli->rtt_cnt;
    g_cli->max_rtt = rtt > g_cli->max_rtt ? rtt : g_cli->max_rtt;
    g_cli->min_rtt = rtt < g_cli->min_rtt ? rtt : g_cli->min_rtt;

    if (abs(g_cli->last_avg_rtt - g_cli->avg_rtt) > 10) {
        LOG_I("stat htkey: %s rtt_cnt: %u min_rtt: %d max_rtt: %d avg_rtt:%d cur_rtt:%llu", conn->htkey, g_cli->rtt_cnt,
              g_cli->min_rtt, g_cli->max_rtt, g_cli->avg_rtt, rtt);
    }
    // LOG_I("stat htkey: %s rtt_cnt: %u min_rtt: %d max_rtt: %d avg_rtt:%d cur_rtt:%llu", conn->htkey, g_cli->rtt_cnt,
    //       g_cli->min_rtt, g_cli->max_rtt, g_cli->avg_rtt, rtt);

    g_cli->last_avg_rtt = g_cli->avg_rtt;
}

static void tcp_accept_cb(skt_tcp_conn_t *tcp_conn) {
    LOG_D("tcp serv accept_conn_cb fd:%d", tcp_conn->fd);

    skcp_conn_t *kcp_conn = skt_kcp_new_conn(g_cli->skt_kcp, tcp_conn->sess_id, NULL);
    if (NULL == kcp_conn) {
        return;
    }

    SKT_GET_KCP_CONN(kcp_conn)->tcp_fd = tcp_conn->fd;
    tcp_conn->sess_id = kcp_conn->sess_id;

    return;
}

static void tcp_close_cb(skt_tcp_conn_t *tcp_conn) {
    if (NULL == g_cli->skt_kcp) {
        return;
    }

    char htkey[SKCP_HTKEY_LEN] = {0};
    skt_kcp_gen_htkey(htkey, SKCP_HTKEY_LEN, tcp_conn->sess_id, NULL);
    skcp_conn_t *kcp_conn = skt_kcp_get_conn(g_cli->skt_kcp, htkey);

    if (NULL == kcp_conn) {
        return;
    }

    skt_kcp_close_conn(SKT_GET_KCP_CONN(kcp_conn)->skt_kcp, htkey);

    return;
}

static void tcp_recv_cb(skt_tcp_conn_t *tcp_conn, const char *buf, int len) {
    char htkey[SKCP_HTKEY_LEN] = {0};
    skt_kcp_gen_htkey(htkey, SKCP_HTKEY_LEN, tcp_conn->sess_id, NULL);
    skcp_conn_t *kcp_conn = skt_kcp_get_conn(g_cli->skt_kcp, htkey);
    if (NULL == kcp_conn) {
        LOG_D("tcp_recv_cb kcp_conn is NULL sess_id:%u", tcp_conn->sess_id);
        return;
    }

    // if (strlen(SKT_GET_KCP_CONN(kcp_conn)->skt_kcp->iv) <= 0) {
    //     skt_kcp_close_conn(SKT_GET_KCP_CONN(kcp_conn)->skt_kcp, kcp_conn->htkey);
    //     skt_tcp_close_conn(tcp_conn);
    // }

    int rt = skt_kcp_send_data(SKT_GET_KCP_CONN(kcp_conn)->skt_kcp, htkey, buf, len);
    if (rt < 0) {
        skt_kcp_close_conn(g_cli->skt_kcp, htkey);
        skt_tcp_close_conn(tcp_conn);
        return;
    }

    return;
}

//////////////////////

static int kcp_recv_data_cb(skcp_conn_t *kcp_conn, char *buf, int len) {
    char htkey[SKCP_HTKEY_LEN] = {0};
    skt_kcp_gen_htkey(htkey, SKCP_HTKEY_LEN, kcp_conn->sess_id, NULL);

    skt_tcp_conn_t *tcp_conn = skt_tcp_get_conn(g_cli->skt_tcp, SKT_GET_KCP_CONN(kcp_conn)->tcp_fd);
    if (NULL == tcp_conn) {
        skt_kcp_close_conn(g_cli->skt_kcp, htkey);
        return SKT_ERROR;
    }

    ssize_t rt = skt_tcp_send(tcp_conn, buf, len);
    if (rt < 0) {
        skt_kcp_close_conn(g_cli->skt_kcp, htkey);
        skt_tcp_close_conn(tcp_conn);
        return SKT_ERROR;
    }

    return SKT_OK;
}

static int kcp_recv_ctrl_cb(skcp_conn_t *kcp_conn, char *buf, int len) {
    if (buf && len > 3 && buf[0] == 's' && buf[1] == ' ') {
        // stat msg
        stat_rtt(kcp_conn, buf);
        return SKT_OK;
    }

    return SKT_OK;
}

static void kcp_close_cb(skt_kcp_conn_t *kcp_conn) {
    LOG_D("kcp_close_cb");

    if (NULL == g_cli->skt_tcp) {
        return;
    }

    if (kcp_conn->tag == SKT_KCP_TAG_HT) {
        g_cli->ht_conn = NULL;
        return;
    }

    skt_tcp_conn_t *tcp_conn = skt_tcp_get_conn(g_cli->skt_tcp, kcp_conn->tcp_fd);
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

//////////////////////

static void healthy_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents) {
    if (EV_ERROR & revents) {
        LOG_E("init_cb got invalid event");
        return;
    }

    skt_kcp_t *skt_kcp = (skt_kcp_t *)watcher->data;

    if (!g_cli->ht_conn) {
        g_cli->ht_conn = skt_kcp_new_conn(skt_kcp, 0, NULL);
        SKT_GET_KCP_CONN(g_cli->ht_conn)->tag = SKT_KCP_TAG_HT;
        reset_stat_rtt();
        // LOG_I("new healthy conn");
        return;
    }

    // stat msg format: "cmd(1B) content(nB)", example: "s 1234567890"
    uint64_t now = getmillisecond();
    char buf[23] = {0};
    snprintf(buf, 23, "s %llu", now);
    skt_kcp_send_ctrl(skt_kcp, g_cli->ht_conn->htkey, buf, strlen(buf));
    // LOG_D("healthy_cb send %s", buf);
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
        FREE_IF(g_cli);
        return NULL;
    }
    g_cli->skt_tcp = tcp_serv;

    skt_kcp_t *skt_kcp = skt_kcp_init(conf->kcp_conf, loop, g_cli, SKCP_MODE_CLI);
    if (NULL == skt_kcp) {
        FREE_IF(g_cli);
        return NULL;
    };
    // skt_kcp->conn_timeout_cb = NULL;
    skt_kcp->new_conn_cb = NULL;
    skt_kcp->conn_close_cb = kcp_close_cb;
    skt_kcp->kcp_recv_data_cb = kcp_recv_data_cb;
    skt_kcp->kcp_recv_ctrl_cb = kcp_recv_ctrl_cb;
    if (conf->kcp_conf->key != NULL) {
        skt_kcp->encrypt_cb = kcp_encrypt_cb;
        skt_kcp->decrypt_cb = kcp_decrypt_cb;
    } else {
        skt_kcp->encrypt_cb = NULL;
        skt_kcp->decrypt_cb = NULL;
    }

    g_cli->skt_kcp = skt_kcp;

    reset_stat_rtt();
    g_cli->ht_conn = NULL;
    g_cli->ht_watcher = malloc(sizeof(ev_timer));
    g_cli->ht_watcher->data = skt_kcp;
    ev_init(g_cli->ht_watcher, healthy_cb);
    ev_timer_set(g_cli->ht_watcher, 0, 1);
    ev_timer_start(skt_kcp->loop, g_cli->ht_watcher);

    return g_cli;
}
void skt_client_free() {
    if (NULL == g_cli) {
        return;
    }

    if (g_cli->skt_kcp) {
        skt_kcp_free(g_cli->skt_kcp);
        g_cli->skt_kcp = NULL;
    }

    if (g_cli->skt_tcp) {
        skt_tcp_free(g_cli->skt_tcp);
        g_cli->skt_tcp = NULL;
    }

    FREE_IF(g_cli);
}