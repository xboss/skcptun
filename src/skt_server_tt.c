#include "skt_server_tt.h"

#include <unistd.h>

#include "skt_cipher.h"
#include "skt_config.h"
#include "skt_tuntap.h"
#include "skt_utils.h"

struct skt_serv_s {
    skt_serv_tt_conf_t *conf;
    struct ev_loop *loop;
    skt_kcp_t *skt_kcp;
    skcp_conn_t *data_conn;
    struct ev_timer *bt_watcher;
    struct ev_io *r_watcher;
    struct ev_io *w_watcher;
    int tun_fd;

    // uint32_t rtt_cnt;
    // int max_rtt;
    // int min_rtt;
    // int avg_rtt;
    // int sum_rtt;
    // int last_avg_rtt;
    // skcp_conn_t *ht_conn;
    // struct ev_timer *ht_watcher;
};
typedef struct skt_serv_s skt_serv_t;

static skt_serv_t *g_ctx = NULL;
static char *iv = "667b02a85c61c580def4521b060265e8";  // TODO: 动态生成

//////////////////////

// static void tun_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
//     if (EV_ERROR & revents) {
//         LOG_E("tun_write_cb got invalid event");
//         return;
//     }
//     skt_kcp_t *skt_kcp = (skt_kcp_t *)(watcher->data);
// }

static void tun_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    if (EV_ERROR & revents) {
        LOG_E("tun_read_cb got invalid event");
        return;
    }
    skt_kcp_t *skt_kcp = (skt_kcp_t *)(watcher->data);

    char buf[1500];
    int len = skt_tuntap_read(g_ctx->tun_fd, buf, 1500);
    if (len <= 0) {
        LOG_E("skt_tuntap_read error tun_fd: %d", g_ctx->tun_fd);
        return;
    }

    for (int i = 0; i < len; i++) {
        printf("%02x ", (buf[i] & 0xFF));
        if ((i - 4) % 16 == 15) printf("\n");
    }
    printf("\n");

    char src_ip[20] = {0};
    char dest_ip[20] = {0};
    inet_ntop(AF_INET, buf + 12, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, buf + 16, dest_ip, sizeof(dest_ip));
    printf("tun_read_cb src_ip: %s dest_ip: %s\n", src_ip, dest_ip);

    if (g_ctx->data_conn) {
        int rt = skt_kcp_send_data(skt_kcp, g_ctx->data_conn->htkey, buf, len);
        if (rt < 0) {
            LOG_E("skt_kcp_send_data error htkey: %s", g_ctx->data_conn->htkey);
            return;
        }
    }
}

//////////////////////

static void kcp_new_conn_cb(skcp_conn_t *kcp_conn) {
    if (!g_ctx->data_conn) {
        g_ctx->data_conn = kcp_conn;
        LOG_I("new data conn by kcp_new_conn_cb");
        return;
    }
    return;
}

static int kcp_recv_data_cb(skcp_conn_t *kcp_conn, char *buf, int len) {
    // char htkey[SKCP_HTKEY_LEN] = {0};
    // skt_kcp_gen_htkey(htkey, SKCP_HTKEY_LEN, kcp_conn->sess_id, NULL);

    for (int i = 0; i < len; i++) {
        printf("%02x ", (buf[i] & 0xFF));
        if ((i - 4) % 16 == 15) printf("\n");
    }
    printf("buf_len: %d\n", len);

    char src_ip[20] = {0};
    char dest_ip[20] = {0};
    inet_ntop(AF_INET, buf + 12, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, buf + 16, dest_ip, sizeof(dest_ip));
    printf("kcp_recv_data_cb src_ip: %s dest_ip: %s\n", src_ip, dest_ip);

    // char bbb[1024] = {0};
    // memcpy(bbb + 4, buf, len);
    int w_len = skt_tuntap_write(g_ctx->tun_fd, buf, len);
    if (w_len < 0) {
        LOG_E("skt_tuntap_write error tun_fd: %d", g_ctx->tun_fd);
        return SKT_ERROR;
    }
    printf("w_len: %d\n", w_len);

    return SKT_OK;
}

static int kcp_recv_ctrl_cb(skcp_conn_t *kcp_conn, char *buf, int len) {
    // if (buf && len > 3 && buf[0] == 's' && buf[1] == ' ') {
    //     // stat msg
    //     stat_rtt(kcp_conn, buf);
    //     return SKT_OK;
    // }

    return SKT_OK;
}

static void kcp_close_cb(skt_kcp_conn_t *kcp_conn) {
    LOG_D("kcp_close_cb");
    // if (kcp_conn->tag == 0) {
    //     // data conn
    //     // g_ctx->data_conn = NULL;
    //     // reconnect
    //     g_ctx->data_conn = skt_kcp_new_conn(g_ctx->skt_kcp, 0, NULL);
    //     LOG_I("new data conn by reconnect");
    // }

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

// static void beat_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents) {
//     if (EV_ERROR & revents) {
//         LOG_E("init_cb got invalid event");
//         return;
//     }

//     skt_kcp_t *skt_kcp = (skt_kcp_t *)watcher->data;

//     if (!g_ctx->data_conn) {
//         g_ctx->data_conn = skt_kcp_new_conn(skt_kcp, 0, NULL);
//         LOG_I("new data conn by beat_cb");
//         return;
//     }
// }

static int init_vpn_serv() {
    char dev_name[32] = {0};
    int utunfd = skt_tuntap_open(dev_name, 32);

    if (utunfd == -1) {
        LOG_E("open tuntap error");
        return -1;
    }

    skt_tuntap_setup(dev_name, "192.168.2.2");

    return utunfd;
}

//////////////////////

int skt_server_tt_init(skt_serv_tt_conf_t *conf, struct ev_loop *loop) {
    g_ctx = malloc(sizeof(skt_serv_t));
    g_ctx->conf = conf;
    g_ctx->loop = loop;

    g_ctx->tun_fd = init_vpn_serv();
    if (g_ctx->tun_fd < 0) {
        return -1;
    }

    skt_kcp_t *skt_kcp = skt_kcp_init(conf->kcp_conf, loop, g_ctx, SKCP_MODE_SERV);
    if (NULL == skt_kcp) {
        FREE_IF(g_ctx);
        return -1;
    };
    // skt_kcp->conn_timeout_cb = NULL;
    skt_kcp->new_conn_cb = kcp_new_conn_cb;
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

    // // 定时
    // g_ctx->data_conn = kcp_new_conn_cb;
    // g_ctx->bt_watcher = malloc(sizeof(ev_timer));
    // g_ctx->bt_watcher->data = skt_kcp;
    // ev_init(g_ctx->bt_watcher, beat_cb);
    // ev_timer_set(g_ctx->bt_watcher, 0, 1);
    // ev_timer_start(skt_kcp->loop, g_ctx->bt_watcher);

    // 设置tun读事件循环
    g_ctx->r_watcher = malloc(sizeof(struct ev_io));
    g_ctx->r_watcher->data = skt_kcp;
    ev_io_init(g_ctx->r_watcher, tun_read_cb, g_ctx->tun_fd, EV_READ);
    ev_io_start(g_ctx->loop, g_ctx->r_watcher);

    // // 设置tun写事件循环
    // g_ctx->w_watcher = malloc(sizeof(struct ev_io));
    // g_ctx->w_watcher->data = skt_kcp;
    // ev_io_init(g_ctx->w_watcher, tun_write_cb, g_ctx->tun_fd, EV_WRITE);
    // ev_io_start(g_ctx->loop, g_ctx->w_watcher);

    g_ctx->skt_kcp = skt_kcp;

    return 0;
}

void skt_server_tt_free() {
    if (NULL == g_ctx) {
        return;
    }

    if (g_ctx->tun_fd >= 0) {
        close(g_ctx->tun_fd);
        g_ctx->tun_fd = -1;
    }

    if (g_ctx->skt_kcp) {
        skt_kcp_free(g_ctx->skt_kcp);
        g_ctx->skt_kcp = NULL;
    }

    FREE_IF(g_ctx);
}