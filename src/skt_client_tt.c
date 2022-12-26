#include "skt_client_tt.h"

#include "skt_cipher.h"
#include "skt_config.h"
#include "skt_utils.h"

struct skt_cli_tt_s {
    skt_cli_tt_conf_t *conf;
    struct ev_loop *loop;
    skt_kcp_t *skt_kcp;

    // uint32_t rtt_cnt;
    // int max_rtt;
    // int min_rtt;
    // int avg_rtt;
    // int sum_rtt;
    // int last_avg_rtt;
    // skcp_conn_t *ht_conn;
    // struct ev_timer *ht_watcher;
};

static skt_cli_tt_t *g_cli = NULL;
static char *iv = "667b02a85c61c786def4521b060265e8";  // TODO: 动态生成

//////////////////////

static int kcp_recv_data_cb(skcp_conn_t *kcp_conn, char *buf, int len) {
    char htkey[SKCP_HTKEY_LEN] = {0};
    skt_kcp_gen_htkey(htkey, SKCP_HTKEY_LEN, kcp_conn->sess_id, NULL);

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

static skt_cli_tt_t *client_init(skt_cli_tt_conf_t *conf, struct ev_loop *loop) {
    g_cli = malloc(sizeof(skt_cli_tt_t));
    g_cli->conf = conf;
    g_cli->loop = loop;

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

    return g_cli;
}

static void client_free() {
    if (NULL == g_cli) {
        return;
    }

    if (g_cli->skt_kcp) {
        skt_kcp_free(g_cli->skt_kcp);
        g_cli->skt_kcp = NULL;
    }

    FREE_IF(g_cli);
}

//////////////////////

skt_cli_tt_t *skt_start_client_tt(struct ev_loop *loop, const char *conf_file) {}