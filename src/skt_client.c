#include "skt_client.h"

#include "skt_cipher.h"
#include "skt_utils.h"

static skt_cli_t *g_cli = NULL;
static char *iv = "667b02a85c61c786def4521b060265e8";  // TODO: 动态生成

static void tcp_accept_cb(skt_tcp_conn_t *tcp_conn) {
    LOG_D("tcp serv accept_conn_cb fd:%d", tcp_conn->fd);
    skcp_conn_t *kcp_conn = skt_kcp_new_conn(g_cli->skt_kcp, tcp_conn->sess_id, NULL);
    if (NULL == kcp_conn) {
        return;
    }

    ((skt_kcp_conn_t *)(kcp_conn->user_data))->tcp_fd = tcp_conn->fd;
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

    skt_kcp_close_conn(((skt_kcp_conn_t *)(kcp_conn->user_data))->skt_kcp, htkey);

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

    int rt = skt_kcp_send(((skt_kcp_conn_t *)(kcp_conn->user_data))->skt_kcp, htkey, buf, len);
    if (rt < 0) {
        skt_kcp_close_conn(g_cli->skt_kcp, htkey);
        skt_tcp_close_conn(tcp_conn);
        return;
    }

    return;
}

//////////////////////

static int kcp_recv_cb(skcp_conn_t *kcp_conn, char *buf, int len) {
    char htkey[SKCP_HTKEY_LEN] = {0};
    skt_kcp_gen_htkey(htkey, SKCP_HTKEY_LEN, kcp_conn->sess_id, NULL);

    skt_tcp_conn_t *tcp_conn = skt_tcp_get_conn(g_cli->skt_tcp, ((skt_kcp_conn_t *)(kcp_conn->user_data))->tcp_fd);
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

static void kcp_close_cb(skt_kcp_conn_t *kcp_conn) {
    LOG_D("kcp_close_cb");

    if (NULL == g_cli->skt_tcp) {
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
    skt_kcp->kcp_recv_cb = kcp_recv_cb;
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