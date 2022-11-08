#include "skt_server.h"

#include "skt_cipher.h"
#include "skt_utils.h"

static skt_serv_t *g_serv = NULL;
static char *iv = "667b02a85c61c786def4521b060265e8";  // TODO: 动态生成

static int tcp_recv_cb(skt_tcp_cli_conn_t *tcp_conn, char *buf, int len) {
    // LOG_D("tcp cli recv:%s", buf);
    LOG_D("tcp cli recv:%d", len);

    skt_kcp_conn_t *kcp_conn = skt_kcp_server_get_conn(g_serv->kcp_serv, tcp_conn->sess_id, &tcp_conn->kcp_cli_addr);
    if (NULL == kcp_conn) {
        LOG_E("tcp_recv_cb kcp_conn error");
        return -1;
    }

    int rt = skt_kcp_server_send(g_serv->kcp_serv, kcp_conn->sess_id, buf, len, &kcp_conn->cliaddr);
    if (SKT_ERROR == rt) {
        skt_kcp_server_close_conn(g_serv->kcp_serv, kcp_conn->sess_id, &tcp_conn->kcp_cli_addr);
        return -1;
    }
    LOG_D("tcp_recv_cb skt_kcp_server_send %u %d %d", kcp_conn->sess_id, rt, len);
    return 0;
}

static void tcp_close_cb(skt_tcp_cli_conn_t *tcp_conn) {
    LOG_D("tcp conn closed fd:%d", tcp_conn->fd);
    if (NULL == g_serv->kcp_serv) {
        return;
    }

    skt_kcp_conn_t *kcp_conn = skt_kcp_server_get_conn(g_serv->kcp_serv, tcp_conn->sess_id, &tcp_conn->kcp_cli_addr);
    if (NULL == kcp_conn) {
        return;
    }

    skt_kcp_server_close_conn(g_serv->kcp_serv, kcp_conn->sess_id, &tcp_conn->kcp_cli_addr);

    return;
}

//////////////////////

static void kcp_new_conn_cb(skt_kcp_conn_t *kcp_conn) {
    LOG_D("kcp_new_conn_cb sess_id:%u", kcp_conn->sess_id);
    skt_tcp_cli_conn_t *tcp_conn =
        skt_tcp_client_create_conn(g_serv->tcp_cli, g_serv->conf->target_addr, g_serv->conf->target_port);
    kcp_conn->tcp_fd = tcp_conn->fd;
    tcp_conn->sess_id = kcp_conn->sess_id;
    tcp_conn->kcp_cli_addr = kcp_conn->cliaddr;
    return;
}

static int kcp_recv_cb(skt_kcp_conn_t *kcp_conn, char *buf, int len) {
    // LOG_D("kcp serv recv:%s", buf);
    LOG_D("kcp serv recv:%d", len);
    skt_tcp_cli_conn_t *tcp_conn = skt_tcp_client_get_conn(g_serv->tcp_cli, kcp_conn->tcp_fd);
    if (NULL == tcp_conn) {
        skt_kcp_server_close_conn(g_serv->kcp_serv, kcp_conn->sess_id, &kcp_conn->cliaddr);
        return SKT_ERROR;
    }

    ssize_t rt = skt_tcp_client_send(tcp_conn->tcp_cli, tcp_conn->fd, buf, len);
    if (rt < 0) {
        skt_kcp_server_close_conn(g_serv->kcp_serv, kcp_conn->sess_id, &kcp_conn->cliaddr);
        skt_tcp_client_close_conn(tcp_conn->tcp_cli, tcp_conn->fd);
        return SKT_ERROR;
    }

    return SKT_OK;
}

static void kcp_timeout_cb(skt_kcp_conn_t *kcp_conn) {
    LOG_D("kcp_timeout_cb sess_id:%u", kcp_conn->sess_id);

    skt_tcp_cli_conn_t *tcp_conn = skt_tcp_client_get_conn(g_serv->tcp_cli, kcp_conn->tcp_fd);
    if (NULL == tcp_conn) {
        return;
    }

    skt_tcp_client_close_conn(tcp_conn->tcp_cli, tcp_conn->fd);
    return;
}

static char *kcp_encrypt_cb(const char *in, int in_len, int *out_len) {
    int padding_size = in_len;
    char *after_padding_buf = (char *)in;
    if (in_len % 16 != 0) {
        after_padding_buf = skt_cipher_padding(in, in_len, &padding_size);
    }
    *out_len = padding_size;

    char *out_buf = malloc(padding_size);
    memset(out_buf, 0, padding_size);
    skt_aes_cbc_encrpyt(after_padding_buf, &out_buf, padding_size, g_serv->kcp_serv->conf->key, iv);
    if (in_len % 16 != 0) {
        FREE_IF(after_padding_buf);
    }
    return out_buf;
}

static char *kcp_decrypt_cb(const char *in, int in_len, int *out_len) {
    int padding_size = in_len;
    char *after_padding_buf = (char *)in;
    if (in_len % 16 != 0) {
        after_padding_buf = skt_cipher_padding(in, in_len, &padding_size);
    }
    *out_len = padding_size;

    char *out_buf = malloc(padding_size);
    memset(out_buf, 0, padding_size);
    skt_aes_cbc_decrpyt(after_padding_buf, &out_buf, padding_size, g_serv->kcp_serv->conf->key, iv);
    if (in_len % 16 != 0) {
        FREE_IF(after_padding_buf);
    }
    return out_buf;
}

//////////////////////

skt_serv_t *skt_server_init(skt_serv_conf_t *conf, struct ev_loop *loop) {
    conf->tcp_cli_conf->close_cb = tcp_close_cb;
    conf->tcp_cli_conf->recv_cb = tcp_recv_cb;

    g_serv = malloc(sizeof(skt_serv_t));
    g_serv->conf = conf;
    g_serv->loop = loop;

    skt_tcp_cli_t *tcp_cli = skt_tcp_client_init(conf->tcp_cli_conf, loop);
    if (NULL == tcp_cli) {
        LOG_E("tcp client init error");
        FREE_IF(g_serv);
        return NULL;
    }

    g_serv->tcp_cli = tcp_cli;

    skt_kcp_serv_t *kcp_serv = skt_kcp_server_init(conf->kcp_serv_conf, loop, g_serv);
    if (NULL == kcp_serv) {
        FREE_IF(g_serv);
        return NULL;
    };
    kcp_serv->conn_timeout_cb = kcp_timeout_cb;
    kcp_serv->kcp_recv_cb = kcp_recv_cb;
    kcp_serv->new_conn_cb = kcp_new_conn_cb;
    if (conf->kcp_serv_conf->key != NULL) {
        kcp_serv->encrypt_cb = kcp_encrypt_cb;
        kcp_serv->decrypt_cb = kcp_decrypt_cb;
    } else {
        kcp_serv->encrypt_cb = NULL;
        kcp_serv->decrypt_cb = NULL;
    }

    g_serv->kcp_serv = kcp_serv;

    return g_serv;
}

void skt_server_free() {
    if (NULL == g_serv) {
        return;
    }
    if (g_serv->kcp_serv) {
        skt_kcp_server_free(g_serv->kcp_serv);
        g_serv->kcp_serv = NULL;
    }
    if (g_serv->tcp_cli) {
        skt_tcp_client_free(g_serv->tcp_cli);
        g_serv->tcp_cli = NULL;
    }
}