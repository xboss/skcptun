#include "skt_client.h"

#include "skt_cipher.h"
#include "skt_utils.h"

static skt_cli_t *g_cli = NULL;
static char *iv = "667b02a85c61c786def4521b060265e8";  // TODO: 动态生成

static void tcp_timeout_cb(skt_tcp_serv_conn_t *tcp_conn) {
    LOG_D("tcp serv timeout_cb fd:%d", tcp_conn->fd);
    // 忽略，已经在tcp_close_conn_cb处理了关闭逻辑
    return;
}

static void tcp_accept_conn_cb(skt_tcp_serv_conn_t *tcp_conn) {
    LOG_D("tcp serv accept_conn_cb fd:%d", tcp_conn->fd);
    skt_kcp_conn_t *kcp_conn = skt_kcp_client_new_conn(g_cli->kcp_cli);
    if (NULL == kcp_conn) {
        return;
    }

    kcp_conn->tcp_fd = tcp_conn->fd;
    tcp_conn->sess_id = kcp_conn->sess_id;

    return;
}
static void tcp_close_conn_cb(skt_tcp_serv_conn_t *tcp_conn) {
    LOG_D("tcp serv close_conn_cb fd:%d", tcp_conn->fd);
    skt_kcp_conn_t *kcp_conn = skt_kcp_client_get_conn(g_cli->kcp_cli, tcp_conn->sess_id);
    if (NULL == kcp_conn) {
        return;
    }

    skt_kcp_client_close_conn(kcp_conn->cli, kcp_conn->sess_id);
    return;
}

static int tcp_recv_cb(skt_tcp_serv_conn_t *tcp_conn, char *buf, int len) {
    // LOG_D("tcp serv recv:%s", buf);
    LOG_D("tcp serv recv:%d", len);

    skt_kcp_conn_t *kcp_conn = skt_kcp_client_get_conn(g_cli->kcp_cli, tcp_conn->sess_id);
    if (NULL == kcp_conn) {
        LOG_D("tcp_recv_cb kcp_conn is NULL sess_id:%u", tcp_conn->sess_id);
        return SKT_ERROR;
    }

    int rt = skt_kcp_client_send(kcp_conn->cli, kcp_conn->sess_id, buf, len);
    if (rt < 0) {
        skt_kcp_client_close_conn(g_cli->kcp_cli, kcp_conn->sess_id);
        skt_tcp_server_close_conn(g_cli->tcp_serv, tcp_conn->fd);
        return SKT_ERROR;
    }

    return SKT_OK;
}

//////////////////////

static int kcp_recv_cb(skt_kcp_conn_t *kcp_conn, char *buf, int len) {
    // LOG_D("kcp cli recv:%s", buf);
    LOG_D("kcp cli recv:%d", len);

    skt_tcp_serv_conn_t *tcp_conn = skt_tcp_server_get_conn(g_cli->tcp_serv, kcp_conn->tcp_fd);
    if (NULL == tcp_conn) {
        skt_kcp_client_close_conn(g_cli->kcp_cli, kcp_conn->sess_id);
        return SKT_ERROR;
    }

    ssize_t rt = skt_tcp_server_send(g_cli->tcp_serv, tcp_conn->fd, buf, len);
    if (rt < 0) {
        skt_kcp_client_close_conn(g_cli->kcp_cli, kcp_conn->sess_id);
        skt_tcp_server_close_conn(g_cli->tcp_serv, tcp_conn->fd);
        return SKT_ERROR;
    }

    return SKT_OK;
}

static void kcp_timeout_cb(skt_kcp_conn_t *kcp_conn) {
    skt_kcp_client_close_conn(g_cli->kcp_cli, kcp_conn->sess_id);
    skt_tcp_serv_conn_t *tcp_conn = skt_tcp_server_get_conn(g_cli->tcp_serv, kcp_conn->tcp_fd);
    if (NULL == tcp_conn) {
        return;
    }
    skt_tcp_server_close_conn(g_cli->tcp_serv, tcp_conn->fd);

    return;
}

static void kcp_close_cb(skt_kcp_conn_t *kcp_conn) {
    LOG_D("kcp_close_cb sess_id:%u", kcp_conn->sess_id);

    skt_tcp_serv_conn_t *tcp_conn = skt_tcp_server_get_conn(g_cli->tcp_serv, kcp_conn->tcp_fd);
    if (NULL == tcp_conn) {
        return;
    }
    skt_tcp_server_close_conn(g_cli->tcp_serv, tcp_conn->fd);

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
    skt_aes_cbc_encrpyt(after_padding_buf, &out_buf, padding_size, g_cli->kcp_cli->conf->key, iv);
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
    skt_aes_cbc_decrpyt(after_padding_buf, &out_buf, padding_size, g_cli->kcp_cli->conf->key, iv);
    if (in_len % 16 != 0) {
        FREE_IF(after_padding_buf);
    }
    return out_buf;
}

//////////////////////

skt_cli_t *skt_client_init(skt_cli_conf_t *conf, struct ev_loop *loop) {
    conf->tcp_serv_conf->accept_conn_cb = tcp_accept_conn_cb;
    conf->tcp_serv_conf->close_conn_cb = tcp_close_conn_cb;
    conf->tcp_serv_conf->recv_cb = tcp_recv_cb;
    conf->tcp_serv_conf->timeout_cb = tcp_timeout_cb;

    g_cli = malloc(sizeof(skt_cli_t));
    g_cli->conf = conf;
    g_cli->loop = loop;

    skt_tcp_serv_t *tcp_serv = skt_tcp_server_init(conf->tcp_serv_conf, loop);
    if (NULL == tcp_serv) {
        LOG_E("start tcp server error addr:%s port:%u", conf->tcp_serv_conf->serv_addr, conf->tcp_serv_conf->serv_port);
        FREE_IF(g_cli);
        return NULL;
    }
    g_cli->tcp_serv = tcp_serv;

    skt_kcp_cli_t *kcp_cli = skt_kcp_client_init(conf->kcp_cli_conf, loop, g_cli);
    if (NULL == kcp_cli) {
        FREE_IF(g_cli);
        return NULL;
    };
    kcp_cli->conn_timeout_cb = kcp_timeout_cb;
    kcp_cli->conn_close_cb = kcp_close_cb;
    kcp_cli->kcp_recv_cb = kcp_recv_cb;
    if (conf->kcp_cli_conf->key != NULL) {
        kcp_cli->encrypt_cb = kcp_encrypt_cb;
        kcp_cli->decrypt_cb = kcp_decrypt_cb;
    } else {
        kcp_cli->encrypt_cb = NULL;
        kcp_cli->decrypt_cb = NULL;
    }

    g_cli->kcp_cli = kcp_cli;

    return g_cli;
}
void skt_client_free() {
    if (NULL == g_cli) {
        return;
    }

    if (g_cli->kcp_cli) {
        skt_kcp_client_free(g_cli->kcp_cli);
        g_cli->kcp_cli = NULL;
    }
    if (g_cli->tcp_serv) {
        skt_tcp_server_free(g_cli->tcp_serv);
        g_cli->tcp_serv = NULL;
    }
}