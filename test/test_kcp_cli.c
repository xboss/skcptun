#include <arpa/inet.h>
#include <ev.h>

#include "../src/skt_cipher.h"
#include "../src/skt_kcp.h"
#include "../src/skt_utils.h"

static char *def_iv = "12345678123456781234567812345678";

static struct ev_timer *send_watcher = NULL;
static skcp_conn_t *sconn = NULL;
static int count = 0;

static void send_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents) {
    if (EV_ERROR & revents) {
        LOG_E("send_cb got invalid event");
        return;
    }

    skt_kcp_t *skt_kcp = (skt_kcp_t *)watcher->data;
    // if (count >= 2) {
    //     skt_kcp_close_conn(skt_kcp, sconn->htkey);
    //     ev_timer_stop(skt_kcp->loop, send_watcher);
    //     // exit(0);
    // }

    LOG_D("send count %d", count);
    if (sconn == NULL) {
        sconn = skt_kcp_new_conn(skt_kcp, 0, NULL);
        LOG_D("send_cb new conn");
        count++;
        return;
    }

// LOG_D("send_cb new iv: %s", SKT_GET_KCP_CONN(sconn)->skt_kcp->iv);

// char str[256] = {0};
// snprintf(str, 256, "hello %llu count %d", getmillisecond(), count);
#define sz 5
    char str[sz] = {0};
    str[0] = 'A';
    for (int i = 1; i < sz - 1; i++) {
        str[i] = 'B';
    }
    str[sz - 2] = 'C';

    skt_kcp_send_data(SKT_GET_KCP_CONN(sconn)->skt_kcp, sconn->htkey, str, strlen(str));
    LOG_D("<%s", str);
    count++;
}

static int kcp_recv_data_cb(skcp_conn_t *kcp_conn, char *buf, int len) {
    LOG_D("cli kcp_recv_cb sess_id: %u len: %d", kcp_conn->sess_id, len);
    char *str = malloc(len + 1);
    memset(str, 0, len + 1);
    memcpy(str, buf, len);
    LOG_D(">%s", str);
    FREE_IF(str);

    return SKT_OK;
}

static int kcp_recv_ctrl_cb(skcp_conn_t *kcp_conn, char *buf, int len) { return SKT_OK; }

static void kcp_close_cb(skt_kcp_conn_t *kcp_conn) {
    LOG_D("cli kcp_close_cb");
    sconn = NULL;
    return;
}

static char *kcp_encrypt_cb(skt_kcp_t *skt_kcp, const char *in, int in_len, int *out_len) {
    char *iv = def_iv;
    // if (strlen(skt_kcp->iv) > 0) {
    //     iv = skt_kcp->iv;
    // }

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
    char *iv = def_iv;
    // if (strlen(skt_kcp->iv_tmp) > 0) {
    //     iv = skt_kcp->iv_tmp;
    // }

    // if (strlen(skt_kcp->iv) > 0) {
    //     iv = skt_kcp->iv;
    // }

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

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Invalid parameter.\nUsage:\n    %s host port\n", argv[0]);
        return -1;
    }

#if (defined(__linux__) || defined(__linux))
    struct ev_loop *loop = ev_loop_new(EVBACKEND_EPOLL);
#elif defined(__APPLE__)
    struct ev_loop *loop = ev_loop_new(EVBACKEND_KQUEUE);
#else
    struct ev_loop *loop = ev_default_loop(0);
#endif

    skt_kcp_conf_t *kcp_conf = malloc(sizeof(skt_kcp_conf_t));
    skcp_conf_t *skcp_conf = malloc(sizeof(skcp_conf_t));
    skcp_conf->interval = 10;
    skcp_conf->mtu = 1024;
    skcp_conf->rcvwnd = 128;
    skcp_conf->sndwnd = 128;
    skcp_conf->nodelay = 1;
    skcp_conf->resend = 2;
    skcp_conf->nc = 1;
    skcp_conf->r_keepalive = 15;  // 600;
    skcp_conf->w_keepalive = 15;  // 600;
    skcp_conf->estab_timeout = 100;

    kcp_conf->skcp_conf = skcp_conf;
    kcp_conf->addr = argv[1];  //"127.0.0.1";
    kcp_conf->port = atoi(argv[2]);
    kcp_conf->key = "12345678123456781234567812345678";
    kcp_conf->r_buf_size = skcp_conf->mtu;
    kcp_conf->kcp_buf_size = 5000;  // 2048;
    kcp_conf->timeout_interval = 1;

    skt_kcp_t *skt_kcp = skt_kcp_init(kcp_conf, loop, NULL, SKCP_MODE_CLI);
    if (NULL == skt_kcp) {
        LOG_E("start kcp client error addr:%s port:%u", kcp_conf->addr, kcp_conf->port);
        return -1;
    };

    // skt_kcp->conn_timeout_cb = kcp_timeout_cb;
    skt_kcp->kcp_recv_data_cb = kcp_recv_data_cb;
    skt_kcp->kcp_recv_ctrl_cb = kcp_recv_ctrl_cb;
    skt_kcp->new_conn_cb = NULL;
    skt_kcp->conn_close_cb = kcp_close_cb;
    if (kcp_conf->key != NULL) {
        skt_kcp->encrypt_cb = kcp_encrypt_cb;
        skt_kcp->decrypt_cb = kcp_decrypt_cb;
    } else {
        skt_kcp->encrypt_cb = NULL;
        skt_kcp->decrypt_cb = NULL;
    }

    // skcp_conn_t *sconn = skt_kcp_new_conn(skt_kcp, 0, NULL);
    send_watcher = malloc(sizeof(ev_timer));
    send_watcher->data = skt_kcp;
    ev_init(send_watcher, send_cb);
    ev_timer_set(send_watcher, 0.1, 0.1);
    ev_timer_start(skt_kcp->loop, send_watcher);

    LOG_D("loop run");
    ev_run(loop, 0);
    LOG_D("loop end");

    skt_kcp_free(skt_kcp);

    return 0;
}