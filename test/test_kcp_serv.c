#include <arpa/inet.h>
#include <ev.h>

#include "../src/skt_cipher.h"
#include "../src/skt_kcp.h"
#include "../src/skt_utils.h"

static char *def_iv = "12345678123456781234567812345678";

static void kcp_new_conn_cb(skcp_conn_t *kcp_conn) {
    LOG_D("serv kcp_new_conn_cb sess_id: %u", kcp_conn->sess_id);
    return;
}

static int kcp_recv_cb(skcp_conn_t *kcp_conn, char *buf, int len) {
    LOG_D("serv kcp_recv_cb sess_id: %u len: %d", kcp_conn->sess_id, len);
    // char htkey[SKCP_HTKEY_LEN] = {0};
    // skt_kcp_gen_htkey(htkey, SKCP_HTKEY_LEN, kcp_conn->sess_id, &SKT_GET_KCP_CONN(kcp_conn)->dest_addr);
    char *str = malloc(len + 1);
    memset(str, 0, len + 1);
    memcpy(str, buf, len);
    LOG_D(">%s", str);
    FREE_IF(str);

    skt_kcp_send(SKT_GET_KCP_CONN(kcp_conn)->skt_kcp, kcp_conn->htkey, buf, len);

    return SKT_OK;
}

static void kcp_close_cb(skt_kcp_conn_t *kcp_conn) {
    LOG_D("serv kcp_close_cb");
    return;
}

static char *kcp_encrypt_cb(skt_kcp_t *skt_kcp, const char *in, int in_len, int *out_len) {
    char *iv = def_iv;
    if (strlen(skt_kcp->iv) > 0) {
        iv = skt_kcp->iv;
    }
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
    if (strlen(skt_kcp->iv) > 0) {
        iv = skt_kcp->iv;
    }

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

    skt_kcp_t *skt_kcp = skt_kcp_init(kcp_conf, loop, NULL, SKCP_MODE_SERV);
    if (NULL == skt_kcp) {
        LOG_E("start kcp server error addr:%s port:%u", kcp_conf->addr, kcp_conf->port);
        return -1;
    };

    // skt_kcp->conn_timeout_cb = kcp_timeout_cb;
    skt_kcp->kcp_recv_cb = kcp_recv_cb;
    skt_kcp->new_conn_cb = kcp_new_conn_cb;
    skt_kcp->conn_close_cb = kcp_close_cb;
    if (kcp_conf->key != NULL) {
        skt_kcp->encrypt_cb = kcp_encrypt_cb;
        skt_kcp->decrypt_cb = kcp_decrypt_cb;
    } else {
        skt_kcp->encrypt_cb = NULL;
        skt_kcp->decrypt_cb = NULL;
    }
    LOG_D("loop run");
    ev_run(loop, 0);
    LOG_D("loop end");

    skt_kcp_free(skt_kcp);

    return 0;
}