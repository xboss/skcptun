#include "skt_client_tt.h"

#include <netinet/ip.h>
#include <unistd.h>

#include "skt_cipher.h"
#include "skt_config.h"
#include "skt_ip_filter.h"
#include "skt_tuntap.h"
#include "skt_utils.h"

struct skt_cli_s {
    skt_cli_tt_conf_t *conf;
    struct ev_loop *loop;
    skt_kcp_t *skt_kcp;
    skcp_conn_t *data_conn;
    struct ev_timer *bt_watcher;
    struct ev_io *r_watcher;
    struct ev_io *w_watcher;
    int tun_fd;
    int raw_w_fd;
    struct sockaddr_in dest_raw_addr;
    skt_ip_filter_t *ip_filter;

    // uint32_t rtt_cnt;
    // int max_rtt;
    // int min_rtt;
    // int avg_rtt;
    // int sum_rtt;
    // int last_avg_rtt;
    // skcp_conn_t *ht_conn;
    // struct ev_timer *ht_watcher;
};
typedef struct skt_cli_s skt_cli_t;

static skt_cli_t *g_ctx = NULL;
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

    printf("tun_read_cb buf_len: %d\n", len);

    // char src_ip[20] = {0};
    // char dest_ip[20] = {0};
    // inet_ntop(AF_INET, buf + 12, src_ip, sizeof(src_ip));
    // inet_ntop(AF_INET, buf + 16, dest_ip, sizeof(dest_ip));

    struct ip *ip = (struct ip *)buf;
    char src_ip[20] = {0};
    char dest_ip[20] = {0};
    inet_ntop(AF_INET, &(ip->ip_src.s_addr), src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &(ip->ip_dst.s_addr), dest_ip, sizeof(dest_ip));
    printf("tun_read_cb src_ip: %s dest_ip: %s\n", src_ip, dest_ip);

    // if (skt_ip_filter_is_in(g_ctx->ip_filter, ip->ip_dst)) {
    //     // route to default net
    //     // printf("tun_read_cb skt_ip_filter_is_in: %s\n", dest_ip);
    //     // inet_pton(AF_INET, "192.168.3.26", &ip->ip_src);
    //     // ip->ip_sum = 0;
    //     // ip->ip_sum = ip_checksum((unsigned short *)ip, 10);

    //     // int w_len = skt_tuntap_write(g_ctx->tun_fd, buf, len);
    //     // if (w_len < 0) {
    //     //     printf("skt_tuntap_write error tun_fd: %d\n", g_ctx->tun_fd);
    //     //     perror("tun_read_cb skt_tuntap_write error");
    //     //     return;
    //     // }
    //     // printf("tun_read_cb skt_tuntap_write %d %d\n", w_len, len);

    //     g_ctx->dest_raw_addr.sin_addr.s_addr = ip->ip_dst.s_addr;  // inet_addr(dest_ip);
    //     int s_bytes = sendto(g_ctx->raw_w_fd, buf, len, 0, (struct sockaddr *)&g_ctx->dest_raw_addr,
    //                          sizeof(g_ctx->dest_raw_addr));
    //     if (s_bytes < 0) {
    //         perror("tun_read_cb raw sendto error");
    //         return;
    //     }
    //     printf("tun_read_cb sendto raw bytes: %d\n", s_bytes);
    //     return;
    // }

    if (g_ctx->data_conn) {
        int rt = skt_kcp_send_data(skt_kcp, g_ctx->data_conn->htkey, buf, len);
        if (rt < 0) {
            LOG_E("skt_kcp_send_data error htkey: %s", g_ctx->data_conn->htkey);
            return;
        }
        printf("tun_read_cb send rt: %d\n", rt);
    }
}

//////////////////////

static int kcp_recv_data_cb(skcp_conn_t *kcp_conn, char *buf, int len) {
    char src_ip[20] = {0};
    char dest_ip[20] = {0};
    inet_ntop(AF_INET, buf + 12, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, buf + 16, dest_ip, sizeof(dest_ip));
    printf("kcp_recv_data_cb src_ip: %s dest_ip: %s\n", src_ip, dest_ip);

    int w_len = skt_tuntap_write(g_ctx->tun_fd, buf, len);
    if (w_len < 0) {
        LOG_E("skt_tuntap_write error tun_fd: %d", g_ctx->tun_fd);
        return SKT_ERROR;
    }

    return SKT_OK;
}

static int kcp_recv_ctrl_cb(skcp_conn_t *kcp_conn, char *buf, int len) { return SKT_OK; }

static void kcp_close_cb(skt_kcp_conn_t *kcp_conn) {
    LOG_D("kcp_close_cb");
    if (kcp_conn->tag == 0) {
        // reconnect
        g_ctx->data_conn = skt_kcp_new_conn(g_ctx->skt_kcp, 0, NULL);
        LOG_I("new data conn by reconnect");
    }

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

static void beat_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents) {
    if (EV_ERROR & revents) {
        LOG_E("init_cb got invalid event");
        return;
    }

    skt_kcp_t *skt_kcp = (skt_kcp_t *)watcher->data;

    if (!g_ctx->data_conn) {
        g_ctx->data_conn = skt_kcp_new_conn(skt_kcp, 0, NULL);
        LOG_I("new data conn by beat_cb");
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

    skt_tuntap_setup(dev_name, "192.168.2.2");

    return utunfd;
}

static int init_raw_sock(char *bind_ip) {
    int raw_w_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_w_fd == -1) {
        perror("init_raw_sock error");
        return -1;
    }

    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(bind_ip);
    // servaddr.sin_port = htons(skt_kcp->conf->port);
    if (-1 == bind(raw_w_fd, (struct sockaddr *)&servaddr, sizeof(servaddr))) {
        perror("bind error");
        close(raw_w_fd);
        return -1;
    }

    setnonblock(raw_w_fd);

    // int on = 1;
    // if (setsockopt(raw_w_fd, IPPROTO_IP, IP_HDRINCL, (const char *)&on, sizeof(on)) == -1) {
    //     perror("setsockopt");
    //     return (0);
    // }

    bzero(&g_ctx->dest_raw_addr, sizeof(g_ctx->dest_raw_addr));
    g_ctx->dest_raw_addr.sin_family = AF_INET;

    return raw_w_fd;
}

//////////////////////

void skt_client_tt_free() {
    if (NULL == g_ctx) {
        return;
    }

    if (g_ctx->r_watcher) {
        ev_io_stop(g_ctx->loop, g_ctx->r_watcher);
        FREE_IF(g_ctx->r_watcher);
    }

    if (g_ctx->tun_fd >= 0) {
        close(g_ctx->tun_fd);
        g_ctx->tun_fd = -1;
    }

    if (g_ctx->raw_w_fd >= 0) {
        close(g_ctx->raw_w_fd);
        g_ctx->raw_w_fd = -1;
    }

    if (g_ctx->data_conn) {
        skt_kcp_close_conn(g_ctx->skt_kcp, g_ctx->data_conn->htkey);
    }

    if (g_ctx->skt_kcp) {
        skt_kcp_free(g_ctx->skt_kcp);
        g_ctx->skt_kcp = NULL;
    }

    FREE_IF(g_ctx);
}

int skt_client_tt_init(skt_cli_tt_conf_t *conf, struct ev_loop *loop) {
    g_ctx = malloc(sizeof(skt_cli_t));
    g_ctx->conf = conf;
    g_ctx->loop = loop;

    g_ctx->tun_fd = init_vpn_cli();
    if (g_ctx->tun_fd < 0) {
        skt_client_tt_free();
        return -1;
    }

    // g_ctx->raw_w_fd = init_raw_sock("192.168.3.26");
    // if (g_ctx->raw_w_fd < 0) {
    //     skt_client_tt_free();
    //     return -1;
    // }

    skt_kcp_t *skt_kcp = skt_kcp_init(conf->kcp_conf, loop, g_ctx, SKCP_MODE_CLI);
    if (NULL == skt_kcp) {
        skt_client_tt_free();
        return -1;
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

    // 定时
    g_ctx->data_conn = NULL;
    g_ctx->bt_watcher = malloc(sizeof(ev_timer));
    g_ctx->bt_watcher->data = skt_kcp;
    ev_init(g_ctx->bt_watcher, beat_cb);
    ev_timer_set(g_ctx->bt_watcher, 0, 1);
    ev_timer_start(skt_kcp->loop, g_ctx->bt_watcher);

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

    g_ctx->ip_filter = skt_load_ip_list("/Users/sunji/chn_ip.txt");
    if (!g_ctx->ip_filter) {
        skt_client_tt_free();
        return -1;
    }

    g_ctx->skt_kcp = skt_kcp;

    return 0;
}
