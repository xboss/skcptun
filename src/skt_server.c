#include "skt_server.h"

#include <netinet/ip.h>
#include <unistd.h>

#include "skt_tuntap.h"
#include "skt_utils.h"
#include "uthash.h"

typedef struct {
    uint32_t ip;  // key
    uint32_t cid;
    UT_hash_handle hh;
} skt_ip_cid_ht_t;

struct skt_serv_s {
    skt_serv_conf_t *conf;
    struct ev_loop *loop;
    skcp_t *skcp;
    // skcp_conn_t *data_conn;
    skt_ip_cid_ht_t *ip_cid_ht;
    struct ev_io *tun_r_watcher;
    int tun_fd;
};
typedef struct skt_serv_s skt_serv_t;

static skt_serv_t *g_ctx = NULL;

inline static void add_ip_cid_ht(uint32_t ip, uint32_t cid) {
    skt_ip_cid_ht_t *ic = NULL;
    HASH_FIND_INT(g_ctx->ip_cid_ht, &ip, ic);
    if (ic == NULL) {
        ic = (skt_ip_cid_ht_t *)malloc(sizeof(skt_ip_cid_ht_t));
        ic->ip = ip;
        HASH_ADD_INT(g_ctx->ip_cid_ht, ip, ic);
    }
    ic->cid = cid;
}

inline static skt_ip_cid_ht_t *find_ip_cid_ht(uint32_t ip) {
    skt_ip_cid_ht_t *ic = NULL;
    HASH_FIND_INT(g_ctx->ip_cid_ht, &ip, ic);
    return ic;
}

inline static void del_ip_cid_ht(skt_ip_cid_ht_t *ic) {
    HASH_DEL(g_ctx->ip_cid_ht, ic);
    FREE_IF(ic);
}

inline static void del_all_ip_cid_ht() {
    skt_ip_cid_ht_t *ic, *tmp;
    HASH_ITER(hh, g_ctx->ip_cid_ht, ic, tmp) {
        HASH_DEL(g_ctx->ip_cid_ht, ic);
        FREE_IF(ic);
    }
}

//////////////////////

static void tun_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    if (EV_ERROR & revents) {
        LOG_E("tun_read_cb got invalid event");
        return;
    }
    skcp_t *skcp = (skcp_t *)(watcher->data);

    char buf[1500];
    int len = skt_tuntap_read(g_ctx->tun_fd, buf, 1500);
    if (len <= 0) {
        LOG_E("skt_tuntap_read error tun_fd: %d", g_ctx->tun_fd);
        return;
    }

    struct ip *ip = (struct ip *)buf;
    // char src_ip[64] = {0};
    // char dest_ip[64] = {0};
    // inet_ntop(AF_INET, &(ip->ip_src.s_addr), src_ip, sizeof(src_ip));
    // inet_ntop(AF_INET, &(ip->ip_dst.s_addr), dest_ip, sizeof(dest_ip));
    // LOG_D("tun_read_cb src_ip: %s dest_ip: %s", src_ip, dest_ip);

    // if (g_ctx->data_conn) {
    //     int rt = skt_kcp_send_data(skt_kcp, g_ctx->data_conn->htkey, buf, len);
    //     if (rt < 0) {
    //         LOG_E("skt_kcp_send_data error htkey: %s", g_ctx->data_conn->htkey);
    //         return;
    //     }
    //     // LOG_D("<<<<<< tun_read_cb send ok len: %d", len);
    // }

    skt_ip_cid_ht_t *ic = find_ip_cid_ht(ip->ip_dst.s_addr);
    if (!ic) {
        // LOG_E("find_ip_cid_ht error ip_dst: %u", ip->ip_dst.s_addr);
        return;
    }
    int rt = skcp_send(g_ctx->skcp, ic->cid, buf, len);
    if (rt < 0) {
        LOG_E("skcp_send error cid: %u", ic->cid);
        return;
    }
}

//////////////////////

static void skcp_on_accept(uint32_t cid) {
    // if (!g_ctx->data_conn) {
    //     g_ctx->data_conn = kcp_conn;
    //     LOG_I("new data conn by kcp_new_conn_cb");
    //     return;
    // }
    // g_ctx->data_conn = kcp_conn;
    // LOG_I("new data conn by kcp_new_conn_cb sess_id: %u", g_ctx->data_conn->sess_id);
    LOG_I("skcp_on_accept cid: %u", cid);
    return;
}

static void skcp_on_recv(uint32_t cid, char *buf, int len, SKCP_MSG_TYPE msg_type) {
    // if (!g_ctx->data_conn) {
    //     g_ctx->data_conn = kcp_conn;
    //     LOG_I("set data conn by kcp_recv_data_cb sess_id: %u", g_ctx->data_conn->sess_id);
    // }

    LOG_D("server on_recv msg_type: %d cid: %u len: %d", msg_type, cid, len);
    struct ip *ip = (struct ip *)buf;
    // char src_ip[64] = {0};
    // char dest_ip[64] = {0};
    // inet_ntop(AF_INET, &(ip->ip_src.s_addr), src_ip, sizeof(src_ip));
    // inet_ntop(AF_INET, &(ip->ip_dst.s_addr), dest_ip, sizeof(dest_ip));

    add_ip_cid_ht(ip->ip_src.s_addr, cid);
    int w_len = skt_tuntap_write(g_ctx->tun_fd, buf, len);
    if (w_len < 0) {
        LOG_E("skt_tuntap_write error tun_fd: %d", g_ctx->tun_fd);
        return;
    }
    // LOG_D(">>>>> kcp_recv_data_cb len: %d src_ip: %s dest_ip: %s", w_len, src_ip, dest_ip);

    return;
}

static void skcp_on_close(uint32_t cid) {
    LOG_D("skcp_on_close cid: %u", cid);
    // g_ctx->cid = 0;
    return;
}

static int skcp_on_check_ticket(char *ticket, int len) { return 0; }

//////////////////////

static int init_vpn_serv() {
    char dev_name[32] = {0};
    int utunfd = skt_tuntap_open(dev_name, 32);

    if (utunfd == -1) {
        LOG_E("open tuntap error");
        return -1;
    }

    skt_tuntap_setup(dev_name, g_ctx->conf->tun_ip, g_ctx->conf->tun_mask);

    return utunfd;
}

//////////////////////

int skt_server_init(skt_serv_conf_t *conf, struct ev_loop *loop) {
    g_ctx = malloc(sizeof(skt_serv_t));
    g_ctx->conf = conf;
    g_ctx->loop = loop;
    // g_ctx->data_conn = NULL;
    g_ctx->ip_cid_ht = NULL;

    g_ctx->tun_fd = init_vpn_serv();
    if (g_ctx->tun_fd < 0) {
        return -1;
    }

    g_ctx->skcp = skcp_init(conf->skcp_conf, loop, g_ctx, SKCP_MODE_SERV);
    if (NULL == g_ctx->skcp) {
        FREE_IF(g_ctx);
        return -1;
    };

    g_ctx->skcp->conf->on_accept = skcp_on_accept;
    g_ctx->skcp->conf->on_check_ticket = skcp_on_check_ticket;
    g_ctx->skcp->conf->on_close = skcp_on_close;
    g_ctx->skcp->conf->on_recv = skcp_on_recv;

    // 设置tun读事件循环
    g_ctx->tun_r_watcher = malloc(sizeof(struct ev_io));
    g_ctx->tun_r_watcher->data = g_ctx->skcp;
    ev_io_init(g_ctx->tun_r_watcher, tun_read_cb, g_ctx->tun_fd, EV_READ);
    ev_io_start(g_ctx->loop, g_ctx->tun_r_watcher);

    return 0;
}

void skt_server_free() {
    if (NULL == g_ctx) {
        return;
    }

    if (g_ctx->ip_cid_ht) {
        del_all_ip_cid_ht();
    }

    if (g_ctx->tun_r_watcher) {
        ev_io_stop(g_ctx->loop, g_ctx->tun_r_watcher);
        FREE_IF(g_ctx->tun_r_watcher);
    }

    if (g_ctx->tun_fd >= 0) {
        close(g_ctx->tun_fd);
        g_ctx->tun_fd = -1;
    }

    if (g_ctx->skcp) {
        skcp_free(g_ctx->skcp);
        g_ctx->skcp = NULL;
    }

    FREE_IF(g_ctx);
}