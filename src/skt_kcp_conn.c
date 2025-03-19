

#include "skcptun.h"

#define SKT_CONV_MIN (10000)

static skt_kcp_conn_t* g_cid_index = NULL;
static skt_kcp_conn_t* g_tun_ip_index = NULL;
static uint32_t g_cid = SKT_CONV_MIN;

static void print_skt_kcp_conn(const skt_kcp_conn_t* conn) {
    if (conn == NULL) {
        _LOG_E("skt_kcp_conn_t is NULL");
        return;
    }
    uint64_t now = skt_mstime();

    _LOG_E("skt_kcp_conn_t:");
    _LOG_E("  cid: %u", conn->cid);
    _LOG_E("  tun_ip: %u", conn->tun_ip);
    _LOG_E("  create_time: %" PRIu64 " ago", now - conn->create_time);
    _LOG_E("  last_r_tm: %" PRIu64 " ago", now - conn->last_r_tm);
    _LOG_E("  last_w_tm: %" PRIu64 " ago", now - conn->last_w_tm);

    const skt_udp_peer_t* peer = conn->peer;
    if (peer == NULL) {
        _LOG_E("  peer is NULL");
        return;
    }

    char remote_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &peer->remote_addr.sin_addr, remote_ip, INET_ADDRSTRLEN);
    _LOG_E("  peer:");
    _LOG_E("    fd: %d", peer->fd);
    _LOG_E("    remote_addr: %s:%d", remote_ip, ntohs(peer->remote_addr.sin_port));

    char local_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &peer->local_addr.sin_addr, local_ip, INET_ADDRSTRLEN);
    _LOG_E("    local_addr: %s:%d", local_ip, ntohs(peer->local_addr.sin_port));

    _LOG_E("    cid: %u", peer->cid);
    _LOG_E("    last_r_tm: %" PRIu64 " ago", now - peer->last_r_tm);
    _LOG_E("    last_w_tm: %" PRIu64 " ago", now - peer->last_w_tm);
}

static int udp_output(const char* buf, int len, ikcpcb* kcp, void* user) {
    skt_kcp_conn_t* conn = (skt_kcp_conn_t*)user;
    assert(conn);
    assert(conn->peer);
    assert(conn->skt);
    assert(len <= conn->skt->conf->kcp_mtu);
    char raw[SKT_MTU] = {0};
    size_t raw_len = 0;
    // _LOG("udp_output len:%d", len);
    if (skt_pack(conn->skt, SKT_PKT_CMD_DATA, conn->skt->conf->ticket, buf, len, raw, &raw_len)) return 0;
    assert(raw_len == len + SKT_PKT_CMD_SZIE + SKT_TICKET_SIZE);

    int slen = sendto(conn->peer->fd, raw, raw_len, 0, (struct sockaddr*)&conn->peer->remote_addr,
                      sizeof(conn->peer->remote_addr));
    if (slen < 0) {
        perror("udp_output sendto");
        _LOG_E("udp_output sendto failed len:%d fd:%d", slen, conn->peer->fd);
        return 0;
    }
    return 0;
}

////////////////////////////////
// API
////////////////////////////////

void skt_kcp_conn_info() {
    _LOG_E("---------- kcp conn info ----------");
    _LOG_E("|-- kcp cid index info");
    unsigned int cid_index_cnt = HASH_CNT(hh_cid, g_cid_index);
    unsigned int tun_ip_index_cnt = HASH_CNT(hh_tun_ip, g_tun_ip_index);
    assert(cid_index_cnt == tun_ip_index_cnt);
    if (cid_index_cnt != tun_ip_index_cnt) {
        _LOG_E("kcp connection cid index count not equal tun_ip index count.cid_index_cnt : %u, tun_ip_index_cnt : %u",
               cid_index_cnt, tun_ip_index_cnt);
    }
    _LOG_E("|-- Total connections: %u", cid_index_cnt);

    skt_kcp_conn_t *conn, *tmp;
    int index = 0;
    HASH_ITER(hh_cid, g_cid_index, conn, tmp) {
        _LOG_E("|-- Connection %d/%d", ++index, cid_index_cnt);
        print_skt_kcp_conn(conn);
        _LOG_E("|-------------------------------");
    }

    if (cid_index_cnt == 0) {
        _LOG_E("|-- No active connections");
    }
}

void skt_kcp_conn_iter(void (*iter)(skt_kcp_conn_t* kcp_conn)) {
    skt_kcp_conn_t *conn, *tmp;
    if (g_cid_index) {
        HASH_ITER(hh_cid, g_cid_index, conn, tmp) { iter(conn); }
    }
}

uint32_t skt_kcp_conn_gen_cid() {
    g_cid++;
    if (g_cid < SKT_CONV_MIN) {
        _LOG_E("cid overflow");
        g_cid = SKT_CONV_MIN;
    }
    return g_cid;
}

skt_kcp_conn_t* skt_kcp_conn_add(uint32_t cid, uint32_t tun_ip, const char* ticket, skt_udp_peer_t* peer,
                                 skcptun_t* skt) {
    if (skt_kcp_conn_get_by_tun_ip(tun_ip) != NULL) {
        _LOG_E("tun_ip already exists. skt_kcp_conn_add");
        return NULL;
    }

    skt_kcp_conn_t* conn = (skt_kcp_conn_t*)calloc(1, sizeof(skt_kcp_conn_t));
    if (!conn) {
        perror("calloc");
        return NULL;
    }
    conn->tun_ip = tun_ip;
    conn->peer = peer;
    conn->create_time = skt_mstime();
    conn->skt = skt;

    conn->cid = cid;
    if (skt_kcp_conn_get_by_cid(conn->cid) != NULL) {
        _LOG_E("cid %d already exists. skt_kcp_conn_add", conn->cid);
        free(conn);
        return NULL;
    }
    conn->kcp = ikcp_create(conn->cid, conn);
    if (!conn->kcp) {
        free(conn);
        return NULL;
    }
    conn->kcp->output = udp_output;
    ikcp_setmtu(conn->kcp, skt->conf->kcp_mtu);
    ikcp_nodelay(conn->kcp, skt->conf->kcp_nodelay, skt->conf->kcp_interval, skt->conf->kcp_resend, skt->conf->kcp_nc);
    ikcp_wndsize(conn->kcp, skt->conf->kcp_sndwnd, skt->conf->kcp_rcvwnd);

    // add to index
    HASH_ADD(hh_cid, g_cid_index, cid, sizeof(conn->cid), conn);
    HASH_ADD(hh_tun_ip, g_tun_ip_index, tun_ip, sizeof(conn->tun_ip), conn);

    return conn;
}

inline skt_kcp_conn_t* skt_kcp_conn_get_by_cid(uint32_t cid) {
    if (cid == 0) return NULL;
    skt_kcp_conn_t* conn = NULL;
    HASH_FIND(hh_cid, g_cid_index, &cid, sizeof(conn->cid), conn);
    return conn;
}

inline skt_kcp_conn_t* skt_kcp_conn_get_by_tun_ip(uint32_t tun_ip) {
    skt_kcp_conn_t* conn = NULL;
    HASH_FIND(hh_tun_ip, g_tun_ip_index, &tun_ip, sizeof(conn->tun_ip), conn);
    return conn;
}

void skt_kcp_conn_del(skt_kcp_conn_t* kcp_conn) {
    if (!kcp_conn) return;
    ikcp_release(kcp_conn->kcp);
    kcp_conn->kcp = NULL;
    if (skt_kcp_conn_get_by_cid(kcp_conn->cid)) {
        HASH_DELETE(hh_cid, g_cid_index, kcp_conn);
    }
    if (skt_kcp_conn_get_by_tun_ip(kcp_conn->tun_ip)) {
        HASH_DELETE(hh_tun_ip, g_tun_ip_index, kcp_conn);
    }
    free(kcp_conn);
    return;
}

void skt_kcp_conn_cleanup() {
    int n = 0, m = 0; /* TODO: debug */
    skt_kcp_conn_t *conn, *tmp;
    if (g_cid_index) {
        HASH_ITER(hh_cid, g_cid_index, conn, tmp) {
            HASH_DELETE(hh_cid, g_cid_index, conn);
            n++;
        }
        g_cid_index = NULL;
    }
    if (g_tun_ip_index) {
        HASH_ITER(hh_tun_ip, g_tun_ip_index, conn, tmp) {
            HASH_DELETE(hh_tun_ip, g_tun_ip_index, conn);
            ikcp_release(conn->kcp);
            conn->kcp = NULL;
            free(conn);
            m++;
        }
        g_tun_ip_index = NULL;
    }
    assert(n == m);
    _LOG("kcp connection cleanup");
}