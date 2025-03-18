

#include "skcptun.h"

#define SKT_CONV_MIN (10000)

typedef struct {
    uint32_t cid;
    skt_kcp_conn_t* conn;
    UT_hash_handle hh;
} cid_index_t;

typedef struct {
    uint32_t tun_ip;
    skt_kcp_conn_t* conn;
    UT_hash_handle hh;
} tun_ip_index_t;

static cid_index_t* g_cid_index = NULL;
static tun_ip_index_t* g_tun_ip_index = NULL;
static uint32_t g_cid = SKT_CONV_MIN;

static void print_skt_kcp_conn(const skt_kcp_conn_t* conn) {
    if (conn == NULL) {
        _LOG_E("skt_kcp_conn_t is NULL");
        return;
    }

    _LOG_E("skt_kcp_conn_t:");
    _LOG_E("  cid: %u", conn->cid);
    _LOG_E("  tun_ip: %u", conn->tun_ip);
    _LOG_E("  create_time: %" PRIu64 "", conn->create_time);
    _LOG_E("  last_r_tm: %" PRIu64 "", conn->last_r_tm);
    _LOG_E("  last_w_tm: %" PRIu64 "", conn->last_w_tm);

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
    _LOG_E("    last_r_tm: %" PRIu64 "", peer->last_r_tm);
    _LOG_E("    last_w_tm: %" PRIu64 "", peer->last_w_tm);
}

static void print_cid_index(const cid_index_t* cid_index) {
    if (cid_index == NULL) {
        _LOG_E("cid_index is NULL");
        return;
    }
    _LOG_E("cid_index:");
    _LOG_E("  cid: %u", cid_index->cid);
    print_skt_kcp_conn(cid_index->conn);
}

static void print_tun_ip_index(const tun_ip_index_t* tun_ip_index) {
    if (tun_ip_index == NULL) {
        _LOG_E("tun_ip_index is NULL");
        return;
    }
    _LOG_E("tun_ip_index:");
    _LOG_E("  tun_ip: %u", tun_ip_index->tun_ip);
    print_skt_kcp_conn(tun_ip_index->conn);
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
    unsigned int cid_index_cnt = HASH_COUNT(g_cid_index);
    _LOG_E("kcp connection cid index count: %u", cid_index_cnt);
    cid_index_t *cid_index = NULL, *tmp1 = NULL;
    HASH_ITER(hh, g_cid_index, cid_index, tmp1) { print_cid_index(cid_index); }

    _LOG_E("|-- kcp tunip index info");
    unsigned int tun_ip_index_cnt = HASH_COUNT(g_tun_ip_index);
    _LOG_E("kcp connection tun_ip index count: %u", tun_ip_index_cnt);
    tun_ip_index_t *tun_ip_index = NULL, *tmp2 = NULL;
    HASH_ITER(hh, g_tun_ip_index, tun_ip_index, tmp2) { print_tun_ip_index(tun_ip_index); }
    if (cid_index_cnt != tun_ip_index_cnt) {
        fprintf(stderr, "ERROR: kcp connection tun_ip index count not equal cid index count.\n");
    }
    assert(cid_index_cnt == tun_ip_index_cnt);
}

void skt_kcp_conn_iter(void (*iter)(skt_kcp_conn_t* kcp_conn)) {
    cid_index_t *cid_index = NULL, *tmp1 = NULL;
    HASH_ITER(hh, g_cid_index, cid_index, tmp1) { iter(cid_index->conn); }
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
    cid_index_t* cid_index = (cid_index_t*)calloc(1, sizeof(cid_index_t));
    if (!cid_index) {
        ikcp_release(conn->kcp);
        free(conn);
        return NULL;
    }
    cid_index->cid = conn->cid;
    cid_index->conn = conn;
    HASH_ADD_INT(g_cid_index, cid, cid_index);

    tun_ip_index_t* tun_ip_index = (tun_ip_index_t*)calloc(1, sizeof(tun_ip_index_t));
    if (!tun_ip_index) {
        ikcp_release(conn->kcp);
        skt_kcp_conn_del(conn);
        free(conn);
        return NULL;
    }
    tun_ip_index->tun_ip = conn->tun_ip;
    tun_ip_index->conn = conn;
    HASH_ADD_INT(g_tun_ip_index, tun_ip, tun_ip_index);

    return conn;
}

skt_kcp_conn_t* skt_kcp_conn_get_by_cid(uint32_t cid) {
    if (cid == 0) return NULL;
    cid_index_t* cid_index = NULL;
    HASH_FIND_INT(g_cid_index, &cid, cid_index);
    if (!cid_index) {
        return NULL;
    }
    assert(cid_index->conn);
    return cid_index->conn;
}

skt_kcp_conn_t* skt_kcp_conn_get_by_tun_ip(uint32_t tun_ip) {
    tun_ip_index_t* tun_ip_index = NULL;
    HASH_FIND_INT(g_tun_ip_index, &tun_ip, tun_ip_index);
    if (!tun_ip_index) {
        return NULL;
    }
    assert(tun_ip_index->conn);
    return tun_ip_index->conn;
}

void skt_kcp_conn_del(skt_kcp_conn_t* kcp_conn) {
    if (!kcp_conn) return;
    ikcp_release(kcp_conn->kcp);
    kcp_conn->kcp = NULL;

    cid_index_t* cid_index = NULL;
    HASH_FIND_INT(g_cid_index, &kcp_conn->cid, cid_index);
    if (cid_index) {
        HASH_DEL(g_cid_index, cid_index);
        free(cid_index);
    }

    tun_ip_index_t* tun_ip_index = NULL;
    HASH_FIND_INT(g_tun_ip_index, &kcp_conn->tun_ip, tun_ip_index);
    if (tun_ip_index) {
        HASH_DEL(g_tun_ip_index, tun_ip_index);
        free(tun_ip_index);
    }

    free(kcp_conn);
    return;
}

void skt_kcp_conn_cleanup() {
    if (g_cid_index) {
        cid_index_t *cid_index, *tmp1;
        HASH_ITER(hh, g_cid_index, cid_index, tmp1) {
            skt_kcp_conn_t* conn = cid_index->conn;
            if (conn) {
                ikcp_release(conn->kcp);
                free(conn);
            }
            HASH_DEL(g_cid_index, cid_index);
            free(cid_index);
        }
        g_cid_index = NULL;
    }

    if (g_tun_ip_index) {
        tun_ip_index_t *tun_ip_index, *tmp2;
        HASH_ITER(hh, g_tun_ip_index, tun_ip_index, tmp2) {
            HASH_DEL(g_tun_ip_index, tun_ip_index);
            free(tun_ip_index);
        }
        g_tun_ip_index = NULL;
    }
    _LOG("kcp connection cleanup");
}