#include "skt_kcp_conn.h"

#define SKT_CONV_MIN (10000)

typedef struct {
    uint32_t cid;
    skt_kcp_conn_t *conn;
    UT_hash_handle hh;
} cid_index_t;

typedef struct {
    uint32_t tun_ip;
    skt_kcp_conn_t *conn;
    UT_hash_handle hh;
} tun_ip_index_t;

static cid_index_t *g_cid_index = NULL;
static tun_ip_index_t *g_tun_ip_index = NULL;
static uint32_t g_cid = SKT_CONV_MIN;

uint32_t skt_kcp_conn_gen_cid() {
    g_cid++;
    if (g_cid < SKT_CONV_MIN) {
        _LOG_E("cid overflow");
        g_cid = SKT_CONV_MIN;
    }
    return g_cid;
}

int udp_output(const char *buf, int len, ikcpcb *kcp, void *user) {
    skt_kcp_conn_t *conn = (skt_kcp_conn_t *)user;
    assert(conn);
    assert(conn->peer);
    assert(conn->skt);

    char raw[SKT_MTU] = {0};
    int raw_len = 0;
    if (skt_pack(conn->skt, SKT_PKT_CMD_DATA, conn->peer->ticket, buf, len, raw, &raw_len)) {
        return 0;
    }
    assert(raw_len == len);
    if (sendto(conn->peer->fd, raw, raw_len, 0, (struct sockaddr *)&conn->peer->remote_addr,
               sizeof(conn->peer->remote_addr)) == -1) {
        _LOG_E("sendto failed when udp_output, fd:%d", conn->peer->fd);
        return 0;
    }
    return 0;
}
skt_kcp_conn_t *skt_kcp_conn_add(uint32_t cid, uint32_t tun_ip, const char *ticket, skt_udp_peer_t *peer,
                                 skcptun_t *skt) {
    if (skt_kcp_conn_get_by_tun_ip(tun_ip) != NULL) {
        _LOG_E("tun_ip already exists. skt_kcp_conn_add");
        return NULL;
    }

    skt_kcp_conn_t *conn = (skt_kcp_conn_t *)calloc(1, sizeof(skt_kcp_conn_t));
    if (!conn) {
        perror("calloc");
        return NULL;
    }
    conn->tun_ip = tun_ip;
    conn->peer = peer;
    conn->create_time = skt_mstime();
    conn->skt = skt;
    strncpy(peer->ticket, ticket, SKT_TICKET_SIZE);

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

    // add to index
    cid_index_t *cid_index = (cid_index_t *)calloc(1, sizeof(cid_index_t));
    if (!cid_index) {
        ikcp_release(conn->kcp);
        free(conn);
        return NULL;
    }
    cid_index->cid = conn->cid;
    cid_index->conn = conn;
    HASH_ADD_INT(g_cid_index, cid, cid_index);

    tun_ip_index_t *tun_ip_index = (tun_ip_index_t *)calloc(1, sizeof(tun_ip_index_t));
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

skt_kcp_conn_t *skt_kcp_conn_get_by_cid(uint32_t cid) {
    cid_index_t *cid_index = NULL;
    HASH_FIND_INT(g_cid_index, &cid, cid_index);
    if (!cid_index) {
        return NULL;
    }
    assert(cid_index->conn);
    return cid_index->conn;
}

skt_kcp_conn_t *skt_kcp_conn_get_by_tun_ip(uint32_t tun_ip) {
    tun_ip_index_t *tun_ip_index = NULL;
    HASH_FIND_INT(g_tun_ip_index, &tun_ip, tun_ip_index);
    if (!tun_ip_index) {
        return NULL;
    }
    assert(tun_ip_index->conn);
    return tun_ip_index->conn;
}

void skt_kcp_conn_del(skt_kcp_conn_t *kcp_conn) {
    if (!kcp_conn) return;
    ikcp_release(kcp_conn->kcp);
    kcp_conn->kcp = NULL;

    cid_index_t *cid_index = NULL;
    HASH_FIND_INT(g_cid_index, &kcp_conn->cid, cid_index);
    if (cid_index) {
        HASH_DEL(g_cid_index, cid_index);
        free(cid_index);
    }

    tun_ip_index_t *tun_ip_index = NULL;
    HASH_FIND_INT(g_tun_ip_index, &kcp_conn->tun_ip, tun_ip_index);
    if (tun_ip_index) {
        HASH_DEL(g_tun_ip_index, tun_ip_index);
        free(tun_ip_index);
    }

    free(kcp_conn);
    return;
}

int skt_kcp_conn_recv(skt_kcp_conn_t *kcp_conn, const char *in, int in_len, char *out) {
    // ikcp_input
    int ret = ikcp_input(kcp_conn->kcp, in, in_len);
    assert(ret == 0);
    ikcp_update(kcp_conn->kcp, SKT_MSTIME32);
    int peeksize = ikcp_peeksize(kcp_conn->kcp);
    if (peeksize <= 0) {
        return peeksize;
    }
    // kcp recv
    int recv_len = ikcp_recv(kcp_conn->kcp, out, peeksize);
    if (recv_len > 0) {
        kcp_conn->last_r_tm = skt_mstime();
    }
    ikcp_update(kcp_conn->kcp, SKT_MSTIME32);
    return recv_len;
}
