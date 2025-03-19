
#include "skcptun.h"

static skt_udp_peer_t* g_addr_peer_index = NULL;

static skt_udp_peer_t* init_peer(int fd, struct sockaddr_in remote_addr, skcptun_t* skt) {
    skt_udp_peer_t* peer = (skt_udp_peer_t*)calloc(1, sizeof(skt_udp_peer_t));
    if (!peer) {
        perror("alloc");
        return NULL;
    }
    peer->fd = fd;
    peer->remote_addr = remote_addr;
    peer->skt = skt;
    peer->addr = remote_addr.sin_addr.s_addr;
    return peer;
}
static void free_peer(skt_udp_peer_t* peer) {
    if (!peer) return;
    if (peer->fd > 0) {
        // close(peer->fd);
        peer->fd = -1;
    }
    free(peer);
}

int skt_udp_peer_add(int fd, struct sockaddr_in remote_addr, skcptun_t* skt) {
    if (skt_udp_peer_get(remote_addr.sin_addr.s_addr)) {
        _LOG_E("peer already exist. skt_udp_peer_add");
        return _ERR;
    }
    skt_udp_peer_t* peer = init_peer(fd, remote_addr, skt);
    if (!peer) {
        return _ERR;
    }
    HASH_ADD(hh_addr, g_addr_peer_index, addr, sizeof(peer->addr), peer);
    return _OK;
}

void skt_udp_peer_del(uint32_t remote_addr) {
    skt_udp_peer_t* peer = NULL;
    HASH_FIND(hh_addr, g_addr_peer_index, &remote_addr, sizeof(peer->addr), peer);
    if (!peer) return;
    HASH_DELETE(hh_addr, g_addr_peer_index, peer);
    free_peer(peer);
    return;
}

skt_udp_peer_t* skt_udp_peer_get(uint32_t remote_addr) {
    skt_udp_peer_t* peer = NULL;
    HASH_FIND(hh_addr, g_addr_peer_index, &remote_addr, sizeof(peer->addr), peer);
    return peer;
}

void skt_udp_peer_iter(void (*iter)(skt_udp_peer_t* peer)) {
    if (g_addr_peer_index) {
        skt_udp_peer_t *peer, *tmp;
        HASH_ITER(hh_addr, g_addr_peer_index, peer, tmp) { iter(peer); }
    }
}

void skt_udp_peer_info() {
    _LOG_E("---------- peers info ----------");
    unsigned int peers_cnt = HASH_CNT(hh_addr, g_addr_peer_index);
    _LOG_E("udp peers count: %u", peers_cnt);
    skt_udp_peer_t *peer, *tmp;
    int index = 0;
    HASH_ITER(hh_addr, g_addr_peer_index, peer, tmp) {
        if (!peer) continue;  // 空指针保护

        _LOG_E("|-- Peer %d/%d", ++index, peers_cnt);

        // 转换远程地址
        char remote_ip[INET_ADDRSTRLEN] = {0};
        if (inet_ntop(AF_INET, &peer->remote_addr.sin_addr, remote_ip, INET_ADDRSTRLEN) == NULL) {
            _LOG_E("    remote_addr: invalid");
        } else {
            _LOG_E("    remote_addr: %s:%d", remote_ip, ntohs(peer->remote_addr.sin_port));
        }

        // 转换本地地址
        char local_ip[INET_ADDRSTRLEN] = {0};
        if (peer->fd > 0 && inet_ntop(AF_INET, &peer->local_addr.sin_addr, local_ip, INET_ADDRSTRLEN)) {
            _LOG_E("    local_addr: %s:%d", local_ip, ntohs(peer->local_addr.sin_port));
        } else {
            _LOG_E("    local_addr: invalid");
        }

        uint64_t now = skt_mstime();
        _LOG_E("    fd: %d", peer->fd);
        _LOG_E("    cid: %u", peer->cid);
        _LOG_E("    last_r_tm: %" PRIu64 " ago", now - peer->last_r_tm);
        _LOG_E("    last_w_tm: %" PRIu64 " ago", now - peer->last_w_tm);
        _LOG_E("|-------------------------------");
    }

    if (peers_cnt == 0) {
        _LOG_E("|-- No active peers");
    }
}

////////////////////////////////
// protocol
////////////////////////////////

#define _IS_SECRET (strlen((const char*)skt->conf->key) > 0 && strlen((const char*)skt->conf->iv) > 0)

// cmd(1B)ticket(32)payload(mtu-32B-1B)

int skt_pack(skcptun_t* skt, char cmd, const char* ticket, const char* payload, size_t payload_len, char* raw,
             size_t* raw_len) {
    // _LOG("skt_pack payload_len:%d, kcp_mtu:%d, tun_mtu:%d", payload_len, skt->conf->kcp_mtu, skt->conf->tun_mtu);
    assert(payload_len <= skt->conf->mtu - SKT_PKT_CMD_SZIE - SKT_TICKET_SIZE);
    if (_IS_SECRET) {
        char cipher_buf[SKT_MTU] = {0};
        memcpy(cipher_buf, &cmd, SKT_PKT_CMD_SZIE);
        memcpy(cipher_buf + SKT_PKT_CMD_SZIE, ticket, SKT_TICKET_SIZE);
        memcpy(cipher_buf + SKT_PKT_CMD_SZIE + SKT_TICKET_SIZE, payload, payload_len);
        if (crypto_encrypt(skt->conf->key, skt->conf->iv, (const unsigned char*)cipher_buf,
                           (payload_len + SKT_TICKET_SIZE + SKT_PKT_CMD_SZIE), (unsigned char*)raw, raw_len)) {
            _LOG_E("crypto encrypt failed");
            return _ERR;
        }
        assert(payload_len + SKT_TICKET_SIZE + SKT_PKT_CMD_SZIE == *raw_len);
    } else {
        memcpy(raw, &cmd, SKT_PKT_CMD_SZIE);
        memcpy(raw + SKT_PKT_CMD_SZIE, ticket, SKT_TICKET_SIZE);
        memcpy(raw + SKT_PKT_CMD_SZIE + SKT_TICKET_SIZE, payload, payload_len);
        *raw_len = payload_len + SKT_TICKET_SIZE + SKT_PKT_CMD_SZIE;
    }
    return _OK;
}

int skt_unpack(skcptun_t* skt, const char* raw, size_t raw_len, char* cmd, char* ticket, char* payload,
               size_t* payload_len) {
    assert(raw_len <= SKT_MTU);
    assert(raw_len > SKT_PKT_CMD_SZIE + SKT_TICKET_SIZE);
    const char* p = raw;
    char cipher_buf[SKT_MTU] = {0};
    if (_IS_SECRET) {
        size_t cipher_len = 0;
        if (crypto_decrypt(skt->conf->key, skt->conf->iv, (const unsigned char*)raw, raw_len,
                           (unsigned char*)cipher_buf, &cipher_len)) {
            _LOG_E("crypto decrypt failed");
            return _ERR;
        }
        assert(cipher_len == raw_len);
        p = cipher_buf;
    }
    memcpy(cmd, p, SKT_PKT_CMD_SZIE);
    memcpy(ticket, p + SKT_PKT_CMD_SZIE, SKT_TICKET_SIZE);
    memcpy(payload, p + SKT_PKT_CMD_SZIE + SKT_TICKET_SIZE, raw_len - SKT_PKT_CMD_SZIE - SKT_TICKET_SIZE);
    *payload_len = raw_len - SKT_PKT_CMD_SZIE - SKT_TICKET_SIZE;
    return _OK;
}

void skt_udp_peer_cleanup() {
    if (g_addr_peer_index) {
        skt_udp_peer_t *peer, *tmp;
        HASH_ITER(hh_addr, g_addr_peer_index, peer, tmp) { skt_udp_peer_del(peer->addr); }
    }
    // addr_peer_index_t *addr_peer_index, *tmp;
    // HASH_ITER(hh, g_addr_peer_index, addr_peer_index, tmp) {
    //     if (addr_peer_index->peer) {
    //         free_peer(addr_peer_index->peer);
    //         addr_peer_index->peer = NULL;
    //     }
    //     HASH_DEL(g_addr_peer_index, addr_peer_index);
    //     free(addr_peer_index);
    // }
    g_addr_peer_index = NULL;
    _LOG("skt_udp_peer_cleanup");
}