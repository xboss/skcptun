
#include "skcptun.h"

typedef struct {
    uint32_t addr;
    skt_udp_peer_t* peer;
    UT_hash_handle hh;
} addr_peer_index_t;

static addr_peer_index_t* g_addr_peer_index = NULL;

static addr_peer_index_t* init_addr_peer_index(skt_udp_peer_t* peer) {
    addr_peer_index_t* addr_peer_index = (addr_peer_index_t*)calloc(1, sizeof(addr_peer_index_t));
    if (!addr_peer_index) {
        perror("alloc");
        return NULL;
    }
    addr_peer_index->addr = peer->remote_addr.sin_addr.s_addr;
    addr_peer_index->peer = peer;
    return addr_peer_index;
}

static skt_udp_peer_t* init_peer(int fd, struct sockaddr_in remote_addr, skcptun_t* skt) {
    skt_udp_peer_t* peer = (skt_udp_peer_t*)calloc(1, sizeof(skt_udp_peer_t));
    if (!peer) {
        perror("alloc");
        return NULL;
    }
    peer->fd = fd;
    peer->remote_addr = remote_addr;
    peer->skt = skt;
    // peer->send_queue = packet_queue_create();
    // if (!peer->send_queue) {
    //     perror("packet_queue_create");
    //     free(peer);
    //     return NULL;
    // }
    return peer;
}
static void free_peer(skt_udp_peer_t* peer) {
    if (!peer) return;
    if (peer->fd > 0) {
        close(peer->fd);
        peer->fd = -1;
    }
    // if (peer->send_queue) {
    //     packet_queue_destroy(peer->send_queue);
    //     peer->send_queue = NULL;
    // }
    free(peer);
}

// skt_udp_peer_t* skt_udp_start(const char* local_ip, uint16_t local_port, const char* remote_ip, uint16_t remote_port,
//                               skcptun_t* skt) {
//     skt_udp_peer_t peer;
//     memset(&peer, 0, sizeof(peer));
//     peer.fd = socket(AF_INET, SOCK_DGRAM, 0);
//     if (peer.fd < 0) {
//         perror("socket");
//         return NULL;
//     }
//     if (skt_set_nonblocking(peer.fd) != _OK) {
//         return NULL;
//     }
//     if (local_ip && strnlen(local_ip, INET_ADDRSTRLEN) > 0 && local_port > 0) {
//         memset(&peer.local_addr, 0, sizeof(peer.local_addr));
//         peer.local_addr.sin_family = AF_INET;
//         peer.local_addr.sin_port = htons(local_port);
//         if (inet_pton(AF_INET, local_ip, &peer.local_addr.sin_addr) <= 0) {
//             perror("inet_pton local");
//             close(peer.fd);
//             return NULL;
//         }
//         if (bind(peer.fd, (struct sockaddr*)&peer.local_addr, sizeof(peer.local_addr)) < 0) {
//             perror("bind");
//             close(peer.fd);
//             return NULL;
//         }
//     }
//     if (remote_ip && strnlen(remote_ip, INET_ADDRSTRLEN) > 0 && remote_port > 0) {
//         memset(&peer.remote_addr, 0, sizeof(peer.remote_addr));
//         peer.remote_addr.sin_family = AF_INET;
//         peer.remote_addr.sin_port = htons(remote_port);
//         if (inet_pton(AF_INET, remote_ip, &peer.remote_addr.sin_addr) <= 0) {
//             perror("inet_pton remote");
//             close(peer.fd);
//             return NULL;
//         }
//     }
//     if (skt_udp_peer_add(peer.fd, peer.remote_addr, skt) != _OK) {
//         close(peer.fd);
//         return NULL;
//     }
//     skt_udp_peer_t* p = skt_udp_peer_get(peer.fd, peer.remote_addr.sin_addr.s_addr);
//     return p;
// }

int skt_udp_peer_add(int fd, struct sockaddr_in remote_addr, skcptun_t* skt) {
    if (skt_udp_peer_get(fd, remote_addr.sin_addr.s_addr)) {
        _LOG_E("peer already exist. skt_udp_peer_add");
        return _ERR;
    }
    skt_udp_peer_t* peer = init_peer(fd, remote_addr, skt);
    if (!peer) {
        return _ERR;
    }
    addr_peer_index_t* addr_peer_index = init_addr_peer_index(peer);
    if (!addr_peer_index) {
        free_peer(peer);
        return _ERR;
    }
    HASH_ADD_INT(g_addr_peer_index, addr, addr_peer_index);
    return _OK;
}

void skt_udp_peer_del(int fd, uint32_t remote_addr) {
    addr_peer_index_t* addr_peer_index = NULL;
    HASH_FIND_INT(g_addr_peer_index, &remote_addr, addr_peer_index);
    if (!addr_peer_index) return;
    assert(addr_peer_index->peer);
    free_peer(addr_peer_index->peer);
    HASH_DEL(g_addr_peer_index, addr_peer_index);
    free(addr_peer_index);
    return;
}

skt_udp_peer_t* skt_udp_peer_get(int fd, uint32_t remote_addr) {
    addr_peer_index_t* addr_peer_index = NULL;
    HASH_FIND_INT(g_addr_peer_index, &remote_addr, addr_peer_index);
    if (!addr_peer_index) {
        return NULL;
    }
    assert(fd == addr_peer_index->peer->fd);
    return addr_peer_index->peer;
}

void skt_udp_peer_iter(void (*iter)(skt_udp_peer_t* peer)) {
    addr_peer_index_t *addr_peer_index = NULL, *tmp = NULL;
    HASH_ITER(hh, g_addr_peer_index, addr_peer_index, tmp) { iter(addr_peer_index->peer); }
}

static void print_addr_peer_index(const addr_peer_index_t* addr_peer_index) {
    if (addr_peer_index == NULL) {
        _LOG_E("addr_peer_index is NULL");
        return;
    }
    _LOG_E("addr_peer_index:");
    _LOG_E("  addr: %u", addr_peer_index->addr);
    const skt_udp_peer_t* peer = addr_peer_index->peer;
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

void skt_udp_peer_info() {
    _LOG_E("---------- peers info ----------");
    unsigned int peers_cnt = HASH_COUNT(g_addr_peer_index);
    _LOG_E("udp peers count: %u", peers_cnt);
    addr_peer_index_t *addr_peer_index = NULL, *tmp = NULL;
    HASH_ITER(hh, g_addr_peer_index, addr_peer_index, tmp) { print_addr_peer_index(addr_peer_index); }
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
    addr_peer_index_t *addr_peer_index, *tmp;
    HASH_ITER(hh, g_addr_peer_index, addr_peer_index, tmp) {
        if (addr_peer_index->peer) {
            free_peer(addr_peer_index->peer);
            addr_peer_index->peer = NULL;
        }
        HASH_DEL(g_addr_peer_index, addr_peer_index);
        free(addr_peer_index);
    }
    g_addr_peer_index = NULL;
    _LOG("skt_udp_peer_cleanup");
}