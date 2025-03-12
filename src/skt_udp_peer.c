#include "skt_udp_peer.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>

typedef struct {
    uint32_t addr;
    skt_udp_peer_t* peer;
    UT_hash_handle hh;
} addr_peer_index_t;

static addr_peer_index_t* g_addr_peer_index = NULL;

int set_nonblocking(int fd) {
    // 获取当前的文件状态标志
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        perror("Error getting file flags");
        return _ERR;
    }

    // 设置非阻塞标志
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("Error setting file to non-blocking mode");
        return _ERR;
    }
    return _OK;
}

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
skt_udp_peer_t* skt_udp_peer_start(const char* local_ip, uint16_t local_port, const char* remote_ip,
                                   uint16_t remote_port) {
    skt_udp_peer_t* peer = (skt_udp_peer_t*)calloc(1, sizeof(skt_udp_peer_t));
    if (!peer) {
        perror("alloc");
        return NULL;
    }

    peer->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (peer->fd < 0) {
        perror("socket");
        free(peer);
        return NULL;
    }
    if (set_nonblocking(peer->fd) != _OK) {
        free(peer);
        return NULL;
    }

    if (local_ip && strnlen(local_ip, INET_ADDRSTRLEN) > 0 && local_port > 0) {
        memset(&peer->local_addr, 0, sizeof(peer->local_addr));
        peer->local_addr.sin_family = AF_INET;
        peer->local_addr.sin_port = htons(local_port);
        if (inet_pton(AF_INET, local_ip, &peer->local_addr.sin_addr) <= 0) {
            perror("inet_pton local");
            close(peer->fd);
            free(peer);
            return NULL;
        }
        if (bind(peer->fd, (struct sockaddr*)&peer->local_addr, sizeof(peer->local_addr)) < 0) {
            perror("bind");
            close(peer->fd);
            free(peer);
            return NULL;
        }
    }

    if (remote_ip && strnlen(remote_ip, INET_ADDRSTRLEN) > 0 && remote_port > 0) {
        memset(&peer->remote_addr, 0, sizeof(peer->remote_addr));
        peer->remote_addr.sin_family = AF_INET;
        peer->remote_addr.sin_port = htons(remote_port);
        if (inet_pton(AF_INET, remote_ip, &peer->remote_addr.sin_addr) <= 0) {
            perror("inet_pton remote");
            close(peer->fd);
            free(peer);
            return NULL;
        }
    }

    if (skt_udp_peer_add(peer) != _OK) {
        close(peer->fd);
        free(peer);
        return NULL;
    }

    return peer;
}

int skt_udp_peer_add(skt_udp_peer_t* peer) {
    if (skt_udp_peer_get(peer->fd, peer->remote_addr.sin_addr.s_addr)) {
        _LOG_E("peer already exist. skt_udp_peer_add");
        return _ERR;
    }
    addr_peer_index_t* addr_peer_index = init_addr_peer_index(peer);
    if (!addr_peer_index) {
        close(peer->fd);
        free(peer);
        return _ERR;
    }
    HASH_ADD_INT(g_addr_peer_index, addr, addr_peer_index);
    return _OK;
}

void skt_udp_peer_del(int fd, uint32_t remote_addr) {
    addr_peer_index_t* addr_peer_index = NULL;
    HASH_FIND_INT(g_addr_peer_index, &remote_addr, addr_peer_index);
    if (addr_peer_index) {
        HASH_DEL(g_addr_peer_index, addr_peer_index);
        free(addr_peer_index);
    }
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

// ssize_t skt_udp_peer_send(skt_udp_peer_t* peer, const void* buf, size_t len) {
//     return sendto(peer->fd, buf, len, 0, (struct sockaddr*)&peer->remote_addr, sizeof(peer->remote_addr));
// }

// ssize_t skt_udp_peer_recv(skt_udp_peer_t* peer, void* buf, size_t len) {
//     return recvfrom(peer->fd, buf, len, 0, (struct sockaddr*)&peer->remote_addr, &peer->ra_len);
// }

void skt_udp_peer_free(skt_udp_peer_t* peer) {
    if (peer) {
        close(peer->fd);
        free(peer);
    }
}

void skt_udp_peer_iter(void (*iter)(skt_udp_peer_t* peer)) {
    addr_peer_index_t *addr_peer_index = NULL, *tmp = NULL;
    HASH_ITER(hh, g_addr_peer_index, addr_peer_index, tmp) { iter(addr_peer_index->peer); }
}

static void print_addr_peer_index(const addr_peer_index_t* addr_peer_index) {
    if (addr_peer_index == NULL) {
        printf("addr_peer_index is NULL\n");
        return;
    }
    printf("addr_peer_index:\n");
    printf("  addr: %u\n", addr_peer_index->addr);
    const skt_udp_peer_t* peer = addr_peer_index->peer;
    if (peer == NULL) {
        printf("  peer is NULL\n");
        return;
    }
    char remote_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &peer->remote_addr.sin_addr, remote_ip, INET_ADDRSTRLEN);
    printf("  peer:\n");
    printf("    fd: %d\n", peer->fd);
    printf("    remote_addr: %s:%d\n", remote_ip, ntohs(peer->remote_addr.sin_port));
    char local_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &peer->local_addr.sin_addr, local_ip, INET_ADDRSTRLEN);
    printf("    local_addr: %s:%d\n", local_ip, ntohs(peer->local_addr.sin_port));
    printf("    cid: %u\n", peer->cid);
    printf("    ticket: %s\n", peer->ticket);
    printf("    last_r_tm: %lu\n", peer->last_r_tm);
    printf("    last_w_tm: %lu\n", peer->last_w_tm);
}

void skt_udp_peer_info() {
    printf("---------- peers info ----------\n");
    unsigned int peers_cnt = HASH_COUNT(g_addr_peer_index);
    printf("udp peers count: %u\n", peers_cnt);
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
    _LOG("skt_pack payload_len:%d, kcp_mtu:%d, tun_mtu:%d", payload_len, skt->conf->kcp_mtu, skt->conf->tun_mtu);
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
    assert(raw_len <= skt->conf->mtu);
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
