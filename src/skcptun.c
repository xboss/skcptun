
#define _XOPEN_SOURCE 700

#include "skcptun.h"

#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "tun.h"



// #define SKT_PKT_HEADER_SZIE 4
// #define MAX_DATA_PAYLOAD_SZIE (1024 * 2)
// #define RECV_DATA_BUF_SIZE ((MAX_DATA_PAYLOAD_SZIE + SKT_PKT_HEADER_SZIE) * 5)
// #define MAX_CTRL_PAYLOAD_SZIE (128)
// #define RECV_CTRL_BUF_SIZE (MAX_CTRL_PAYLOAD_SZIE + SKT_PKT_HEADER_SZIE)
// #define RECV_TIMEOUT 1000 * 60 * 5
// #define SEND_TIMEOUT 1000 * 60 * 5
// #define POLL_TIMEOUT 1000

#define _IS_SECRET (strlen((const char*)skt->conf->key) > 0 && strlen((const char*)skt->conf->iv) > 0)

////////////////////////////////
// tools
////////////////////////////////

inline static uint64_t mstime() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t millisecond = (tv.tv_sec * 1000000l + tv.tv_usec) / 1000l;
    return millisecond;
}

static void print_hex(const char* label, const unsigned char* data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

////////////////////////////////
// protocol
////////////////////////////////



// cmd(1B)ticket(32)payload(mtu-32B-1B)

 int skt_pack(skcptun_t* skt, char cmd, const char* ticket, const char* payload, int payload_len, char* raw, int* raw_len) {
    assert(payload_len <= skt->conf->tun_mtu - SKT_TICKET_SIZE - SKT_PKT_CMD_SZIE);
    if (_IS_SECRET) {
        char cipher_buf[SKT_MTU] = {0};
        memcpy(cipher_buf, &cmd, SKT_PKT_CMD_SZIE);
        memcpy(cipher_buf + SKT_PKT_CMD_SZIE, ticket, SKT_TICKET_SIZE);
        memcpy(cipher_buf + SKT_PKT_CMD_SZIE + SKT_TICKET_SIZE, payload, payload_len);
        if (crypto_encrypt(skt->conf->key, skt->conf->iv, (const unsigned char*)&cipher_buf, (size_t)(payload_len + SKT_TICKET_SIZE + SKT_PKT_CMD_SZIE), (unsigned char*)raw, (size_t*)raw_len)) {
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

 int skt_unpack(skcptun_t* skt, const char* raw, int raw_len, char* cmd, char* ticket, char* payload, int *payload_len) {
    assert(raw_len <= skt->conf->kcp_mtu);
    assert(raw_len > SKT_PKT_CMD_SZIE + SKT_TICKET_SIZE);
    char* p = (char*)raw;
    if (_IS_SECRET) {
        char cipher_buf[SKT_MTU] = {0};
        int cipher_len = 0;
        if (crypto_decrypt(skt->conf->key, skt->conf->iv, (const unsigned char*)raw, raw_len, (unsigned char*)cipher_buf, (size_t*)&cipher_len)) {
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

////////////////////////////////
// callback
////////////////////////////////

static int udp_output(const char* buf, int len, ikcpcb* kcp, void* user) {
    /* TODO: */
    return 0;
}

////////////////////////////////
// skcptun API
////////////////////////////////

skcptun_t* skt_init(skt_config_t* conf, struct ev_loop* loop) {
    if (!conf) return NULL;
    if (conf->tun_mtu + SKT_TICKET_SIZE > conf->kcp_mtu || conf->tun_mtu + SKT_TICKET_SIZE > SKT_MTU || conf->kcp_mtu > SKT_MTU) {
        _LOG_E("MTU error");
        return NULL;
    }

    skcptun_t* skt = (skcptun_t*)calloc(1, sizeof(skcptun_t));
    if (skt == NULL) {
        perror("calloc");
        return NULL;
    }
    skt->conf = conf;
    skt->running = 0;

    // Allocate TUN device
    skt->tun_fd = tun_alloc(conf->tun_dev, IFNAMSIZ);
    if (skt->tun_fd < 0) {
        perror("tun_alloc");
        skt_free(skt);
        return NULL;
    }

    // Set TUN device IP
    if (tun_set_ip(conf->tun_dev, conf->tun_ip) < 0) {
        perror("tun_set_ip");
        skt_free(skt);
        return NULL;
    }

    // Set TUN device netmask
    if (tun_set_netmask(conf->tun_dev, conf->tun_netmask) < 0) {
        perror("tun_set_netmask");
        skt_free(skt);
        return NULL;
    }

    // Set TUN device MTU
    if (tun_set_mtu(conf->tun_dev, conf->tun_mtu) < 0) {
        perror("tun_set_mtu");
        skt_free(skt);
        return NULL;
    }

    // Bring up TUN device
    if (tun_up(conf->tun_dev) < 0) {
        perror("tun_up");
        skt_free(skt);
        return NULL;
    }

    // // init udp data channel
    // skt->udp = ssudp_init(conf->udp_local_ip, conf->udp_local_port, conf->udp_remote_ip, conf->udp_remote_port);
    // if (skt->udp == NULL) {
    //     skt_free(skt);
    //     return NULL;
    // }

    skt->loop = loop;
    skt->timeout_watcher = (ev_timer*)calloc(1, sizeof(ev_timer));
    if (!skt->timeout_watcher) {
        perror("alloc timeout_watcher");
        skt_free(skt);
        return NULL;
    }
    skt->timeout_watcher->data = skt;

    skt->tun_io_watcher = (ev_io*)calloc(1, sizeof(ev_io));
    if (!skt->tun_io_watcher) {
        perror("alloc tun_io_watcher");
        skt_free(skt);
        return NULL;
    }
    skt->tun_io_watcher->data = skt;

    skt->udp_io_watcher = (ev_io*)calloc(1, sizeof(ev_io));
    if (!skt->udp_io_watcher) {
        perror("alloc udp_io_watcher");
        skt_free(skt);
        return NULL;
    }
    skt->udp_io_watcher->data = skt;

    return NULL;
}

void skt_free(skcptun_t* skt) {
    /* TODO: */
    return;
}
