
#define _XOPEN_SOURCE 700

#include "skcptun.h"

#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "tun.h"


#define SKT_PKT_HEADER_SZIE 4
#define MAX_DATA_PAYLOAD_SZIE (1024 * 2)
#define RECV_DATA_BUF_SIZE ((MAX_DATA_PAYLOAD_SZIE + SKT_PKT_HEADER_SZIE) * 5)
#define MAX_CTRL_PAYLOAD_SZIE (128)
// #define RECV_CTRL_BUF_SIZE (MAX_CTRL_PAYLOAD_SZIE + SKT_PKT_HEADER_SZIE)
#define RECV_TIMEOUT 1000 * 60 * 5
#define SEND_TIMEOUT 1000 * 60 * 5
#define POLL_TIMEOUT 1000

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

inline static int pack(skcptun_t* skt, char* payload, int payload_len, char* pkt, int* pkt_len) {
    int cipher_len = 0;
    int payload_len_net = htonl(payload_len);
    memcpy(pkt, &payload_len_net, SKT_PKT_HEADER_SZIE);
    *pkt_len += SKT_PKT_HEADER_SZIE;
    if (_IS_SECRET) {
        if (crypto_encrypt(skt->conf->key, skt->conf->iv, (const unsigned char*)&payload, (size_t)payload_len, (unsigned char*)pkt + SKT_PKT_HEADER_SZIE, (size_t*)&cipher_len)) {
            _LOG_E("crypto encrypt failed");
            return _ERR;
        }
        assert(cipher_len == payload_len && cipher_len > 0);
        *pkt_len += cipher_len;
    } else {
        memcpy(pkt + SKT_PKT_HEADER_SZIE, payload, payload_len);
        *pkt_len += payload_len;
    }
    return _OK;
}

inline static int unpack(skcptun_t* skt, char* pkt, int pkt_len, char* payload, int* payload_len) {
    if (_IS_SECRET) {
        int cipher_len = 0;
        if (crypto_decrypt(skt->conf->key, skt->conf->iv, (const unsigned char*)pkt + SKT_PKT_HEADER_SZIE, pkt_len - SKT_PKT_HEADER_SZIE, (unsigned char*)payload, (size_t*)&cipher_len)) {
            _LOG_E("crypto decrypt failed when do_auth");
            assert(cipher_len == pkt_len - SKT_PKT_HEADER_SZIE);
            *payload_len += cipher_len;
            return _ERR;
        } else {
            memcpy(payload, pkt + SKT_PKT_HEADER_SZIE, pkt_len - SKT_PKT_HEADER_SZIE);
            *payload_len += pkt_len - SKT_PKT_HEADER_SZIE;
        }
    }
    return _OK;
}

////////////////////////////////
// controller channel
////////////////////////////////

static int udp_output(const char* buf, int len, ikcpcb* kcp, void* user) {
    /* TODO: */
    return 0;
}

static void timeout_cb(struct ev_loop* loop, ev_timer* watcher, int revents) {
    if (EV_ERROR & revents) {
        _LOG("timeout_cb got invalid event");
        return;
    }
}

static void tun_read_cb(struct ev_loop* loop, struct ev_io* watcher, int revents) {
    if (EV_ERROR & revents) {
        _LOG("tun_read_cb got invalid event");
        return;
    }
}

static void udp_read_cb(struct ev_loop* loop, struct ev_io* watcher, int revents) {
    if (EV_ERROR & revents) {
        _LOG("udp_read_cb got invalid event");
        return;
    }
}

////////////////////////////////
// API
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

    // init udp data channel
    skt->udp = ssudp_init(conf->udp_local_ip, conf->udp_local_port, conf->udp_remote_ip, conf->udp_remote_port);
    if (skt->udp == NULL) {
        skt_free(skt);
        return NULL;
    }
    skt->loop = loop;
    skt->timeout_watcher = (ev_timer*)calloc(1, sizeof(ev_timer));
    if (!skt->timeout_watcher) {
        perror("alloc timeout_watcher");
        skt_free(skt);
        return NULL;
    }
    ev_timer_init(skt->timeout_watcher, timeout_cb, 0, conf->interval);
    ev_timer_start(loop, skt->timeout_watcher);

    skt->tun_io_watcher = (ev_io*)calloc(1, sizeof(ev_io));
    if (!skt->tun_io_watcher) {
        perror("alloc tun_io_watcher");
        skt_free(skt);
        return NULL;
    }
    ev_io_init(skt->tun_io_watcher, tun_read_cb, skt->tun_fd, EV_READ);
    ev_io_start(skt->loop, skt->tun_io_watcher);

    skt->udp_io_watcher = (ev_io*)calloc(1, sizeof(ev_io));
    if (!skt->udp_io_watcher) {
        perror("alloc udp_io_watcher");
        skt_free(skt);
        return NULL;
    }
    ev_io_init(skt->udp_io_watcher, udp_read_cb, skt->udp->fd, EV_READ);
    ev_io_start(skt->loop, skt->udp_io_watcher);

    return NULL;
}

void skt_free(skcptun_t* skt) {
    /* TODO: */
    return;
}
