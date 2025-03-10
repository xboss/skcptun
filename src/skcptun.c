
#define _XOPEN_SOURCE 700

#include "skcptun.h"

// #define SKT_PKT_HEADER_SZIE 4
// #define MAX_DATA_PAYLOAD_SZIE (1024 * 2)
// #define RECV_DATA_BUF_SIZE ((MAX_DATA_PAYLOAD_SZIE + SKT_PKT_HEADER_SZIE) * 5)
// #define MAX_CTRL_PAYLOAD_SZIE (128)
// #define RECV_CTRL_BUF_SIZE (MAX_CTRL_PAYLOAD_SZIE + SKT_PKT_HEADER_SZIE)
// #define RECV_TIMEOUT 1000 * 60 * 5
// #define SEND_TIMEOUT 1000 * 60 * 5
// #define POLL_TIMEOUT 1000

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
    if (conf->tun_mtu + SKT_TICKET_SIZE > conf->kcp_mtu || conf->tun_mtu + SKT_TICKET_SIZE > SKT_MTU ||
        conf->kcp_mtu > SKT_MTU) {
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

    skt->kcp_update_watcher = (ev_timer*)calloc(1, sizeof(ev_timer));
    if (!skt->kcp_update_watcher) {
        perror("alloc kcp_update_watcher");
        skt_free(skt);
        return NULL;
    }
    skt->kcp_update_watcher->data = skt;

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

    return skt;
}

void skt_free(skcptun_t* skt) {
    /* TODO: */
    return;
}

int skt_start_tun(char* tun_dev, char* tun_ip, char* tun_netmask, int tun_mtu) {
    // Allocate TUN device
    int tun_fd = tun_alloc(tun_dev, IFNAMSIZ);
    if (tun_fd < 0) {
        perror("tun_alloc");
        return _ERR;
    }

    // Set TUN device IP
    if (tun_set_ip(tun_dev, tun_ip) < 0) {
        perror("tun_set_ip");
        return _ERR;
    }

    // Set TUN device netmask
    if (tun_set_netmask(tun_dev, tun_netmask) < 0) {
        perror("tun_set_netmask");
        return _ERR;
    }

    // Set TUN device MTU
    if (tun_set_mtu(tun_dev, tun_mtu) < 0) {
        perror("tun_set_mtu");
        return _ERR;
    }

    // Bring up TUN device
    if (tun_up(tun_dev) < 0) {
        perror("tun_up");
        return _ERR;
    }
    return tun_fd;
}