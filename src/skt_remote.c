#include "skt_remote.h"

#include <stdio.h>

static void on_cmd_auth_req(skcptun_t* skt, skt_packet_t* pkt) {
    // check ticket
    // gen cid
    // gen virtual ip

    // send resp
}

static void on_cmd_data(skcptun_t* skt, skt_packet_t* pkt) {
    // check ticket
    // check is kcp packet
    // get cid
    // check is conn exists
    // ikcp_input
    // kcp recv
    // send to tun
}

static void dispatch_cmd(skcptun_t* skt, skt_packet_t* pkt) {
    if (!pkt) return;
    switch (pkt->cmd) {
        case SKT_PKT_CMD_DATA:
            /* TODO: */
            break;
        case SKT_PKT_CMD_AUTH_REQ:
            /* TODO: */
            break;
        case SKT_PKT_CMD_PING:
            /* TODO: */
            break;
        case SKT_PKT_CMD_CLOSE:
            /* TODO: */
            break;

        default:
            break;
    }
}

////////////////////////////////
// callback
////////////////////////////////

static void timeout_cb(struct ev_loop* loop, ev_timer* watcher, int revents) {
    if (EV_ERROR & revents) {
        _LOG("timeout_cb got invalid event");
        return;
    }
    skcptun_t* skt = (skcptun_t*)watcher->data;
    assert(skt);
    /* TODO: */
}

static void tun_read_cb(struct ev_loop* loop, struct ev_io* watcher, int revents) {
    if (EV_ERROR & revents) {
        _LOG("tun_read_cb got invalid event");
        return;
    }
    skcptun_t* skt = (skcptun_t*)watcher->data;
    assert(skt);
    /* TODO: */
}

static void udp_read_cb(struct ev_loop* loop, struct ev_io* watcher, int revents) {
    if (EV_ERROR & revents) {
        _LOG("udp_read_cb got invalid event");
        return;
    }
    skcptun_t* skt = (skcptun_t*)watcher->data;
    assert(skt);
    char raw[SKT_MTU] = {0};
    int rlen = ssudp_recv(skt->udp, raw, SKT_MTU);
    if (rlen < 0) {
        perror("udp recv");
        return;
    }

    char cmd = 0x00;
    char ticket[SKT_TICKET_SIZE] = {0};
    char payload[SKT_MTU - SKT_TICKET_SIZE - SKT_PKT_CMD_SZIE] = {0};
    int payload_len = 0;
    if (skt_unpack(skt, raw, rlen, &cmd, ticket, payload, &payload_len) != _OK) return;
    assert(payload_len > 0);

    skt_packet_t pkt = {.cmd = cmd, .ticket = ticket, .payload = payload, .payload_len = payload_len};
    dispatch_cmd(skt, &pkt);

    // check phase

    /* TODO: */
}

////////////////////////////////
// API
////////////////////////////////

int skt_remote_start(skcptun_t* skt) {
    ev_io_init(skt->tun_io_watcher, tun_read_cb, skt->tun_fd, EV_READ);
    ev_io_start(skt->loop, skt->tun_io_watcher);

    ev_io_init(skt->udp_io_watcher, udp_read_cb, skt->udp->fd, EV_READ);
    ev_io_start(skt->loop, skt->udp_io_watcher);

    ev_timer_init(skt->timeout_watcher, timeout_cb, 0, skt->conf->interval);
    ev_timer_start(skt->loop, skt->timeout_watcher);
    /* TODO: */
    return _OK;
}