#include "skt_remote.h"

#include <stdio.h>

#include "skt_conv.h"

static void on_cmd_auth_req(skcptun_t* skt, skt_packet_t* pkt) {
    // check ticket
    if (strncmp(skt->conf->ticket, pkt->ticket, SKT_TICKET_SIZE) != 0) {
        _LOG("invalid ticket in auth");
        return;
    }
    // gen cid
    int cid = skt_conv_gen_cid();

    // gen virtual ip
    uint32_t my_tun_ip = 0;
    if (inet_pton(AF_INET, skt->conf->tun_ip, &my_tun_ip) != 1) return;
    assert(my_tun_ip > 0);
    uint32_t vt_ip = my_tun_ip + 1; /* TODO: gen and check virtual ip */
    uint32_t vt_ip_net = htonl(vt_ip);

    // uint32_t src_addr_host_order = ntohl(src_addr_network_order);
    // inet_ntop(AF_INET, &src_addr_host_order, src_ip_str, INET_ADDRSTRLEN);

    // send resp
    char raw[SKT_MTU] = {0};
    int raw_len = 0;
    if (skt_pack(skt, SKT_PKT_CMD_AUTH_RESP, pkt->ticket, &vt_ip_net, sizeof(uint32_t), raw, &raw_len)) return;
    assert(raw_len > 0);
    ssudp_send(skt->udp, raw, raw_len);
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

    // init udp data channel
    skt->udp_peer = skt_udp_peer_init(skt->conf->udp_local_ip, skt->conf->udp_local_port, skt->conf->udp_remote_ip, skt->conf->udp_remote_port);
    if (skt->udp_peer == NULL) {
        return NULL;
    }
    // skt_kcp_conn_add(,)


    ev_io_init(skt->tun_io_watcher, tun_read_cb, skt->tun_fd, EV_READ);
    ev_io_start(skt->loop, skt->tun_io_watcher);

    ev_io_init(skt->udp_io_watcher, udp_read_cb, skt->udp_peer->fd, EV_READ);
    ev_io_start(skt->loop, skt->udp_io_watcher);

    ev_timer_init(skt->timeout_watcher, timeout_cb, 0, skt->conf->interval);
    ev_timer_start(skt->loop, skt->timeout_watcher);
    /* TODO: */
    return _OK;
}