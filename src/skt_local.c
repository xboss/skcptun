#include "skt_local.h"

#include "skt_kcp_conn.h"

// recv auth resp format: cmd(1B)|ticket(32B)|cid(4B)|timestamp(8B)
static void on_cmd_auth_resp(skcptun_t* skt, skt_packet_t* pkt, struct sockaddr_in remote_addr, skt_udp_peer_t* peer) {
    if (pkt->payload_len < 12) {
        _LOG_E("invalid auth resp. len: %d", pkt->payload_len);
        return;
    }
    if (!peer) {
        /* TODO: update remote_addr? */
        return;
    }
    if (peer->cid > 0) {
        _LOG("already authed");
        return;
    }
    uint32_t cid = ntohl(*(uint32_t*)(pkt->payload));
    uint32_t tun_ip = ntohl(*(uint32_t*)(pkt->payload + 4));

    /* TODO: */
    // skt->tun_fd = skt_start_tun(skt->conf->tun_dev, skt->conf->tun_ip, skt->conf->tun_netmask, skt->conf->tun_mtu);

    // new kcp connection
    skt_kcp_conn_t* kcp_conn = skt_kcp_conn_add(tun_ip, peer, skt);
    if (!kcp_conn) {
        skt_udp_peer_del(peer->fd, peer->remote_addr.sin_addr.s_addr);
        return;
    }
    kcp_conn->kcp = ikcp_create(kcp_conn->cid, kcp_conn);
    peer->cid = kcp_conn->cid;

    // start tun dev

    uint32_t my_tun_ip = 0;
    if (inet_pton(AF_INET, skt->conf->tun_ip, &my_tun_ip) != 1) {
        skt_udp_peer_del(peer->fd, peer->remote_addr.sin_addr.s_addr);
        return;
    }
    assert(my_tun_ip > 0);
    uint32_t vt_ip = my_tun_ip + 1; /* TODO: gen and check virtual ip */
    uint32_t vt_ip_net = htonl(vt_ip);

    // send auth resp format: cmd(1B)|ticket(32B)|cid(4B)|virtual ip(4b)|timestamp(8B)
    uint32_t cid_net = htonl(kcp_conn->cid);
    uint64_t timestamp_net = htonll(skt_mstime());
    char payload[16] = {0};
    memcpy(payload, &cid_net, sizeof(uint32_t));
    memcpy(payload, &vt_ip_net, sizeof(uint32_t));
    memcpy(payload, &timestamp_net, sizeof(uint64_t));
    char raw[SKT_MTU] = {0};
    int raw_len = 0;
    if (skt_pack(skt, SKT_PKT_CMD_AUTH_RESP, pkt->ticket, payload, sizeof(payload), raw, &raw_len)) {
        ikcp_release(kcp_conn->kcp);
        skt_kcp_conn_del(kcp_conn);
        skt_udp_peer_del(peer->fd, peer->remote_addr.sin_addr.s_addr);
        return;
    }
    assert(raw_len > 0);
    if (sendto(peer->fd, raw, raw_len, 0, (struct sockaddr*)&peer->remote_addr, sizeof(peer->remote_addr)) == -1) {
        _LOG_E("sendto failed when send auth resp, fd:%d", peer->fd);
        ikcp_release(kcp_conn->kcp);
        skt_kcp_conn_del(kcp_conn);
        skt_udp_peer_del(peer->fd, peer->remote_addr.sin_addr.s_addr);
    }
}

static void on_cmd_data(skcptun_t* skt, skt_packet_t* pkt, struct sockaddr_in remote_addr, skt_udp_peer_t* peer) {
    /* TODO: */
    if (!peer) {
        _LOG_E("peer does not exists. on_cmd_data");
        return;
    }

    // check is kcp packet
    if (pkt->payload_len < SKT_KCP_HEADER_SZIE) {
        _LOG_E("invalid kcp packet, payload_len:%d", pkt->payload_len);
    }
    // get cid
    uint32_t cid = ikcp_getconv(pkt->payload);
    // check is conn exists
    skt_kcp_conn_t* kcp_conn = skt_kcp_conn_get_by_cid(cid);
    if (!kcp_conn) {
        _LOG_E("invalid cid:%d", cid);
        return;
    }
    // ikcp_input
    int ret = ikcp_input(kcp_conn->kcp, pkt->payload, pkt->payload_len);
    assert(ret == 0);
    ikcp_update(kcp_conn->kcp, SKT_MSTIME32);
    do {
        int peeksize = ikcp_peeksize(kcp_conn->kcp);
        if (peeksize <= 0) {
            break;
        }
        // kcp recv
        char recv_buf[SKT_MTU - SKT_PKT_CMD_SZIE - SKT_TICKET_SIZE] = {0};
        assert(peeksize <= sizeof(recv_buf));
        int recv_len = ikcp_recv(kcp_conn->kcp, recv_buf, peeksize);
        if (recv_len > 0) {
            ikcp_update(kcp_conn->kcp, SKT_MSTIME32);
            kcp_conn->last_r_tm = skt_mstime();
        }
        // send to tun
        if (tun_write(skt->tun_fd, recv_buf, recv_len) <= 0) {
            _LOG_E("tun_write failed");
        }
    } while (1);
}

static void on_cmd_pong(skcptun_t* skt, skt_packet_t* pkt, struct sockaddr_in remote_addr, skt_udp_peer_t* peer) {
    // recv pong format: cmd(1B)|ticket(32B)|timestamp(8B)|cid(4B)
    if (pkt->payload_len < 12) {
        _LOG_E("invalid pong. len: %d", pkt->payload_len);
        return;
    }

    /* TODO: */
    uint32_t cid = ntohl(*(uint32_t*)(pkt->payload + 8));
    skt_kcp_conn_t* kcp_conn = skt_kcp_conn_get_by_cid(cid);
    if (!kcp_conn) {
        _LOG_E("kcp_conn does not exists. on_cmd_ping cid:%u", cid);
        /* TODO: how? */
        return;
    }
    if (!peer) {
        // update remote_addr
        assert(kcp_conn->peer);
        assert(kcp_conn->peer->cid == cid);
        kcp_conn->peer->remote_addr = remote_addr;
        peer = kcp_conn->peer;
    } else {
        assert(peer == kcp_conn->peer);
    }

    // send pong format: cmd(1B)|ticket(32B)|timestamp(8B)|cid(4B)
    // reuse pkt->payload
    uint64_t timestamp_net = htonll(skt_mstime());
    memcpy(pkt->payload, &timestamp_net, sizeof(timestamp_net));

    char raw[SKT_MTU] = {0};
    int raw_len = 0;
    if (skt_pack(skt, SKT_PKT_CMD_AUTH_RESP, pkt->ticket, pkt->payload, 12, raw, &raw_len)) {
        return;
    }
    assert(raw_len > 0);
    if (sendto(peer->fd, raw, raw_len, 0, (struct sockaddr*)&peer->remote_addr, sizeof(peer->remote_addr)) == -1) {
        _LOG_E("sendto failed when send auth resp, fd:%d", peer->fd);
    }
}

static void dispatch_cmd(skcptun_t* skt, skt_packet_t* pkt, struct sockaddr_in remote_addr, skt_udp_peer_t* peer) {
    if (!pkt) return;
    switch (pkt->cmd) {
        case SKT_PKT_CMD_DATA:
            on_cmd_data(skt, pkt, remote_addr, peer);
            /* TODO: */
            break;
        case SKT_PKT_CMD_AUTH_RESP:
            on_cmd_auth_resp(skt, pkt, remote_addr, peer);
            /* TODO: */
            break;
        case SKT_PKT_CMD_PONG:
            on_cmd_pong(skt, pkt, remote_addr, peer);
            /* TODO: */
            break;
        case SKT_PKT_CMD_CLOSE:
            /* TODO: */
            break;

        default:
            _LOG_E("unknown cmd. %x", pkt->cmd);
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
    int raw_len = 0;
    struct sockaddr_in remote_addr;
    socklen_t ra_len;
    int rlen = recvfrom(skt->udp_fd, raw, raw_len, 0, (struct sockaddr*)&remote_addr, &ra_len);
    if (rlen < 0) {
        perror("udp recv");
        return;
    }

    skt_udp_peer_t* peer = skt_udp_peer_get(skt->udp_fd, remote_addr.sin_addr.s_addr);

    char cmd = 0x00;
    char ticket[SKT_TICKET_SIZE] = {0};
    char payload[SKT_MTU - SKT_TICKET_SIZE - SKT_PKT_CMD_SZIE] = {0};
    int payload_len = 0;
    if (skt_unpack(skt, raw, rlen, &cmd, ticket, payload, &payload_len) != _OK) return;
    assert(payload_len > 0);

    // check ticket
    if (strncmp(skt->conf->ticket, ticket, SKT_TICKET_SIZE) != 0) {
        _LOG("invalid ticket in auth");
        return;
    }

    skt_packet_t pkt = {.cmd = cmd, .ticket = ticket, .payload = payload, .payload_len = payload_len};
    dispatch_cmd(skt, &pkt, remote_addr, peer);

    // check phase

    /* TODO: */
}

////////////////////////////////
// API
////////////////////////////////

int skt_local_start(skcptun_t* skt) {
    // init udp data channel
    skt_udp_peer_t* peer = skt_udp_peer_start(skt->conf->udp_local_ip, skt->conf->udp_local_port,
                                              skt->conf->udp_remote_ip, skt->conf->udp_remote_port);
    if (peer == NULL) {
        return _ERR;
    }
    skt->udp_fd = peer->fd;

    ev_io_init(skt->tun_io_watcher, tun_read_cb, skt->tun_fd, EV_READ);
    ev_io_start(skt->loop, skt->tun_io_watcher);

    ev_io_init(skt->udp_io_watcher, udp_read_cb, skt->udp_fd, EV_READ);
    ev_io_start(skt->loop, skt->udp_io_watcher);

    ev_timer_init(skt->timeout_watcher, timeout_cb, 0, 1); /* TODO: config */
    ev_timer_start(skt->loop, skt->timeout_watcher);

    ev_timer_init(skt->kcp_update_watcher, timeout_cb, 0, skt->conf->interval / 1000.0);
    ev_timer_start(skt->loop, skt->kcp_update_watcher);

    return _OK;
}

void skt_local_stop(skcptun_t* skt) {
    /* TODO: */
    return _OK;
}