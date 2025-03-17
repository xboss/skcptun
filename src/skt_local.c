#include "skt_local.h"

#include <errno.h>
#include <unistd.h>

static int send_auth_req(skcptun_t* skt, uint32_t cid, struct sockaddr_in remote_addr) {
    if (cid > 0 || !skt->running) {
        _LOG("no auth required");
        return _OK;
    }

    assert(skt->tun_ip_addr > 0);
    // send auth request format: cmd(1B)|ticket(32B)|tun_ip(4B)|timestamp(8B)
    uint32_t tun_ip_net = htonl(skt->tun_ip_addr);
    uint64_t timestamp_net = skt_htonll(skt_mstime());
    char payload[12] = {0};
    memcpy(payload, &tun_ip_net, 4);
    memcpy(payload + 4, &timestamp_net, 8);
    char raw[SKT_MTU] = {0};
    size_t raw_len = 0;
    if (skt_pack(skt, SKT_PKT_CMD_AUTH_REQ, skt->conf->ticket, payload, sizeof(payload), raw, &raw_len)) return _ERR;
    assert(raw_len > 0);
    if (sendto(skt->udp_fd, raw, raw_len, 0, (struct sockaddr*)&remote_addr, sizeof(remote_addr)) < 0) {
        _LOG_E("sendto failed when send auth resp, fd:%d", skt->udp_fd);
        return _ERR;
    }
    _LOG("send_auth_req ok.");
    return _OK;
}

// recv auth resp format: cmd(1B)|ticket(32B)|timestamp(8B)|cid(4B)|mtu(4B)|kcp_interval(4B)|speed_mode(1B)
static int on_cmd_auth_resp(skcptun_t* skt, skt_packet_t* pkt, skt_udp_peer_t* peer) {
    if (pkt->payload_len < 21) {
        _LOG_E("invalid auth resp. len: %d", pkt->payload_len);
        return _ERR;
    }
    uint32_t cid = ntohl(*(uint32_t*)(pkt->payload + 8));
    if (cid == 0) {
        _LOG("invalid cid");
        return _ERR;
    }
    if (peer->cid > 0) {
        _LOG("already authed");
        assert(cid == peer->cid);
        return _OK;
    }
    if (skt->conf->mtu <= 0) {
        skt->conf->mtu = ntohl(*(int*)(pkt->payload + 12));
        /* code */
    }
    if (skt->conf->mtu > SKT_MTU || skt->conf->mtu <= 0) {
        _LOG("invalid mtu in auth resp. %d", skt->conf->mtu);
        return _ERR;
    }
    skt->conf->kcp_mtu = SKT_ASSIGN_KCP_MTU(skt->conf->mtu);
    skt->conf->tun_mtu = SKT_ASSIGN_TUN_MTU(skt->conf->mtu);

    if (skt->conf->kcp_interval <= 0) {
        skt->conf->kcp_interval = ntohl(*(int*)(pkt->payload + 16));
    }
    if (skt->conf->kcp_interval <= 0 || skt->conf->kcp_interval > 9999999) {
        _LOG("invalid kcp_interval in auth resp. %d", skt->conf->kcp_interval);
        return _ERR;
    }
    skt->conf->speed_mode = (int)(pkt->payload[20] & 0x00ffu);
    skt_setup_kcp(skt);
    // uint32_t tun_ip = 0;
    // if (inet_pton(AF_INET, skt->conf->tun_ip, &tun_ip) <= 0) {
    //     perror("inet_pton");
    //     return _ERR;
    // }

    if (skt_setup_tun(skt) != _OK) {
        _LOG_E("skt_start_tun failed");
        return _ERR;
    }

    if (!skt->tun_r_watcher_started) {
        ev_io_start(skt->loop, skt->tun_r_watcher);
        skt->tun_r_watcher_started = 1;
    }

    assert(skt->tun_ip_addr > 0);
    // new kcp connection
    skt_kcp_conn_t* kcp_conn = skt_kcp_conn_add(cid, skt->tun_ip_addr, pkt->ticket, peer, skt);
    if (!kcp_conn) {
        return _ERR;
    }
    skt->local_cid = peer->cid = cid;
    // peer->last_r_tm = skt_mstime();
    _LOG("auth ok!");
    return _OK;
}

static int on_cmd_data(skcptun_t* skt, skt_packet_t* pkt, skt_udp_peer_t* peer) {
    // _LOG("on_cmd_data");
    if (skt_kcp_to_tun(skt, pkt) != _OK) return _ERR;
    return _OK;
}

static int on_cmd_pong(skcptun_t* skt, skt_packet_t* pkt, skt_udp_peer_t* peer) {
    // recv pong format: cmd(1B)|ticket(32B)|cid(4B)|timestamp(8B)
    if (pkt->payload_len < 12) {
        _LOG_E("invalid pong. len: %d", pkt->payload_len);
        return _ERR;
    }
    // uint64_t now = skt_mstime();
    uint32_t cid = ntohl(*(uint32_t*)(pkt->payload));
    skt_kcp_conn_t* kcp_conn = NULL;
    if (cid > 0) {
        kcp_conn = skt_kcp_conn_get_by_cid(cid);
        if (!kcp_conn) {
            _LOG_E("kcp_conn does not exists. on_cmd_pong cid:%u", cid);
            return _ERR;
        }
        assert(skt->local_cid == cid);
        // peer->last_r_tm = kcp_conn->last_r_tm = now;
        kcp_conn->peer = peer;
    } else {
        assert(skt->local_cid > 0);
        kcp_conn = skt_kcp_conn_get_by_cid(skt->local_cid);
        // trigger auth
        skt_close_kcp_conn(kcp_conn);
        // skt->local_cid = peer->cid = 0;
        // skt_kcp_conn_del(kcp_conn);
    }

    // _LOG("on_cmd_pong ok! cid:%u", cid);
    return _OK;
}

static int dispatch_cmd(skcptun_t* skt, skt_packet_t* pkt, skt_udp_peer_t* peer) {
    int ret = _OK;
    assert(pkt);
    switch (pkt->cmd) {
        case SKT_PKT_CMD_DATA:
            ret = on_cmd_data(skt, pkt, peer);
            break;
        case SKT_PKT_CMD_AUTH_RESP:
            ret = on_cmd_auth_resp(skt, pkt, peer);
            break;
        case SKT_PKT_CMD_PONG:
            ret = on_cmd_pong(skt, pkt, peer);
            break;

        default:
            _LOG_E("unknown cmd. %x", pkt->cmd);
            ret = _ERR;
            break;
    }
    if (ret == _OK) {
        peer->last_r_tm = skt_mstime();
    }

    return ret;
}

////////////////////////////////
// callback
////////////////////////////////

static void timeout_cb(struct ev_loop* loop, ev_timer* watcher, int revents) {
    if (EV_ERROR & revents) {
        _LOG_E("timeout_cb got invalid event");
        return;
    }
    skcptun_t* skt = (skcptun_t*)watcher->data;
    assert(skt);
    // if (!skt->running) {
    //     ev_timer_stop(loop, watcher);
    // }
    skt_kcp_conn_t* kcp_conn = skt_kcp_conn_get_by_cid(skt->local_cid);
    if (kcp_conn) {
        if (kcp_conn->peer->last_r_tm + skt->conf->keepalive < skt_mstime()) {
            // trigger auth
            _LOG("timeout_cb skt_close_kcp_conn trigger auth peer->last_r_tm:%llu", kcp_conn->peer->last_r_tm);
            skt_close_kcp_conn(kcp_conn);
            // skt->local_cid = kcp_conn->peer->cid = 0;
            // skt_kcp_conn_del(kcp_conn);
        }
    }

    if (skt->local_cid == 0) {
        send_auth_req(skt, skt->local_cid, skt->remote_addr);
        return;
    }
    // skt_kcp_conn_t* kcp_conn = skt_kcp_conn_get_by_cid(skt->local_cid);
    if (!kcp_conn) {
        _LOG_E(" timeout_cb got invalid kcp_conn. cid:%u", skt->local_cid);
        return;
    }
    assert(kcp_conn->peer);
    // send ping format: cmd(1B)|ticket(32B)|cid(4B)|timestamp(8B)
    char payload[12] = {0};
    uint32_t cid_net = htonl(kcp_conn->cid);
    uint64_t timestamp_net = skt_htonll(skt_mstime());
    memcpy(payload, &cid_net, sizeof(cid_net));
    memcpy(payload + 4, &timestamp_net, sizeof(timestamp_net));
    char raw[SKT_MTU] = {0};
    size_t raw_len = 0;
    if (skt_pack(skt, SKT_PKT_CMD_PING, skt->conf->ticket, payload, sizeof(payload), raw, &raw_len)) {
        return;
    }
    assert(raw_len > 0);
    if (sendto(kcp_conn->peer->fd, raw, raw_len, 0, (struct sockaddr*)&kcp_conn->peer->remote_addr,
               sizeof(kcp_conn->peer->remote_addr)) < 0) {
        _LOG_E("sendto failed when send ping, fd:%d", kcp_conn->peer->fd);
        return;
    }
    // _LOG("send ping to %s:%d", inet_ntoa(kcp_conn->peer->remote_addr.sin_addr),
    //      ntohs(kcp_conn->peer->remote_addr.sin_port));
}

static void kcp_update_cb(struct ev_loop* loop, ev_timer* watcher, int revents) {
    if (EV_ERROR & revents) {
        _LOG_E("kcp_update_cb got invalid event");
        return;
    }
    // skcptun_t* skt = (skcptun_t*)watcher->data;
    // assert(skt);
    skt_kcp_conn_iter(skt_update_kcp_cb);
}

static void tun_read_cb(struct ev_loop* loop, struct ev_io* watcher, int revents) {
    if (EV_ERROR & revents) {
        _LOG_E("tun_read_cb got invalid event");
        return;
    }
    skcptun_t* skt = (skcptun_t*)watcher->data;
    assert(skt);

    char buf[SKT_MTU] = {0};
    int len = tun_read(skt->tun_fd, buf, SKT_MTU);
    // _LOG("tun_read_cb read %d bytes", len);
    if (skt_tun_to_kcp(skt, buf, len) != _OK) return;
}

static void udp_read_cb(struct ev_loop* loop, struct ev_io* watcher, int revents) {
    if (EV_ERROR & revents) {
        _LOG_E("udp_read_cb got invalid event");
        return;
    }
    // _LOG("udp_read_cb start");
    skcptun_t* skt = (skcptun_t*)watcher->data;
    assert(skt);

    char raw[SKT_MTU] = {0};
    struct sockaddr_in remote_addr;
    socklen_t ra_len = sizeof(remote_addr);
    int rlen = recvfrom(skt->udp_fd, raw, SKT_MTU, 0, (struct sockaddr*)&remote_addr, &ra_len);
    if (rlen == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            _LOG("udp recv pending...");
            return;
        } else {
            perror("recvfrom");
            return;
        }
    } else if (rlen == 0) {
        _LOG_E("udp recv len: %d fd:%d", rlen, skt->udp_fd);
        return;
    } else if (rlen < SKT_PKT_CMD_SZIE + SKT_TICKET_SIZE) {
        _LOG_E("udp recv error fd:%d", skt->udp_fd);
        return;
    }
    // _LOG("recvfrom len:%d", rlen);

    skt_udp_peer_t* peer = skt_udp_peer_get(skt->udp_fd, remote_addr.sin_addr.s_addr);
    if (!peer) {
        _LOG_E("udp peer not found");
        return;
    }

    char cmd = 0x00;
    char ticket[SKT_TICKET_SIZE] = {0};
    char payload[SKT_MTU - SKT_TICKET_SIZE - SKT_PKT_CMD_SZIE] = {0};
    size_t payload_len = 0;
    if (skt_unpack(skt, raw, rlen, &cmd, ticket, payload, &payload_len) != _OK) return;
    assert(payload_len > 0);

    // check ticket
    if (strncmp(skt->conf->ticket, ticket, SKT_TICKET_SIZE) != 0) {
        _LOG("invalid ticket in auth");
        return;
    }

    skt->remote_addr = peer->remote_addr = remote_addr;

    skt_packet_t pkt = {.cmd = cmd, .ticket = ticket, .payload = payload, .payload_len = payload_len};
    if (dispatch_cmd(skt, &pkt, peer) != _OK) {
        _LOG_E("dispatch_cmd failed");
        return;
    }
    // _LOG("udp_read_cb end");
}

////////////////////////////////
// API
////////////////////////////////

int skt_local_start(skcptun_t* skt) {
    // init tun dev
    if (skt_init_tun(skt) != _OK) {
        skt_local_stop(skt);
        return _ERR;
    }

    // init udp data channel
    skt_udp_peer_t* peer = skt_udp_peer_start(skt->conf->udp_local_ip, skt->conf->udp_local_port,
                                              skt->conf->udp_remote_ip, skt->conf->udp_remote_port, skt);
    if (peer == NULL) {
        skt_local_stop(skt);
        return _ERR;
    }
    skt->udp_fd = peer->fd;
    skt->remote_addr = peer->remote_addr;

    ev_io_init(skt->tun_r_watcher, tun_read_cb, skt->tun_fd, EV_READ);
    // ev_io_start(skt->loop, skt->tun_r_watcher);

    ev_io_init(skt->udp_r_watcher, udp_read_cb, skt->udp_fd, EV_READ);
    ev_io_start(skt->loop, skt->udp_r_watcher);

    ev_timer_init(skt->timeout_watcher, timeout_cb, 0, skt->conf->timeout / 1000.0);
    ev_timer_start(skt->loop, skt->timeout_watcher);

    ev_timer_init(skt->kcp_update_watcher, kcp_update_cb, 0, skt->conf->kcp_interval / 1000.0);
    ev_timer_start(skt->loop, skt->kcp_update_watcher);
    skt->running = 1;

    if (send_auth_req(skt, peer->cid, peer->remote_addr) != _OK) {
        skt_local_stop(skt);
        return _ERR;
    }

    return _OK;
}

void skt_local_stop(skcptun_t* skt) {
    if (!skt) return;

    skt->running = 0;

    if (skt->timeout_watcher) {
        ev_timer_stop(skt->loop, skt->timeout_watcher);
    }
    if (skt->kcp_update_watcher) {
        ev_timer_stop(skt->loop, skt->kcp_update_watcher);
    }
    if (skt->tun_r_watcher) {
        ev_io_stop(skt->loop, skt->tun_r_watcher);
        skt->tun_r_watcher_started = 0;
    }
    if (skt->udp_r_watcher) {
        ev_io_stop(skt->loop, skt->udp_r_watcher);
    }

    if (skt->tun_fd > 0) {
        close(skt->tun_fd);
        skt->tun_fd = 0;
    }
    if (skt->udp_fd > 0) {
        close(skt->udp_fd);
        skt->udp_fd = 0;
    }

    skt_kcp_conn_cleanup();
    skt_udp_peer_cleanup();
    _LOG("local stop");
}