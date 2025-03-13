#include "skt_remote.h"

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

// #include "skt_kcp_conn.h"

// recv auth req format: cmd(1B)|ticket(32B)|tun_ip(4B)|timestamp(8B)
static int on_cmd_auth_req(skcptun_t* skt, skt_packet_t* pkt, skt_udp_peer_t* peer) {
    // _LOG("on_cmd_auth_req start");
    if (pkt->payload_len < 12) {
        _LOG_E("invalid auth req. len: %d", pkt->payload_len);
        return _ERR;
    }
    skt_kcp_conn_t* kcp_conn = NULL;
    if (peer->cid > 0) {
        kcp_conn = skt_kcp_conn_get_by_cid(peer->cid);
    }
    if (!kcp_conn) {
        uint32_t tun_ip = ntohl(*(uint32_t*)(pkt->payload));
        _LOG("on_cmd_auth_req tun_ip: %u", tun_ip);
        uint32_t cid = skt_kcp_conn_gen_cid();
        // new kcp connection
        kcp_conn = skt_kcp_conn_add(cid, tun_ip, pkt->ticket, peer, skt);
        if (!kcp_conn) {
            return _ERR;
        }
    }
    peer->cid = kcp_conn->cid;

    // send auth resp format: cmd(1B)|ticket(32B)|cid(4B)|timestamp(8B)
    uint32_t cid_net = htonl(kcp_conn->cid);
    uint64_t timestamp_net = skt_htonll(skt_mstime());
    char payload[12] = {0};
    memcpy(payload, &cid_net, 4);
    memcpy(payload + 4, &timestamp_net, 8);
    char raw[SKT_MTU] = {0};
    size_t raw_len = 0;
    if (skt_pack(skt, SKT_PKT_CMD_AUTH_RESP, pkt->ticket, payload, sizeof(payload), raw, &raw_len)) return _ERR;
    assert(raw_len > 0);
    skt_print_iaddr("on_cmd_auth_req", peer->remote_addr);
    int ret = sendto(peer->fd, raw, raw_len, 0, (struct sockaddr*)&peer->remote_addr, sizeof(peer->remote_addr));
    if (ret == -1) {
        _LOG_E("sendto failed when send auth resp, fd:%d", peer->fd);
        return _ERR;
    }
    _LOG("on_cmd_auth_req ok! cid:%u send:%d", peer->cid, ret);
    return _OK;
}

static int on_cmd_data(skcptun_t* skt, skt_packet_t* pkt, skt_udp_peer_t* peer) {
    // _LOG("on_cmd_data");
    if (skt_kcp_to_tun(skt, pkt) != _OK) return _ERR;
    return _OK;
}

static int on_cmd_ping(skcptun_t* skt, skt_packet_t* pkt, skt_udp_peer_t* peer) {
    // recv ping format: cmd(1B)|ticket(32B)|cid(4B)|timestamp(8B)
    if (pkt->payload_len < 12) {
        _LOG_E("invalid ping. len: %d", pkt->payload_len);
        return _ERR;
    }

    uint64_t now = skt_mstime();
    uint32_t cid = ntohl(*(uint32_t*)(pkt->payload));
    skt_kcp_conn_t* kcp_conn = skt_kcp_conn_get_by_cid(cid);
    if (!kcp_conn) {
        _LOG_W("kcp_conn does not exists. on_cmd_ping cid:%u", cid);
        cid = 0;
    } else {
        // kcp_conn->last_r_tm = now;
        kcp_conn->peer = peer;
    }
    peer->last_r_tm = now;

    // send pong format: cmd(1B)|ticket(32B)|cid(4B)|timestamp(8B)
    // reuse pkt->payload
    uint64_t timestamp_net = skt_htonll(skt_mstime());
    uint32_t cid_net = htonl(cid);
    memcpy(pkt->payload, &cid_net, sizeof(cid_net));
    memcpy(pkt->payload + 4, &timestamp_net, sizeof(timestamp_net));
    char raw[SKT_MTU] = {0};
    size_t raw_len = 0;
    if (skt_pack(skt, SKT_PKT_CMD_PONG, pkt->ticket, pkt->payload, 12, raw, &raw_len)) {
        return _ERR;
    }
    assert(raw_len > 0);
    if (sendto(peer->fd, raw, raw_len, 0, (struct sockaddr*)&peer->remote_addr, sizeof(peer->remote_addr)) == -1) {
        _LOG_E("sendto failed when send auth resp, fd:%d", peer->fd);
        return _ERR;
    }
    // _LOG("send pong to %s:%d ok!", inet_ntoa(peer->remote_addr.sin_addr), ntohs(peer->remote_addr.sin_port));
    return _OK;
}

static int dispatch_cmd(skcptun_t* skt, skt_packet_t* pkt, skt_udp_peer_t* peer) {
    int ret = _OK;
    assert(pkt);
    switch (pkt->cmd) {
        case SKT_PKT_CMD_DATA:
            ret = on_cmd_data(skt, pkt, peer);
            break;
        case SKT_PKT_CMD_AUTH_REQ:
            ret = on_cmd_auth_req(skt, pkt, peer);
            break;
        case SKT_PKT_CMD_PING:
            ret = on_cmd_ping(skt, pkt, peer);
            break;
            // case SKT_PKT_CMD_CLOSE:
            //     /* TODO: */
            //     break;

        default:
            _LOG_E("unknown cmd. %x", pkt->cmd);
            ret = _ERR;
            break;
    }
    return ret;
}

////////////////////////////////
// callback
////////////////////////////////

#define SKT_DEF_KEEPALIVE (1000 * 60)
static void iter_kcp_conn_cb(skt_kcp_conn_t* kcp_conn) {
    if (!kcp_conn) {
        _LOG_E("kcp_conn is null. iter_kcp_conn_cb");
        return;
    }
    uint64_t now = skt_mstime();
    if (kcp_conn->last_r_tm + SKT_DEF_KEEPALIVE < now) { /* TODO: config keepalive */
        _LOG("cllect kcp conn cid:%d", kcp_conn->cid);
        skt_kcp_conn_del(kcp_conn);
    }
}

static void iter_udp_peer_cb(skt_udp_peer_t* peer) {
    if (!peer) {
        _LOG_E("peer is null. iter_udp_peer_cb");
        return;
    }
    uint64_t now = skt_mstime();
    if (peer->last_r_tm + SKT_DEF_KEEPALIVE < now) { /* TODO: config keepalive */
        if (peer->remote_addr.sin_addr.s_addr == 0) {
            // _LOG("self peer doesn't need to be cllected.");
            return;
        }
        skt_kcp_conn_t* kcp_conn = skt_kcp_conn_get_by_cid(peer->cid);
        if (kcp_conn) {
            _LOG("cllect kcp conn cid:%d in peer", kcp_conn->cid);
            skt_kcp_conn_del(kcp_conn);
        }
        skt_udp_peer_del(peer->fd, peer->remote_addr.sin_addr.s_addr);
        _LOG("cllect peer fd:%d addr:%u", peer->fd, peer->remote_addr.sin_addr.s_addr);
        free(peer);
    }
}

static void idle_cb(struct ev_loop* loop, ev_idle* watcher, int revents) {
    if (EV_ERROR & revents) {
        _LOG_E("idle_cb got invalid event");
        return;
    }
    skcptun_t* skt = (skcptun_t*)watcher->data;
    assert(skt);

    // cllect peers
    skt_udp_peer_iter(iter_udp_peer_cb);
    // cllect kcp_conn, double check
    skt_kcp_conn_iter(iter_kcp_conn_cb);
    skt->last_cllect_tm = skt_mstime();

    ev_idle_stop(loop, watcher);
    _LOG("cllect ok.")
}

static void timeout_cb(struct ev_loop* loop, ev_timer* watcher, int revents) {
    if (EV_ERROR & revents) {
        _LOG_E("timeout_cb got invalid event");
        return;
    }
    skcptun_t* skt = (skcptun_t*)watcher->data;
    assert(skt);
    // cllect all connetions， include kcp_conn and peer
    uint64_t now = skt_mstime();
    if (skt->last_cllect_tm + SKT_DEF_KEEPALIVE < now) { /* TODO: config keepalive */
        // notify idle to cllect
        ev_idle_start(skt->loop, skt->idle_watcher);
    }
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

    // skt_print_iaddr("udp_read_cb", remote_addr);

    skt_udp_peer_t* peer = skt_udp_peer_get(skt->udp_fd, remote_addr.sin_addr.s_addr);

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

    if (!peer) {
        peer = (skt_udp_peer_t*)calloc(1, sizeof(skt_udp_peer_t));
        if (!peer) {
            perror("alloc");
            return;
        }
        peer->fd = watcher->fd;
        peer->remote_addr = remote_addr;
        memcpy(peer->ticket, ticket, SKT_TICKET_SIZE);
        if (skt_udp_peer_add(peer) != _OK) {
            free(peer);
            return;
        }
    }
    peer->remote_addr = remote_addr;

    skt_packet_t pkt = {.cmd = cmd, .ticket = ticket, .payload = payload, .payload_len = payload_len};
    if (dispatch_cmd(skt, &pkt, peer) != _OK) {
        if (peer->cid > 0) {
            skt_kcp_conn_t* kcp_conn = skt_kcp_conn_get_by_cid(peer->cid);
            skt_kcp_conn_del(kcp_conn);
        }
        skt_udp_peer_del(peer->fd, peer->remote_addr.sin_addr.s_addr);
        free(peer);
    }

    // _LOG("udp_read_cb end");
}

////////////////////////////////
// API
////////////////////////////////

int skt_remote_start(skcptun_t* skt) {
    // start tun dev
    if (skt_start_tun(skt) != _OK) {
        skt_remote_stop(skt);
        return _ERR;
    }

    skt->last_cllect_tm = skt_mstime();

    // start udp
    skt_udp_peer_t* peer = skt_udp_peer_start(skt->conf->udp_local_ip, skt->conf->udp_local_port,
                                              skt->conf->udp_remote_ip, skt->conf->udp_remote_port);
    if (peer == NULL) {
        skt_remote_stop(skt);
        return _ERR;
    }
    skt->udp_fd = peer->fd;

    ev_io_init(skt->udp_io_watcher, udp_read_cb, skt->udp_fd, EV_READ);
    ev_io_start(skt->loop, skt->udp_io_watcher);

    ev_timer_init(skt->timeout_watcher, timeout_cb, 0, skt->conf->timeout / 1000.0);
    ev_timer_start(skt->loop, skt->timeout_watcher);

    ev_idle_init(skt->idle_watcher, idle_cb);

    ev_io_init(skt->tun_io_watcher, tun_read_cb, skt->tun_fd, EV_READ);
    ev_io_start(skt->loop, skt->tun_io_watcher);

    ev_timer_init(skt->kcp_update_watcher, kcp_update_cb, 0, skt->conf->kcp_interval / 1000.0);
    ev_timer_start(skt->loop, skt->kcp_update_watcher);

    skt->running = 1;
    return _OK;
}

void skt_remote_stop(skcptun_t* skt) {
    if (!skt) return;

    skt->running = 0;

    if (skt->timeout_watcher) {
        ev_timer_stop(skt->loop, skt->timeout_watcher);
    }
    if (skt->kcp_update_watcher) {
        ev_timer_stop(skt->loop, skt->kcp_update_watcher);
    }
    if (skt->tun_io_watcher) {
        ev_io_stop(skt->loop, skt->tun_io_watcher);
    }
    if (skt->udp_io_watcher) {
        ev_io_stop(skt->loop, skt->udp_io_watcher);
    }
    if (skt->idle_watcher) {
        ev_idle_stop(skt->loop, skt->idle_watcher);
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
    _LOG("skt_remote_stop");
    return;
}