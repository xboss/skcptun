#include "skt_remote.h"

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

// recv ping format: cmd(1B)|ticket(32B)|tun_ip(4B)|timestamp(8B)
static int on_cmd_ping(skcptun_t* skt, skt_packet_t* pkt, skt_udp_peer_t* peer) {
    // _LOG("on ping start");
    if (pkt->payload_len < 12) {
        _LOG_E("invalid ping. len: %d", pkt->payload_len);
        return _ERR;
    }
    skt_kcp_conn_t* kcp_conn = NULL;
    if (peer->cid > 0) {
        kcp_conn = skt_kcp_conn_get_by_cid(peer->cid);
    }
    uint64_t now = skt_mstime();
    if (!kcp_conn) {
        uint32_t tun_ip = ntohl(*(uint32_t*)(pkt->payload));
        _LOG("on_cmd_ping tun_ip: %u", tun_ip);
        uint32_t cid = skt_kcp_conn_gen_cid();
        // new kcp connection
        kcp_conn = skt_kcp_conn_add(cid, tun_ip, pkt->ticket, peer, skt);
        if (!kcp_conn) {
            return _ERR;
        }
        kcp_conn->last_r_tm = now;
    }
    peer->cid = kcp_conn->cid;
    // send pong format: cmd(1B)|ticket(32B)|timestamp(8B)|cid(4B)|mtu(4B)|kcp_interval(4B)|speed_mode(1B)|keepalive(4B)
    uint32_t cid_net = htonl(kcp_conn->cid);
    uint64_t timestamp_net = skt_htonll(now);
    uint32_t mtu_net = htonl(skt->conf->mtu);
    uint32_t kcp_interval_net = htonl(skt->conf->kcp_interval);
    char payload[25] = {0};
    memcpy(payload, &timestamp_net, 8);
    memcpy(payload + 8, &cid_net, 4);
    memcpy(payload + 12, &mtu_net, 4);
    memcpy(payload + 16, &kcp_interval_net, 4);
    payload[20] = (char)(skt->conf->speed_mode & 0x00ffu);
    memcpy(payload + 21, &skt->conf->keepalive, 4);
    char raw[SKT_MTU] = {0};
    size_t raw_len = 0;
    if (skt_pack(skt, SKT_PKT_CMD_PONG, pkt->ticket, payload, sizeof(payload), raw, &raw_len)) return _ERR;
    assert(raw_len > 0);
    // skt_print_iaddr("on_cmd_ping", peer->remote_addr);
    int ret = sendto(peer->fd, raw, raw_len, 0, (struct sockaddr*)&peer->remote_addr, sizeof(peer->remote_addr));
    if (ret < 0) {
        _LOG_E("sendto failed when send pong, fd:%d", peer->fd);
        return _ERR;
    }
    _LOG("on_cmd_ping ok! cid:%u send:%d", peer->cid, ret);
    return _OK;
}

static void iter_kcp_conn_cb(skt_kcp_conn_t* kcp_conn) {
    if (!kcp_conn) {
        _LOG_E("kcp_conn is null. iter_kcp_conn_cb");
        return;
    }
    uint64_t now = skt_mstime();
    if (kcp_conn->last_r_tm + kcp_conn->skt->conf->keepalive < now) {
        _LOG("cllect kcp conn cid:%d", kcp_conn->cid);
        skt_close_kcp_conn(kcp_conn);
    } else {
        // kcp update
        ikcp_update(kcp_conn->kcp, SKT_MSTIME32);
        ikcp_flush(kcp_conn->kcp); /* TODO: */
    }
}

static void iter_udp_peer_cb(skt_udp_peer_t* peer) {
    if (!peer) {
        _LOG_E("peer is null. iter_udp_peer_cb");
        return;
    }
    uint64_t now = skt_mstime();
    skt_kcp_conn_t* kcp_conn = skt_kcp_conn_get_by_cid(peer->cid);
    if (peer->last_r_tm + peer->skt->conf->keepalive < now) {
        if (peer->remote_addr.sin_addr.s_addr == 0) {
            // _LOG("self peer doesn't need to be cllected.");
            return;
        }
        _LOG("cllect kcp conn peer");
        skt_close_kcp_conn(kcp_conn);
        _LOG("cllect peer fd:%d addr:%u", peer->fd, peer->remote_addr.sin_addr.s_addr);
        skt_udp_peer_del(peer->fd, peer->remote_addr.sin_addr.s_addr);
    } else {
        // kcp update
        if (kcp_conn) {
            ikcp_update(kcp_conn->kcp, SKT_MSTIME32);
            ikcp_flush(kcp_conn->kcp); /* TODO: */
        }
    }
}

static void on_timeout(skcptun_t* skt) {
    // cllect all connetions， include kcp_conn and peer
    uint64_t now = skt_mstime();
    if (skt->last_cllect_tm + skt->conf->keepalive < now) {
        // cllect peers and kcp_conn
        skt_udp_peer_iter(iter_udp_peer_cb);
        skt->last_cllect_tm = now;
        _LOG("cllect ok.")
    } else {
        // kcp update
        skt_kcp_conn_iter(iter_kcp_conn_cb);
    }
}

////////////////////////////////
// API
////////////////////////////////

int skt_remote_start(skcptun_t* skt) {
    // start tun dev
    if (skt_init_tun(skt) != _OK || skt_setup_tun(skt) != _OK) {
        skt_remote_stop(skt);
        return _ERR;
    }
    skt->last_cllect_tm = skt_mstime();
    // start udp
    skt_udp_peer_t* peer = skt_udp_start(skt->conf->udp_local_ip, skt->conf->udp_local_port, skt->conf->udp_remote_ip,
                                         skt->conf->udp_remote_port, skt);
    if (peer == NULL) {
        skt_remote_stop(skt);
        return _ERR;
    }
    peer->last_r_tm = skt_mstime();
    skt->udp_fd = peer->fd;
    skt->running = 1;
    skt->on_cmd_ping = on_cmd_ping;
    skt->on_timeout = on_timeout;
    if (skt_run(skt) != _OK) {
        skt_remote_stop(skt);
        return _ERR;
    }
    return _OK;
}

void skt_remote_stop(skcptun_t* skt) {
    if (!skt) return;
    skt->running = 0;
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
