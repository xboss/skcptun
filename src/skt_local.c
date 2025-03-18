#include "skt_local.h"

#include <errno.h>
#include <unistd.h>

static int ping(skcptun_t* skt, struct sockaddr_in remote_addr) {
    assert(skt->tun_ip_addr > 0);
    uint64_t now = skt_mstime();
    // send ping format: cmd(1B)|ticket(32B)|tun_ip(4B)|timestamp(8B)
    uint32_t tun_ip_net = htonl(skt->tun_ip_addr);
    uint64_t timestamp_net = skt_htonll(now);
    char payload[12] = {0};
    memcpy(payload, &tun_ip_net, 4);
    memcpy(payload + 4, &timestamp_net, 8);
    char raw[SKT_MTU] = {0};
    size_t raw_len = 0;
    if (skt_pack(skt, SKT_PKT_CMD_PING, skt->conf->ticket, payload, sizeof(payload), raw, &raw_len)) return _ERR;
    assert(raw_len > 0);
    if (sendto(skt->udp_fd, raw, raw_len, 0, (struct sockaddr*)&remote_addr, sizeof(remote_addr)) < 0) {
        _LOG_E("sendto failed when send ping, fd:%d", skt->udp_fd);
        return _ERR;
    }
    skt->last_ping_tm = now;
    _LOG("ping ok.");
    return _OK;
}

// recv pong resp format:
// cmd(1B)|ticket(32B)|timestamp(8B)|cid(4B)|mtu(4B)|kcp_interval(4B)|speed_mode(1B)|keepalive(4B)
static int on_cmd_pong(skcptun_t* skt, skt_packet_t* pkt, skt_udp_peer_t* peer) {
    if (pkt->payload_len < 25) {
        _LOG_E("invalid pong. len: %d", pkt->payload_len);
        return _ERR;
    }
    uint32_t cid = ntohl(*(uint32_t*)(pkt->payload + 8));
    if (cid == 0) {
        _LOG("invalid cid");
        return _ERR;
    }
    if (cid == skt->local_cid && cid == peer->cid) {
        _LOG("already authed");
        return _OK;
    }
    if (skt->conf->mtu <= 0) {
        skt->conf->mtu = ntohl(*(int*)(pkt->payload + 12));
    }
    if (skt->conf->mtu > SKT_MTU || skt->conf->mtu <= 0) {
        _LOG("invalid mtu in pong. %d", skt->conf->mtu);
        return _ERR;
    }
    skt->conf->kcp_mtu = SKT_ASSIGN_KCP_MTU(skt->conf->mtu);
    skt->conf->tun_mtu = SKT_ASSIGN_TUN_MTU(skt->conf->mtu);

    // if (skt->conf->kcp_interval <= 0)
    skt->conf->kcp_interval = ntohl(*(int*)(pkt->payload + 16));
    if (skt->conf->kcp_interval <= 0 || skt->conf->kcp_interval > 9999999) {
        _LOG("invalid kcp_interval in pong. %d", skt->conf->kcp_interval);
        return _ERR;
    }
    skt->conf->keepalive = ntohl(*(int*)(pkt->payload + 21));
    if (skt->conf->keepalive <= 0 || skt->conf->keepalive > 9999999) {
        _LOG("invalid keepalive in pong. %d", skt->conf->keepalive);
        return _ERR;
    }
    skt->conf->speed_mode = (int)(pkt->payload[20] & 0x00ffu);
    skt_setup_kcp(skt);
    if (skt_setup_tun(skt) != _OK) {
        _LOG_E("skt_start_tun failed");
        return _ERR;
    }

    _LOG("pong ok. cid:%u mtu:%d kcp_interval:%d speed_mode:%d keepalive:%d", cid, skt->conf->mtu,
         skt->conf->kcp_interval, skt->conf->speed_mode, skt->conf->keepalive);
    assert(skt->tun_ip_addr > 0);
    // new kcp connection
    skt_kcp_conn_t* kcp_conn = skt_kcp_conn_add(cid, skt->tun_ip_addr, pkt->ticket, peer, skt);
    if (!kcp_conn) {
        return _ERR;
    }
    skt->local_cid = peer->cid = cid;
    kcp_conn->last_r_tm = skt_mstime();
    _LOG("pong and auth ok!");
    return _OK;
}

static void on_timeout(skcptun_t* skt) {
    uint64_t now = skt_mstime();
    skt_kcp_conn_t* kcp_conn = skt_kcp_conn_get_by_cid(skt->local_cid);
    if (kcp_conn) {
        if (kcp_conn->peer->last_r_tm + skt->conf->keepalive < now) {
            // trigger auth
            _LOG("timeout_cb skt_close_kcp_conn trigger auth peer->last_r_tm:%llu", kcp_conn->peer->last_r_tm);
            skt_close_kcp_conn(kcp_conn);
        } else {
            ikcp_update(kcp_conn->kcp, SKT_MSTIME32);
            ikcp_flush(kcp_conn->kcp); /* TODO: */
        }
    }
    if (skt->last_ping_tm + skt->conf->ping_interval < now) {
        /* TODO: debug */
        if (kcp_conn)
            _LOG("timeout_cb cid:%u peer->last_r_tm:%llu ago, kcp_conn->last_r_tm:%llu ago", skt->local_cid,
                 now - kcp_conn->peer->last_r_tm, now - kcp_conn->last_r_tm);

        if (ping(skt, skt->remote_addr) != _OK) return;
    }
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
    skt_udp_peer_t* peer = skt_udp_start(skt->conf->udp_local_ip, skt->conf->udp_local_port, skt->conf->udp_remote_ip,
                                         skt->conf->udp_remote_port, skt);
    if (peer == NULL) {
        skt_local_stop(skt);
        return _ERR;
    }
    peer->last_r_tm = skt_mstime();
    skt->udp_fd = peer->fd;
    skt->remote_addr = peer->remote_addr;
    skt->running = 1;
    skt->on_cmd_pong = on_cmd_pong;
    skt->on_timeout = on_timeout;
    skt->conf->kcp_interval = 1000;

    if (ping(skt, peer->remote_addr) != _OK) {
        skt_local_stop(skt);
        return _ERR;
    }
    if (skt_run(skt) != _OK) {
        skt_local_stop(skt);
        return _ERR;
    }
    return _OK;
}

void skt_local_stop(skcptun_t* skt) {
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
    _LOG("local stop");
}