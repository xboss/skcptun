#include "skt_local.h"

#include <errno.h>
#include <unistd.h>

static int ping(skcptun_t* skt, struct sockaddr_in remote_addr) {
    assert(skt->tun_ip_addr > 0);
    // send ping format: cmd(1B)|ticket(32B)|tun_ip(4B)|timestamp(8B)
    uint32_t tun_ip_net = htonl(skt->tun_ip_addr);
    uint64_t timestamp_net = skt_htonll(skt_mstime());
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
    _LOG("ping ok.");
    return _OK;
}

// recv pong resp format: cmd(1B)|ticket(32B)|timestamp(8B)|cid(4B)|mtu(4B)|kcp_interval(4B)|speed_mode(1B)
static int on_cmd_pong(skcptun_t* skt, skt_packet_t* pkt, skt_udp_peer_t* peer) {
    if (pkt->payload_len < 21) {
        _LOG_E("invalid pong. len: %d", pkt->payload_len);
        return _ERR;
    }
    uint32_t cid = ntohl(*(uint32_t*)(pkt->payload + 8));
    if (cid == 0) {
        _LOG("invalid cid");
        return _ERR;
    }
    if (peer->cid > 0 && cid == peer->cid) {
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

    if (skt->conf->kcp_interval <= 0) {
        skt->conf->kcp_interval = ntohl(*(int*)(pkt->payload + 16));
    }
    if (skt->conf->kcp_interval <= 0 || skt->conf->kcp_interval > 9999999) {
        _LOG("invalid kcp_interval in pong. %d", skt->conf->kcp_interval);
        return _ERR;
    }
    skt->conf->speed_mode = (int)(pkt->payload[20] & 0x00ffu);
    skt_setup_kcp(skt);
    if (skt_setup_tun(skt) != _OK) {
        _LOG_E("skt_start_tun failed");
        return _ERR;
    }
    assert(skt->tun_ip_addr > 0);
    // new kcp connection
    skt_kcp_conn_t* kcp_conn = skt_kcp_conn_add(cid, skt->tun_ip_addr, pkt->ticket, peer, skt);
    if (!kcp_conn) {
        return _ERR;
    }
    skt->local_cid = peer->cid = cid;
    _LOG("pong and auth ok!");
    return _OK;
}

static void on_timeout(skcptun_t* skt) {
    skt_kcp_conn_t* kcp_conn = skt_kcp_conn_get_by_cid(skt->local_cid);
    if (kcp_conn) {
        if (kcp_conn->peer->last_r_tm + skt->conf->keepalive < skt_mstime()) {
            // trigger auth
            _LOG("timeout_cb skt_close_kcp_conn trigger auth peer->last_r_tm:%llu", kcp_conn->peer->last_r_tm);
            skt_close_kcp_conn(kcp_conn);
        } else {
            ikcp_update(kcp_conn->kcp, SKT_MSTIME32);
            ikcp_flush(kcp_conn->kcp); /* TODO: */
        }
    }
    if (ping(skt, skt->remote_addr) != _OK) return;
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
    skt->udp_fd = peer->fd;
    skt->remote_addr = peer->remote_addr;
    skt->running = 1;
    skt->on_cmd_pong = on_cmd_pong;
    skt->on_timeout = on_timeout;

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