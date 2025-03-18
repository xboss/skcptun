#include "skcptun.h"

#include <errno.h>
#include <poll.h>

static void print_skcptun(const skcptun_t* skt) {
    if (!skt) {
        _LOG_E("skcptun_t is NULL");
        return;
    }

    _LOG_E("skcptun_t:");
    _LOG_E("  running: %d", skt->running);
    _LOG_E("  tun_fd: %d", skt->tun_fd);
    _LOG_E("  udp_fd: %d", skt->udp_fd);
    _LOG_E("  tun_ip_addr: %u", skt->tun_ip_addr);
    _LOG_E("  local_cid: %u", skt->local_cid);
    _LOG_E("  last_cllect_tm: %" PRIu64 "", skt->last_cllect_tm);

    if (!skt->conf) {
        _LOG_E("  skt_config_t is NULL");
        return;
    }

    const skt_config_t* conf = skt->conf;
    _LOG_E("  skt_config_t:");
    _LOG_E("    udp_local_ip: %s", conf->udp_local_ip);
    _LOG_E("    udp_local_port: %u", conf->udp_local_port);
    _LOG_E("    udp_remote_ip: %s", conf->udp_remote_ip);
    _LOG_E("    udp_remote_port: %u", conf->udp_remote_port);
    _LOG_E("    key: %s", conf->key);
    _LOG_E("    iv: %s", conf->iv);
    _LOG_E("    ticket: %s", conf->ticket);
    _LOG_E("    mode: %d", conf->mode);
    _LOG_E("    timeout: %d", conf->timeout);
    _LOG_E("    log_file: %s", conf->log_file);
    _LOG_E("    log_level: %d", conf->log_level);
    _LOG_E("    tun_dev: %s", conf->tun_dev);
    _LOG_E("    tun_ip: %s", conf->tun_ip);
    _LOG_E("    tun_mask: %s", conf->tun_mask);
    _LOG_E("    tun_mtu: %d", conf->tun_mtu);
    _LOG_E("    mtu: %d", conf->mtu);
    _LOG_E("    keepalive: %d", conf->keepalive);
    _LOG_E("    kcp_mtu: %d", conf->kcp_mtu);
    _LOG_E("    kcp_interval: %d", conf->kcp_interval);
    _LOG_E("    kcp_nodelay: %d", conf->kcp_nodelay);
    _LOG_E("    kcp_resend: %d", conf->kcp_resend);
    _LOG_E("    kcp_nc: %d", conf->kcp_nc);
    _LOG_E("    kcp_sndwnd: %d", conf->kcp_sndwnd);
    _LOG_E("    kcp_rcvwnd: %d", conf->kcp_rcvwnd);
    _LOG_E("    speed_mode: %d", conf->speed_mode);
}

static int parse_ip_addresses(const char* data, int data_len, char* src_ip_str, char* dst_ip_str, uint32_t* src_ip,
                              uint32_t* dst_ip) {
    if (data == NULL || src_ip_str == NULL || dst_ip_str == NULL || data_len < 20 || src_ip == NULL || dst_ip == NULL) {
        return _ERR;
    }
    // Check the version part of the first byte (version_ihl)
    uint8_t version_ihl = data[0];
    uint8_t version = (version_ihl >> 4);
    if (version != 4) {
        return _ERR;
    }
    // Extract source IP address (bytes 12-15)
    uint32_t src_addr_network_order = (data[12] << 24) | (data[13] << 16) | (data[14] << 8) | data[15];
    *src_ip = ntohl(src_addr_network_order);
    inet_ntop(AF_INET, src_ip, src_ip_str, INET_ADDRSTRLEN);
    // Extract destination IP address (bytes 16-19)
    uint32_t dst_addr_network_order = (data[16] << 24) | (data[17] << 16) | (data[18] << 8) | data[19];
    *dst_ip = ntohl(dst_addr_network_order);
    inet_ntop(AF_INET, dst_ip, dst_ip_str, INET_ADDRSTRLEN);
    return _OK;
}

static int tun_to_kcp(skcptun_t* skt, const char* buf, int len) {
    // check result
    if (len < 0) {
        _LOG_E("tun read len: %d", len);
        skt->running = 0;
        return _ERR;
    }
    if (len == 0) {
        _LOG_E("tun read len==0");
        return _ERR;
    }

    assert(len + SKT_KCP_HEADER_SZIE <= skt->conf->kcp_mtu);
    // filter ip packet
    char src_ip_str[INET_ADDRSTRLEN + 1] = {0};
    char dst_ip_str[INET_ADDRSTRLEN + 1] = {0};
    uint32_t src_ip = 0;
    uint32_t dst_ip = 0;
    if (parse_ip_addresses(buf, len, src_ip_str, dst_ip_str, &src_ip, &dst_ip) != _OK) {
        _LOG("Not an IPv4 packet");
        return _OK;
    }
    _LOG("tun2udp IPV4: %s -> %s", src_ip_str, dst_ip_str);

    assert(skt->tun_ip_addr > 0);
    uint32_t tun_ip = skt->tun_ip_addr;
    if (skt->conf->mode == SKT_MODE_REMOTE) {
        tun_ip = dst_ip;
    }
    // find kcp conn
    // _LOG("skt_tun_to_kcp tun_ip:%u", tun_ip);
    skt_kcp_conn_t* kcp_conn = skt_kcp_conn_get_by_tun_ip(tun_ip);
    if (!kcp_conn) {
        _LOG_E("kcp conn not found in skt_tun_to_kcp, tun_ip: %u", tun_ip);
        return _ERR;
    }
    // kcp send
    int ret = ikcp_send(kcp_conn->kcp, buf, len);
    if (ret < 0) {
        _LOG_E(" ikcp_send failed, cid: %u", kcp_conn->cid);
        skt_close_kcp_conn(kcp_conn);
        return _ERR;
    }
    ikcp_update(kcp_conn->kcp, SKT_MSTIME32);
    ikcp_flush(kcp_conn->kcp);
    // _LOG("skt_tun_to_kcp send ok len:%d", ret);
    return _OK;
}

static int kcp_to_tun(skcptun_t* skt, skt_packet_t* pkt) {
    // check is kcp packet
    if (pkt->payload_len < SKT_KCP_HEADER_SZIE) {
        _LOG_E("invalid kcp packet, payload_len:%d", pkt->payload_len);
        return _ERR;
    }
    // get cid
    uint32_t cid = ikcp_getconv(pkt->payload);
    // check is conn exists
    skt_kcp_conn_t* kcp_conn = skt_kcp_conn_get_by_cid(cid);
    if (!kcp_conn) {
        _LOG_E("invalid cid:%d in on_cmd_data", cid);
        return _ERR;
    }
    int ret = ikcp_input(kcp_conn->kcp, pkt->payload, pkt->payload_len);
    assert(ret == 0);
    int recv_len = 0;
    char recv_buf[SKT_MTU - SKT_PKT_CMD_SZIE - SKT_TICKET_SIZE] = {0};
    do {
        ikcp_update(kcp_conn->kcp, SKT_MSTIME32);
        ikcp_flush(kcp_conn->kcp);
        recv_len = ikcp_recv(kcp_conn->kcp, recv_buf, sizeof(recv_buf));
        if (recv_len <= 0) {
            // _LOG("skt_kcp_conn_recv eagain. cid:%d len:%d", cid, recv_len);
            break;
        }
        kcp_conn->last_r_tm = skt_mstime();
        assert(recv_len <= sizeof(recv_buf));

        /* TODO: debug start */
        char src_ip_str[INET_ADDRSTRLEN + 1] = {0};
        char dst_ip_str[INET_ADDRSTRLEN + 1] = {0};
        uint32_t src_ip = 0;
        uint32_t dst_ip = 0;
        if (parse_ip_addresses(recv_buf, recv_len, src_ip_str, dst_ip_str, &src_ip, &dst_ip) != _OK) {
            _LOG("Not an IPv4 packet");
            return _OK;
        }
        _LOG("upd2tun IPV4: %s -> %s", src_ip_str, dst_ip_str);
        /* TODO: debug end */

        // send to tun
        assert(skt->tun_fd > 0);
        if (tun_write(skt->tun_fd, recv_buf, recv_len) <= 0) {
            _LOG_E("tun_write failed");
            return _ERR;
        }
    } while (recv_len > 0);
    ikcp_update(kcp_conn->kcp, SKT_MSTIME32);
    ikcp_flush(kcp_conn->kcp);
    return _OK;
}

static int on_cmd_data(skcptun_t* skt, skt_packet_t* pkt, skt_udp_peer_t* peer) {
    // _LOG("on_cmd_data");
    if (kcp_to_tun(skt, pkt) != _OK) return _ERR;
    return _OK;
}

static int dispatch_cmd(skcptun_t* skt, skt_packet_t* pkt, skt_udp_peer_t* peer) {
    int ret = _OK;
    assert(pkt);
    switch (pkt->cmd) {
        case SKT_PKT_CMD_DATA:
            ret = on_cmd_data(skt, pkt, peer);
            break;
        // case SKT_PKT_CMD_AUTH_REQ:
        //     if (skt->on_cmd_auth_req) ret = skt->on_cmd_auth_req(skt, pkt, peer);
        //     break;
        case SKT_PKT_CMD_PING:
            if (skt->on_cmd_ping) ret = skt->on_cmd_ping(skt, pkt, peer);
            break;
        // case SKT_PKT_CMD_AUTH_RESP:
        //     if (skt->on_cmd_auth_resp) ret = skt->on_cmd_auth_resp(skt, pkt, peer);
        //     break;
        case SKT_PKT_CMD_PONG:
            if (skt->on_cmd_pong) ret = skt->on_cmd_pong(skt, pkt, peer);
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

static void udp_to_tun(skcptun_t* skt, const char* buf, ssize_t len, struct sockaddr_in remote_addr) {
    if (len < SKT_PKT_CMD_SZIE + SKT_TICKET_SIZE) {
        _LOG_E("udp recv error len:%d fd:%d", len, skt->udp_fd);
        return;
    }
    char cmd = 0x00;
    char ticket[SKT_TICKET_SIZE] = {0};
    char payload[SKT_MTU - SKT_TICKET_SIZE - SKT_PKT_CMD_SZIE] = {0};
    size_t payload_len = 0;
    if (skt_unpack(skt, buf, len, &cmd, ticket, payload, &payload_len) != _OK) return;
    assert(payload_len > 0);
    // check ticket
    if (strncmp(skt->conf->ticket, ticket, SKT_TICKET_SIZE) != 0) {
        _LOG("invalid ticket");
        return;
    }
    skt_udp_peer_t* peer = skt_udp_peer_get(skt->udp_fd, remote_addr.sin_addr.s_addr);
    if (!peer) {
        if (skt->conf->mode == SKT_MODE_LOCAL) {
            _LOG_E("invalid remote addr in local mode");
            return;
        }
        if (skt_udp_peer_add(skt->udp_fd, remote_addr, skt) != _OK) return;
        peer = skt_udp_peer_get(skt->udp_fd, remote_addr.sin_addr.s_addr);
        _LOG("add new peer");
    }
    skt->remote_addr = peer->remote_addr = remote_addr;
    skt_packet_t pkt = {.cmd = cmd, .ticket = ticket, .payload = payload, .payload_len = payload_len};
    if (dispatch_cmd(skt, &pkt, peer) != _OK) {
        _LOG_E("dispatch_cmd failed");
        skt_kcp_conn_t* kcp_conn = skt_kcp_conn_get_by_cid(peer->cid);
        skt_close_kcp_conn(kcp_conn);
        return;
    }
    return;
}

static void tun_to_udp(skcptun_t* skt, const char* buf, ssize_t len) { tun_to_kcp(skt, buf, len); }

////////////////////////////////
// skcptun API
////////////////////////////////

skcptun_t* skt_init(skt_config_t* conf) {
    if (!conf) return NULL;
    skcptun_t* skt = (skcptun_t*)calloc(1, sizeof(skcptun_t));
    if (skt == NULL) {
        perror("calloc");
        return NULL;
    }
    skt->conf = conf;
    skt->running = 0;
    return skt;
}

void skt_free(skcptun_t* skt) {
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
    free(skt);
    _LOG("skt_free");
}

void skt_setup_kcp(skcptun_t* skt) {
    skt->conf->kcp_rcvwnd = 512;
    skt->conf->kcp_sndwnd = 512;
    if (skt->conf->speed_mode != 0) {
        skt->conf->kcp_nodelay = 1;
        skt->conf->kcp_resend = 2;
        skt->conf->kcp_nc = 1;
        _LOG("kcp speed mode ok.");
    } else {
        skt->conf->kcp_nodelay = skt->conf->kcp_resend = skt->conf->kcp_nc = 0;
    }
}

int skt_init_tun(skcptun_t* skt) {
    if (!skt) {
        return _ERR;
    }
    // Allocate TUN device
    skt->tun_fd = tun_alloc(skt->conf->tun_dev, IFNAMSIZ);
    if (skt->tun_fd < 0) {
        perror("tun_alloc");
        return _ERR;
    }
    // if (skt_set_nonblocking(skt->tun_fd) != _OK) { /* TODO: */
    //     return _ERR;
    // }
    if (inet_pton(AF_INET, skt->conf->tun_ip, &skt->tun_ip_addr) <= 0) {
        perror("inet_pton tun_ip");
        return _ERR;
    }
    return _OK;
}

int skt_setup_tun(skcptun_t* skt) {
    if (!skt) {
        return _ERR;
    }
    // Set TUN device IP
    if (tun_set_ip(skt->conf->tun_dev, skt->conf->tun_ip) < 0) {
        perror("tun_set_ip");
        return _ERR;
    }

    // Set TUN device netmask
    if (tun_set_netmask(skt->conf->tun_dev, skt->conf->tun_mask) < 0) {
        perror("tun_set_netmask");
        return _ERR;
    }

    // Set TUN device MTU
    if (tun_set_mtu(skt->conf->tun_dev, skt->conf->tun_mtu) < 0) {
        perror("tun_set_mtu");
        return _ERR;
    }

    // Bring up TUN device
    if (tun_up(skt->conf->tun_dev) < 0) {
        perror("tun_up");
        return _ERR;
    }
    return _OK;
}

skt_udp_peer_t* skt_udp_start(const char* local_ip, uint16_t local_port, const char* remote_ip, uint16_t remote_port,
                              skcptun_t* skt) {
    skt_udp_peer_t peer;
    memset(&peer, 0, sizeof(peer));
    peer.fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (peer.fd < 0) {
        perror("socket");
        return NULL;
    }
    // if (skt_set_nonblocking(peer.fd) != _OK) { /* TODO: */
    //     return NULL;
    // }
    if (local_ip && strnlen(local_ip, INET_ADDRSTRLEN) > 0 && local_port > 0) {
        memset(&peer.local_addr, 0, sizeof(peer.local_addr));
        peer.local_addr.sin_family = AF_INET;
        peer.local_addr.sin_port = htons(local_port);
        if (inet_pton(AF_INET, local_ip, &peer.local_addr.sin_addr) <= 0) {
            perror("inet_pton local");
            close(peer.fd);
            return NULL;
        }
        if (bind(peer.fd, (struct sockaddr*)&peer.local_addr, sizeof(peer.local_addr)) < 0) {
            perror("bind");
            close(peer.fd);
            return NULL;
        }
    }
    if (remote_ip && strnlen(remote_ip, INET_ADDRSTRLEN) > 0 && remote_port > 0) {
        memset(&peer.remote_addr, 0, sizeof(peer.remote_addr));
        peer.remote_addr.sin_family = AF_INET;
        peer.remote_addr.sin_port = htons(remote_port);
        if (inet_pton(AF_INET, remote_ip, &peer.remote_addr.sin_addr) <= 0) {
            perror("inet_pton remote");
            close(peer.fd);
            return NULL;
        }
    }
    if (skt_udp_peer_add(peer.fd, peer.remote_addr, skt) != _OK) {
        close(peer.fd);
        return NULL;
    }
    skt_udp_peer_t* p = skt_udp_peer_get(peer.fd, peer.remote_addr.sin_addr.s_addr);
    return p;
}

int skt_run(skcptun_t* skt) {
    unsigned char rbuf[SKT_MTU] = {0};
    int infd = 0, ret = 0;
    // int  outfd = 0;
    ssize_t rlen = 0;
    struct sockaddr_in remote_addr;
    socklen_t ra_len = sizeof(remote_addr);
    struct pollfd fds[2] = {{.fd = skt->udp_fd, .events = POLLIN}, {.fd = skt->tun_fd, .events = POLLIN}};
    while (skt->running) {
        // _LOG("poll start");
        ret = poll(fds, 2, skt->conf->kcp_interval); /* TODO: timeout or kcp_interval*/
        if (!skt->running) {
            break;
        }
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("poll failed");
            return _ERR;
        } else if (ret == 0) {
            // _LOG("poll timeout.");
            if (skt->on_timeout) skt->on_timeout(skt);
            continue;
        }
        infd = (fds[0].revents & POLLIN) ? skt->udp_fd : skt->tun_fd;
        // outfd = infd == skt->tun_fd ? skt->udp_fd : skt->tun_fd;
        if (infd == skt->tun_fd) {
            rlen = tun_read(skt->tun_fd, rbuf, sizeof(rbuf));
            tun_to_udp(skt, (const char*)rbuf, rlen);
        } else {
            rlen = recvfrom(skt->udp_fd, rbuf, sizeof(rbuf), 0, (struct sockaddr*)&remote_addr, &ra_len);
            udp_to_tun(skt, (const char*)rbuf, rlen, remote_addr);
        }
    }
    return _OK;
}

void skt_update_kcp_cb(skt_kcp_conn_t* kcp_conn) {
    if (!kcp_conn || kcp_conn->cid == 0 || !kcp_conn->kcp) {
        _LOG_E("invalid kcp_conn");
        return;
    }
    ikcp_update(kcp_conn->kcp, SKT_MSTIME32);
    ikcp_flush(kcp_conn->kcp);
}

void skt_close_kcp_conn(skt_kcp_conn_t* kcp_conn) {
    if (!kcp_conn) {
        return;
    }
    kcp_conn->skt->local_cid = kcp_conn->peer->cid = 0;
    skt_kcp_conn_del(kcp_conn);
}

void skt_monitor(skcptun_t* skt) {
    _LOG_E("**************************************");
    _LOG_E("*               monitor              *");
    _LOG_E("**************************************");
    _LOG_E("------------ skcptun info ------------");
    print_skcptun(skt);
    _LOG_E("--------------------------------------");
    // peers info
    skt_udp_peer_info();
    _LOG_E("--------------------------------------");
    // kcp connections info
    skt_kcp_conn_info();
    _LOG_E("--------------------------------------");
}
