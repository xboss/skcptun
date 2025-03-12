
#include "skcptun.h"

#include <errno.h>

#include "skt_kcp_conn.h"

////////////////////////////////
// skcptun API
////////////////////////////////

skcptun_t* skt_init(skt_config_t* conf, struct ev_loop* loop) {
    if (!conf) return NULL;

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

    skt->idle_watcher = (ev_idle*)calloc(1, sizeof(ev_idle));
    if (!skt->idle_watcher) {
        perror("alloc idle_watcher");
        skt_free(skt);
        return NULL;
    }
    skt->idle_watcher->data = skt;

    return skt;
}

int skt_start_tun(skcptun_t* skt) {
    // Allocate TUN device
    skt->tun_fd = tun_alloc(skt->conf->tun_dev, IFNAMSIZ);
    if (skt->tun_fd < 0) {
        perror("tun_alloc");
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

    if (inet_pton(AF_INET, skt->conf->tun_ip, &skt->tun_ip_addr) <= 0) {
        perror("inet_pton tun_ip");
        return _ERR;
    }

    if (skt_set_nonblocking(skt->tun_fd) != _OK) {
        return _ERR;
    }
    return _OK;
}

int skt_kcp_to_tun(skcptun_t* skt, skt_packet_t* pkt) {
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
    char recv_buf[SKT_MTU - SKT_PKT_CMD_SZIE - SKT_TICKET_SIZE] = {0};
    int recv_len = skt_kcp_conn_recv(kcp_conn, pkt->payload, pkt->payload_len, recv_buf);
    if (recv_len <= 0) {
        _LOG("skt_kcp_conn_recv eagain. cid:%d len:%d", cid, recv_len);
        return _OK;
    }
    assert(recv_len <= sizeof(recv_buf));
    // send to tun
    assert(skt->tun_fd > 0);
    if (tun_write(skt->tun_fd, recv_buf, recv_len) <= 0) {
        _LOG_E("tun_write failed");
        return _ERR;
    }
    return _OK;
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

int skt_tun_to_kcp(skcptun_t* skt, const char* buf, int len) {
    // check result
    if (len < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            _LOG("tun read pending...");
            return _OK;
        } else {
            perror("recvfrom");
            return _ERR;
        }
    } else if (len == 0) {
        _LOG_E("tun read len: %d", len);
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
    _LOG("IPV4: %s -> %s", src_ip_str, dst_ip_str);

    assert(skt->tun_ip_addr > 0);
    uint32_t tun_ip = skt->tun_ip_addr;
    if (skt->conf->mode == SKT_MODE_REMOTE) {
        tun_ip = dst_ip;
    }
    // find kcp conn
    _LOG("skt_tun_to_kcp tun_ip:%u", tun_ip);
    skt_kcp_conn_t* kcp_conn = skt_kcp_conn_get_by_tun_ip(tun_ip);
    if (!kcp_conn) {
        _LOG_E("kcp conn not found in skt_tun_to_kcp, tun_ip: %u", tun_ip);
        return _ERR;
    }
    // kcp send
    int ret = ikcp_send(kcp_conn->kcp, buf, len);
    if (ret < 0) {
        _LOG_E(" ikcp_send failed, cid: %u", kcp_conn->cid);
        return _ERR;
    }
    return _OK;
}

void skt_free(skcptun_t* skt) {
    /* TODO: */
    return;
}

void skt_monitor(skcptun_t* skt) {
    // peers info
    skt_udp_peer_info();
    skt_kcp_conn_info();
    // kcp connections info
    /* TODO: */
}

void skt_update_kcp_cb(skt_kcp_conn_t* kcp_conn) {
    if (!kcp_conn || kcp_conn->cid == 0 || !kcp_conn->kcp) {
        _LOG_E("invalid kcp_conn");
        return;
    }
    ikcp_update(kcp_conn->kcp, SKT_MSTIME32);
}