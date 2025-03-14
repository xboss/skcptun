#include "skcptun.h"

#include <errno.h>

#include "skt_kcp_conn.h"

static void print_skcptun(const skcptun_t* skt) {
    if (!skt) {
        printf("skcptun_t is NULL\n");
        return;
    }

    printf("skcptun_t:\n");
    printf("  running: %d\n", skt->running);
    printf("  tun_fd: %d\n", skt->tun_fd);
    printf("  udp_fd: %d\n", skt->udp_fd);
    printf("  tun_ip_addr: %u\n", skt->tun_ip_addr);
    printf("  local_cid: %u\n", skt->local_cid);
    printf("  last_cllect_tm: %" PRIu64 "\n", skt->last_cllect_tm);

    if (!skt->conf) {
        printf("  skt_config_t is NULL\n");
        return;
    }

    const skt_config_t* conf = skt->conf;
    printf("  skt_config_t:\n");
    printf("    udp_local_ip: %s\n", conf->udp_local_ip);
    printf("    udp_local_port: %u\n", conf->udp_local_port);
    printf("    udp_remote_ip: %s\n", conf->udp_remote_ip);
    printf("    udp_remote_port: %u\n", conf->udp_remote_port);
    printf("    key: %s\n", conf->key);
    printf("    iv: %s\n", conf->iv);
    printf("    ticket: %s\n", conf->ticket);
    printf("    mode: %d\n", conf->mode);
    printf("    timeout: %d\n", conf->timeout);
    printf("    log_file: %s\n", conf->log_file);
    printf("    log_level: %d\n", conf->log_level);
    printf("    tun_dev: %s\n", conf->tun_dev);
    printf("    tun_ip: %s\n", conf->tun_ip);
    printf("    tun_mask: %s\n", conf->tun_mask);
    printf("    tun_mtu: %d\n", conf->tun_mtu);
    printf("    mtu: %d\n", conf->mtu);
    printf("    keepalive: %d\n", conf->keepalive);
    printf("    kcp_mtu: %d\n", conf->kcp_mtu);
    printf("    kcp_interval: %d\n", conf->kcp_interval);
    printf("    kcp_nodelay: %d\n", conf->kcp_nodelay);
    printf("    kcp_resend: %d\n", conf->kcp_resend);
    printf("    kcp_nc: %d\n", conf->kcp_nc);
    printf("    kcp_sndwnd: %d\n", conf->kcp_sndwnd);
    printf("    kcp_rcvwnd: %d\n", conf->kcp_rcvwnd);
    printf("    speed_mode: %d\n", conf->speed_mode);
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

// static void udp_write_cb(struct ev_loop* loop, struct ev_io* watcher, int revents) {
//     if (EV_ERROR & revents) {
//         _LOG_E("udp_write_cb got invalid event");
//         return;
//     }
//     _LOG("udp_write_cb start");
//     skt_kcp_conn_t* kcp_conn = (skt_kcp_conn_t*)watcher->data;
//     assert(kcp_conn);
//     ikcp_update(kcp_conn->kcp, SKT_MSTIME32);
//     ikcp_flush(kcp_conn->kcp);
//     if (kcp_conn->kcp->nsnd_que == 0) {
//         ev_io_stop(loop, watcher);
//     }
//     _LOG("udp_write_cb end");

//     /* TODO: */
// }

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
    skt->loop = loop;
    skt->tun_r_watcher_started = 0;

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

    skt->tun_r_watcher = (ev_io*)calloc(1, sizeof(ev_io));
    if (!skt->tun_r_watcher) {
        perror("alloc tun_r_watcher");
        skt_free(skt);
        return NULL;
    }
    skt->tun_r_watcher->data = skt;

    skt->udp_r_watcher = (ev_io*)calloc(1, sizeof(ev_io));
    if (!skt->udp_r_watcher) {
        perror("alloc udp_r_watcher");
        skt_free(skt);
        return NULL;
    }
    skt->udp_r_watcher->data = skt;

    // skt->udp_w_watcher = (ev_io*)calloc(1, sizeof(ev_io));
    // if (!skt->udp_w_watcher) {
    //     perror("alloc udp_w_watcher");
    //     skt_free(skt);
    //     return NULL;
    // }
    // // skt->udp_w_watcher->data = skt;
    // ev_io_init(skt->udp_w_watcher, udp_write_cb, skt->udp_fd, EV_READ);

    skt->idle_watcher = (ev_idle*)calloc(1, sizeof(ev_idle));
    if (!skt->idle_watcher) {
        perror("alloc idle_watcher");
        skt_free(skt);
        return NULL;
    }
    skt->idle_watcher->data = skt;

    return skt;
}

void skt_free(skcptun_t* skt) {
    if (!skt) return;
    skt->running = 0;

    if (skt->timeout_watcher) {
        ev_timer_stop(skt->loop, skt->timeout_watcher);
        free(skt->timeout_watcher);
        skt->timeout_watcher = NULL;
    }
    if (skt->kcp_update_watcher) {
        ev_timer_stop(skt->loop, skt->kcp_update_watcher);
        free(skt->kcp_update_watcher);
        skt->kcp_update_watcher = NULL;
    }
    if (skt->tun_r_watcher) {
        ev_io_stop(skt->loop, skt->tun_r_watcher);
        free(skt->tun_r_watcher);
        skt->tun_r_watcher = NULL;
    }
    if (skt->udp_r_watcher) {
        ev_io_stop(skt->loop, skt->udp_r_watcher);
        free(skt->udp_r_watcher);
        skt->udp_r_watcher = NULL;
    }
    // if (skt->udp_w_watcher) {
    //     ev_io_stop(skt->loop, skt->udp_w_watcher);
    //     free(skt->udp_w_watcher);
    //     skt->udp_w_watcher = NULL;
    // }
    if (skt->idle_watcher) {
        ev_idle_stop(skt->loop, skt->idle_watcher);
        free(skt->idle_watcher);
        skt->idle_watcher = NULL;
    }

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
    if (skt_set_nonblocking(skt->tun_fd) != _OK) {
        return _ERR;
    }
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
        return _ERR;
    }
    ikcp_update(kcp_conn->kcp, SKT_MSTIME32);
    ikcp_flush(kcp_conn->kcp);
    // _LOG("skt_tun_to_kcp send ok len:%d", ret);
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

void skt_monitor(skcptun_t* skt) {
    printf("**************************************\n");
    printf("*               monitor              *\n");
    printf("**************************************\n");
    printf("------------ skcptun info ------------\n");
    print_skcptun(skt);
    printf("--------------------------------------\n");
    // peers info
    skt_udp_peer_info();
    printf("--------------------------------------\n");
    // kcp connections info
    skt_kcp_conn_info();
    printf("--------------------------------------\n");
}
