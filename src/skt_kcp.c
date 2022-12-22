#include "skt_kcp.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>

#include "3rd/uthash/utlist.h"

static uint32_t rtt_cnt = 0;
static int max_rtt = 0;
static int min_rtt = INT_MAX;
static int avg_rtt = 0;
static int sum_rtt = 0;
static int last_avg_rtt = 0;

static void stat_rtt(skcp_conn_t *conn, const char *kcp_recv_buf) {
    rtt_cnt = rtt_cnt >= INT_MAX ? 0 : rtt_cnt + 1;
    if (rtt_cnt >= 1000000) {
        rtt_cnt = 0;
        max_rtt = 0;
        min_rtt = INT_MAX;
        avg_rtt = 0;
        sum_rtt = 0;
    }
    rtt_cnt++;

    char *pEnd = NULL;
    uint64_t pitm = strtoull(kcp_recv_buf, &pEnd, 10);
    uint64_t potm = strtoull(pEnd, NULL, 10);
    uint64_t now = getmillisecond();
    uint64_t rtt = now - pitm;
    sum_rtt += rtt;
    avg_rtt = sum_rtt / rtt_cnt;
    max_rtt = rtt > max_rtt ? rtt : max_rtt;
    min_rtt = rtt < min_rtt ? rtt : min_rtt;

    // LOG_I("stat sess_id: %u min_rtt: %d max_rtt: %d avg_rtt:%d cur_rtt:%lld", conn->sess_id, min_rtt, max_rtt,
    // avg_rtt,
    //   rtt);
    if (abs(last_avg_rtt - avg_rtt) > 10) {
        LOG_I("stat sess_id: %u min_rtt: %d max_rtt: %d avg_rtt:%d cur_rtt:%lld", conn->sess_id, min_rtt, max_rtt,
              avg_rtt, rtt);
    }

    last_avg_rtt = avg_rtt;
}

void skt_kcp_gen_htkey(char *htkey, int key_len, uint32_t sess_id, struct sockaddr_in *sock_addr) {
    in_port_t port = 0;
    in_addr_t ip = 0;
    if (sock_addr != NULL) {
        port = sock_addr->sin_port;
        ip = sock_addr->sin_addr.s_addr;
    }

    memset(htkey, 0, key_len);
    snprintf(htkey, key_len, "%u:%u:%u", ip, port, sess_id);

    return;
}

skcp_conn_t *skt_kcp_get_conn(skt_kcp_t *skt_kcp, char *htkey) { return skcp_get_conn(skt_kcp->skcp, htkey); }

static void call_conn_close_cb(skt_kcp_t *skt_kcp, skt_kcp_conn_t *kcp_conn) {
    skt_kcp->conn_close_cb(kcp_conn);
    // free kcp_conn
    FREE_IF(kcp_conn);
}

static int init_cli_network(skt_kcp_t *skt_kcp) {
    // 设置客户端
    // 创建socket对象
    skt_kcp->fd = socket(AF_INET, SOCK_DGRAM, 0);
    // 设置为非阻塞
    if (-1 == fcntl(skt_kcp->fd, F_SETFL, fcntl(skt_kcp->fd, F_GETFL) | O_NONBLOCK)) {
        LOG_E("error fcntl");
        close(skt_kcp->fd);
        return SKT_ERROR;
    }

    skt_kcp->servaddr.sin_family = AF_INET;
    skt_kcp->servaddr.sin_port = htons(skt_kcp->conf->port);
    skt_kcp->servaddr.sin_addr.s_addr = inet_addr(skt_kcp->conf->addr);

    return SKT_OK;
}

static int init_serv_network(skt_kcp_t *skt_kcp) {
    // 设置服务端
    skt_kcp->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (-1 == skt_kcp->fd) {
        LOG_E("start kcp server socket error");
        return SKT_ERROR;
    }
    // 设置为非阻塞
    setnonblock(skt_kcp->fd);

    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    if (NULL == skt_kcp->conf->addr) {
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        servaddr.sin_addr.s_addr = inet_addr(skt_kcp->conf->addr);
    }
    servaddr.sin_port = htons(skt_kcp->conf->port);

    if (-1 == bind(skt_kcp->fd, (struct sockaddr *)&servaddr, sizeof(servaddr))) {
        LOG_E("bind error when start kcp server");
        close(skt_kcp->fd);
        return SKT_ERROR;
    }

    LOG_I("udp listening %s %u", skt_kcp->conf->addr, skt_kcp->conf->port);

    return SKT_OK;
}

void skt_kcp_close_conn(skt_kcp_t *skt_kcp, char *htkey) {
    skcp_conn_t *conn = skt_kcp_get_conn(skt_kcp, htkey);
    if (NULL == conn) {
        return;
    }
    if (SKCP_CONN_ST_ON == conn->status || SKCP_CONN_ST_READY == conn->status) {
        conn->status = SKCP_CONN_ST_CAN_OFF;
    }
}

static void conn_timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents) {
    if (EV_ERROR & revents) {
        LOG_E("timeout_cb got invalid event");
        return;
    }
    skt_kcp_t *skt_kcp = (skt_kcp_t *)(watcher->data);
    uint64_t now = getmillisecond();
    skcp_conn_t *conn, *tmp;
    HASH_ITER(hh, skt_kcp->skcp->conn_ht, conn, tmp) {
        skt_kcp_conn_t *kcp_conn = (skt_kcp_conn_t *)conn->user_data;
        int rt = skcp_check_timeout(conn, now);
        if (rt == -1 || rt == -2) {
            // estab timeout or conn can off
            LOG_D("conn_timeout_cb rt:%d", rt);
            call_conn_close_cb(skt_kcp, kcp_conn);
        } else if (rt == -3) {
            // conn timeout
            skcp_close_conn(conn);
            call_conn_close_cb(skt_kcp, kcp_conn);
        } else {
            // send ping
            if (skt_kcp->mode == SKCP_MODE_CLI && conn->status == SKCP_CONN_ST_ON &&
                ((now - conn->last_r_tm) / 1000) > (skt_kcp->conf->skcp_conf->r_keepalive / 2)) {
                // TODO: 需要优化，目前仅用来统计rtt
                // LOG_I("send ping sess_id:%u time:%llu", conn->sess_id, now);
                // skcp_send_ping(conn, now);
            }
        }
    }
}

static int kcp_output(const char *buf, int len, skcp_conn_t *conn) {
    if (NULL == conn) {
        LOG_E("kcp_output conn is NULL");
        return -1;
    }

    skt_kcp_conn_t *kcp_conn = (skt_kcp_conn_t *)conn->user_data;

    // 加密
    char *out_buf = (char *)buf;
    int out_len = len;
    if (kcp_conn->skt_kcp->encrypt_cb) {
        out_buf = kcp_conn->skt_kcp->encrypt_cb(kcp_conn->skt_kcp, buf, len, &out_len);
    }
    if (out_len > conn->skcp->conf->mtu) {
        LOG_E("kcp skt_kcp output encrypt len > mtu:%d", conn->skcp->conf->mtu);
    }

    skcp_append_wait_buf(conn, out_buf, out_len);

    if (kcp_conn->skt_kcp->encrypt_cb) {
        FREE_IF(out_buf);
    }

    ev_io_start(kcp_conn->skt_kcp->loop, kcp_conn->skt_kcp->w_watcher);

    return 0;
}

// kcp update 回调
static void kcp_update_cb(struct ev_loop *loop, ev_timer *watcher, int revents) {
    if (EV_ERROR & revents) {
        LOG_E("kcp update got invalid event");
        return;
    }
    skt_kcp_t *skt_kcp = (skt_kcp_t *)(watcher->data);

    // 更新所有kcp update
    skcp_update_all(skt_kcp->skcp, clock());
}

int skt_kcp_send(skt_kcp_t *skt_kcp, char *htkey, const char *buf, int len) {
    skcp_conn_t *conn = skt_kcp_get_conn(skt_kcp, htkey);
    if (NULL == conn) {
        return -1;
    }
    int rt = skcp_send_data(conn, buf, len);
    return rt;
}

skcp_conn_t *skt_kcp_new_conn(skt_kcp_t *skt_kcp, uint32_t sess_id, struct sockaddr_in *sock_addr) {
    skt_kcp_conn_t *kcp_conn = malloc(sizeof(skt_kcp_conn_t));
    if (skt_kcp->mode == SKCP_MODE_CLI) {
        sess_id = skcp_gen_sess_id(skt_kcp->skcp);
        kcp_conn->dest_addr = skt_kcp->servaddr;
    }
    kcp_conn->skt_kcp = skt_kcp;
    kcp_conn->tcp_fd = 0;
    memset(kcp_conn->iv, 0, sizeof(kcp_conn->iv));

    char *htkey = malloc(SKCP_HTKEY_LEN);
    memset(htkey, 0, SKCP_HTKEY_LEN);
    skt_kcp_gen_htkey(htkey, SKCP_HTKEY_LEN, sess_id, sock_addr);
    uint64_t now = getmillisecond();
    skcp_conn_t *conn = skcp_create_conn(skt_kcp->skcp, htkey, sess_id, now, kcp_conn);
    return conn;
}

static void write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    if (EV_ERROR & revents) {
        LOG_E("read_cb got invalid event");
        return;
    }
    skt_kcp_t *skt_kcp = (skt_kcp_t *)(watcher->data);

    skcp_conn_t *conn, *tmp;
    HASH_ITER(hh, skt_kcp->skcp->conn_ht, conn, tmp) {
        skt_kcp_conn_t *kcp_conn = (skt_kcp_conn_t *)conn->user_data;
        if (conn->waiting_buf_q) {
            waiting_buf_t *wbtmp, *item;
            DL_FOREACH_SAFE(conn->waiting_buf_q, item, wbtmp) {
                int rt = sendto(kcp_conn->skt_kcp->fd, item->buf, item->len, 0, (struct sockaddr *)&kcp_conn->dest_addr,
                                sizeof(kcp_conn->dest_addr));
                if (-1 == rt) {
                    LOG_W("write_cb sendto error fd:%d  sess_id:%u errno: %d %s", kcp_conn->skt_kcp->fd, conn->sess_id,
                          errno, strerror(errno));
                    return;
                }
                conn->last_w_tm = getmillisecond();
                DL_DELETE(conn->waiting_buf_q, item);
                FREE_IF(item);
            }
            conn->waiting_buf_q = NULL;
        }
    }

    ev_io_stop(skt_kcp->loop, skt_kcp->w_watcher);
}

// 读回调
static void read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    if (EV_ERROR & revents) {
        LOG_E("read_cb got invalid event");
        return;
    }
    skt_kcp_t *skt_kcp = (skt_kcp_t *)(watcher->data);

    char *raw_buf = malloc(skt_kcp->conf->r_buf_size);
    struct sockaddr_in cliaddr;
    socklen_t cliaddr_len = sizeof(cliaddr);
    int32_t bytes =
        recvfrom(skt_kcp->fd, raw_buf, skt_kcp->conf->r_buf_size, 0, (struct sockaddr *)&cliaddr, &cliaddr_len);
    if (-1 == bytes) {
        LOG_E("read_cb recvfrom errno: %d %s", errno, strerror(errno));
        FREE_IF(raw_buf);
        return;
    }

    // 解密
    char *out_buf = raw_buf;
    int out_len = bytes;
    if (skt_kcp->decrypt_cb) {
        out_buf = skt_kcp->decrypt_cb(skt_kcp, raw_buf, bytes, &out_len);
        FREE_IF(raw_buf);
    }

    // 校验数据头
    if (24 > out_len) {
        LOG_E("read_cb kcp head error en_len: %d", out_len);
        FREE_IF(out_buf);
        return;
    }

    // 从数据包中解析出sessionid
    uint32_t sess_id = skcp_get_sess_id(out_buf);
    skcp_conn_t *conn = NULL;
    skt_kcp_conn_t *kcp_conn = NULL;
    char htkey[SKCP_HTKEY_LEN] = {0};

    if (skt_kcp->mode == SKCP_MODE_CLI) {
        skt_kcp_gen_htkey(htkey, SKCP_HTKEY_LEN, sess_id, NULL);
        conn = skt_kcp_get_conn(skt_kcp, htkey);
        if (NULL == conn) {
            FREE_IF(out_buf);
            return;
        }
        kcp_conn = (skt_kcp_conn_t *)conn->user_data;
    } else {
        skt_kcp_gen_htkey(htkey, SKCP_HTKEY_LEN, sess_id, &cliaddr);
        conn = skt_kcp_get_conn(skt_kcp, htkey);
        if (NULL == conn) {
            conn = skt_kcp_new_conn(skt_kcp, sess_id, &cliaddr);
            kcp_conn = (skt_kcp_conn_t *)conn->user_data;
            kcp_conn->dest_addr = cliaddr;
        }
        kcp_conn = (skt_kcp_conn_t *)conn->user_data;
    }

    skcp_input(conn, out_buf, out_len);
    FREE_IF(out_buf);

    char *kcp_recv_buf = malloc(skt_kcp->conf->kcp_buf_size);
    memset(kcp_recv_buf, 0, skt_kcp->conf->kcp_buf_size);
    int kcp_recv_len = 0;
    int op_type = 0;
    int rt = skcp_recv(conn, kcp_recv_buf, skt_kcp->conf->kcp_buf_size, &op_type);
    if (rt < 0) {
        // 错误
        LOG_D("skcp_recv error");
        skcp_close_conn(conn);
        call_conn_close_cb(skt_kcp, kcp_conn);
        FREE_IF(kcp_recv_buf);
        return;
    }

    if (rt == 0) {
        // empty EAGAIN
        LOG_I("skcp_recv empty");
        FREE_IF(kcp_recv_buf);
        return;
    }
    int iv_len = 0;
    switch (op_type) {
        case 1:
            // 创建连接
            iv_len = rt > sizeof(kcp_conn->iv) ? sizeof(kcp_conn->iv) : rt;
            memcpy(kcp_conn->iv, kcp_recv_buf, iv_len);

            skt_kcp->new_conn_cb(conn);
            LOG_D("new conn sess_id:%u", conn->sess_id);
            break;
        case 2:
            // 收到connect ack 命令
            iv_len = rt > sizeof(kcp_conn->iv) ? sizeof(kcp_conn->iv) : rt;
            memcpy(kcp_conn->iv, kcp_recv_buf, iv_len);
            LOG_D("cmd conn ack sess_id:%u", conn->sess_id);
            conn->last_r_tm = getmillisecond();
            break;
        case 3:
            // 收到close 命令
            LOG_D("cmd close tcp_fd:%u", kcp_conn->tcp_fd);
            conn->last_r_tm = getmillisecond();
            call_conn_close_cb(skt_kcp, kcp_conn);
            break;
        case 4:
            // 收到data 命令
            conn->last_r_tm = getmillisecond();
            skt_kcp->kcp_recv_cb(conn, kcp_recv_buf, rt);
            break;
        case 5:
            // 收到control命令
            LOG_D("cmd control sess_id:%u", conn->sess_id);
            conn->last_r_tm = getmillisecond();
            break;

        default:
            LOG_W("skcp_recv no op_type");
            break;
    }
    FREE_IF(kcp_recv_buf);
    return;

    // if (rt > 0) {
    //     // 成功
    //     conn->last_r_tm = getmillisecond();
    //     skt_kcp->kcp_recv_cb(conn, kcp_recv_buf, rt);
    // } else {
    //     switch (rt) {
    //         case -1:
    //             // 错误
    //             LOG_D("skcp_recv error");
    //             skcp_close_conn(conn);
    //             call_conn_close_cb(skt_kcp, kcp_conn);
    //             break;
    //         case -2:
    //             // 创建连接
    //             skt_kcp->new_conn_cb(conn);
    //             LOG_D("new conn sess_id:%u", conn->sess_id);
    //             break;
    //         case -3:
    //             // 收到connect ack 命令
    //             LOG_D("cmd conn ack sess_id:%u", conn->sess_id);
    //             conn->last_r_tm = getmillisecond();
    //             break;
    //         case -4:
    //             // 收到close 命令
    //             LOG_D("cmd close tcp_fd:%u", kcp_conn->tcp_fd);
    //             conn->last_r_tm = getmillisecond();
    //             call_conn_close_cb(skt_kcp, kcp_conn);
    //             break;
    //         case -5:
    //             // 收到ping 命令
    //             {
    //                 conn->last_r_tm = getmillisecond();
    //                 uint64_t pitm = strtoull(kcp_recv_buf, NULL, 10);
    //                 uint64_t now = getmillisecond();
    //                 skcp_send_pong(conn, pitm, now);
    //             }
    //             break;
    //         case -6:
    //             // 收到pong 命令
    //             conn->last_r_tm = getmillisecond();
    //             stat_rtt(conn, kcp_recv_buf);
    //             break;
    //         default:
    //             break;
    //     }
    // }
    // FREE_IF(kcp_recv_buf);
    // return;
}

skt_kcp_t *skt_kcp_init(skt_kcp_conf_t *conf, struct ev_loop *loop, void *data, SKCP_MODE mode) {
    skt_kcp_t *skt_kcp = malloc(sizeof(skt_kcp_t));
    skt_kcp->conf = conf;
    skt_kcp->data = data;
    skt_kcp->loop = loop;
    skt_kcp->mode = mode;

    if (mode == SKCP_MODE_CLI) {
        if (init_cli_network(skt_kcp) != SKT_OK) {
            FREE_IF(skt_kcp);
            return NULL;
        }
    } else {
        if (init_serv_network(skt_kcp) != SKT_OK) {
            FREE_IF(skt_kcp);
            return NULL;
        }
    }

    conf->skcp_conf->output = kcp_output;
    skt_kcp->skcp = skcp_init(conf->skcp_conf, mode);

    // 设置读事件循环
    skt_kcp->r_watcher = malloc(sizeof(struct ev_io));
    skt_kcp->r_watcher->data = skt_kcp;
    ev_io_init(skt_kcp->r_watcher, read_cb, skt_kcp->fd, EV_READ);
    ev_io_start(skt_kcp->loop, skt_kcp->r_watcher);

    // 设置写事件循环
    skt_kcp->w_watcher = malloc(sizeof(struct ev_io));
    skt_kcp->w_watcher->data = skt_kcp;
    ev_io_init(skt_kcp->w_watcher, write_cb, skt_kcp->fd, EV_WRITE);
    ev_io_start(skt_kcp->loop, skt_kcp->w_watcher);

    // 设置kcp定时循环
    skt_kcp->kcp_update_watcher = malloc(sizeof(ev_timer));
    double kcp_interval = conf->skcp_conf->interval / 1000.0;
    skt_kcp->kcp_update_watcher->data = skt_kcp;
    ev_init(skt_kcp->kcp_update_watcher, kcp_update_cb);
    ev_timer_set(skt_kcp->kcp_update_watcher, kcp_interval, kcp_interval);
    ev_timer_start(skt_kcp->loop, skt_kcp->kcp_update_watcher);

    // 设置超时定时循环
    skt_kcp->timeout_watcher = malloc(sizeof(ev_timer));
    skt_kcp->timeout_watcher->data = skt_kcp;
    ev_init(skt_kcp->timeout_watcher, conn_timeout_cb);
    ev_timer_set(skt_kcp->timeout_watcher, skt_kcp->conf->timeout_interval, skt_kcp->conf->timeout_interval);
    ev_timer_start(skt_kcp->loop, skt_kcp->timeout_watcher);

    return skt_kcp;
}

void skt_kcp_free(skt_kcp_t *skt_kcp) {
    if (skt_kcp->r_watcher) {
        ev_io_stop(skt_kcp->loop, skt_kcp->r_watcher);
        FREE_IF(skt_kcp->r_watcher);
    }

    if (skt_kcp->timeout_watcher) {
        ev_timer_stop(skt_kcp->loop, skt_kcp->timeout_watcher);
        FREE_IF(skt_kcp->timeout_watcher);
    }

    if (skt_kcp->kcp_update_watcher) {
        ev_timer_stop(skt_kcp->loop, skt_kcp->kcp_update_watcher);
        FREE_IF(skt_kcp->kcp_update_watcher);
    }

    skcp_conn_t *conn, *tmp;
    HASH_ITER(hh, skt_kcp->skcp->conn_ht, conn, tmp) {
        skt_kcp_conn_t *kcp_conn = (skt_kcp_conn_t *)conn->user_data;
        skcp_close_conn(conn);
        FREE_IF(kcp_conn);
    }

    if (skt_kcp->w_watcher) {
        ev_io_stop(skt_kcp->loop, skt_kcp->w_watcher);
        FREE_IF(skt_kcp->w_watcher);
    }
    skcp_free(skt_kcp->skcp);

    if (skt_kcp->fd) {
        close(skt_kcp->fd);
    }

    FREE_IF(skt_kcp);
    LOG_D("skt_kcp_free ok");
    return;
}