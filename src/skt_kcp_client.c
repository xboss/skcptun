#include "skt_kcp_client.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "3rd/uthash/utlist.h"

static void append_wait_buf(skt_kcp_conn_t *conn, char *buffer, int len) {
    size_t wb_sz = sizeof(waiting_buf_t);
    waiting_buf_t *msg = (waiting_buf_t *)malloc(wb_sz);
    memset(msg, 0, wb_sz);
    memcpy(msg->buf, buffer, len);
    msg->len = len;
    DL_APPEND(conn->waiting_buf_q, msg);
}

skt_kcp_conn_t *skt_kcp_client_get_conn(skt_kcp_cli_t *cli, uint32_t sess_id) {
    skt_kcp_conn_t *conn = NULL;
    if (!cli->conn_ht) {
        return conn;
    }
    HASH_FIND_INT(cli->conn_ht, &sess_id, conn);
    return conn;
}

static int add_conn(uint32_t sess_id, skt_kcp_conn_t *conn) {
    if (NULL == conn) {
        return SKT_ERROR;
    }

    if (NULL == skt_kcp_client_get_conn(conn->cli, sess_id)) {
        HASH_ADD_INT(conn->cli->conn_ht, sess_id, conn);
    }
    return SKT_OK;
}

static int del_conn(skt_kcp_conn_t *conn) {
    if (NULL == conn) {
        return SKT_ERROR;
    }
    LOG_D("del_conn sess_id:%d", conn->sess_id);
    HASH_DEL(conn->cli->conn_ht, conn);
    return SKT_OK;
}

static int init_network(skt_kcp_cli_t *cli) {
    // 设置客户端
    //创建socket对象
    cli->fd = socket(AF_INET, SOCK_DGRAM, 0);
    //设置立即释放端口并可以再次使用
    int reuse = 1;
    if (-1 == setsockopt(cli->fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))) {
        LOG_E("setsockopt error in uac_init");
        close(cli->fd);
        return SKT_ERROR;
    }
    //设置为非阻塞
    if (-1 == fcntl(cli->fd, F_SETFL, fcntl(cli->fd, F_GETFL) | O_NONBLOCK)) {
        LOG_E("error fcntl in uac_init");
        close(cli->fd);
        return SKT_ERROR;
    }

    cli->servaddr.sin_family = AF_INET;
    cli->servaddr.sin_port = htons(cli->conf->port);
    cli->servaddr.sin_addr.s_addr = inet_addr(cli->conf->addr);

    return SKT_OK;
}

static int kcp_send_raw(skt_kcp_conn_t *conn, char *buf, int len, char cmd) {
    char *raw_buf = NULL;
    int raw_len = 0;
    if (SKT_KCP_CMD_DATA == cmd) {
        raw_len = len + 1;
        raw_buf = malloc(raw_len);
        snprintf(raw_buf, raw_len, "%c", cmd);
        char *p = raw_buf + 1;
        memcpy(p, buf, len);
    } else {
        // add jam
        srand((unsigned)time(NULL));
        int jam = rand() % (RAND_MAX - 10000000) + 10000000;
        char s[34] = {0};
        snprintf(s, 34, "%c%d", cmd, jam);
        raw_len = strlen(s);
        raw_buf = s;
    }

    int rt = ikcp_send(conn->kcp, raw_buf, raw_len);
    if (SKT_KCP_CMD_DATA == cmd) {
        FREE_IF(raw_buf);
    }
    if (rt < 0) {
        // 发送失败
        LOG_E("kcp_send_raw send error");
        return -1;
    }
    ikcp_update(conn->kcp, clock());  // TODO: 可以性能优化

    return rt;
}

static void close_conn(skt_kcp_cli_t *cli, uint32_t sess_id, int close_cmd_flg) {
    skt_kcp_conn_t *conn = skt_kcp_client_get_conn(cli, sess_id);
    if (NULL == conn) {
        return;
    }

    if (!close_cmd_flg) {
        kcp_send_raw(conn, NULL, 0, SKT_KCP_CMD_CLOSE);
    }

    LOG_D("close_conn sess_id:%u", conn->sess_id);
    conn->status = SKT_KCP_CONN_ST_OFF;
    conn->cli->conn_close_cb(conn);

    if (conn->cli->conn_ht) {
        del_conn(conn);
    }

    if (conn->waiting_buf_q) {
        waiting_buf_t *wbtmp, *item;
        DL_FOREACH_SAFE(conn->waiting_buf_q, item, wbtmp) {
            DL_DELETE(conn->waiting_buf_q, item);
            FREE_IF(item);
        }
        conn->waiting_buf_q = NULL;
    }

    if (conn->kcp) {
        ikcp_release(conn->kcp);
        conn->kcp = NULL;
    }

    conn->sess_id = 0;  // TODO: for test
    FREE_IF(conn);
}
void skt_kcp_client_close_conn(skt_kcp_cli_t *cli, uint32_t sess_id) {
    skt_kcp_conn_t *conn = skt_kcp_client_get_conn(cli, sess_id);
    if (NULL == conn) {
        return;
    }
    if (SKT_KCP_CONN_ST_ON == conn->status || SKT_KCP_CONN_ST_READY == conn->status) {
        conn->status = SKT_KCP_CONN_ST_CAN_OFF;
    }
}

static void conn_timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents) {
    if (EV_ERROR & revents) {
        LOG_E("timeout_cb got invalid event");
        return;
    }
    skt_kcp_cli_t *cli = (skt_kcp_cli_t *)(watcher->data);
    uint64_t now = getmillisecond();
    skt_kcp_conn_t *conn, *tmp;
    HASH_ITER(hh, cli->conn_ht, conn, tmp) {
        if (SKT_KCP_CONN_ST_READY == conn->status) {
            // 连接管理
            if ((now - conn->estab_tm) >= cli->conf->estab_timeout * 1000l) {
                // 超时
                LOG_D("estab_timeout sess_id:%u", conn->sess_id);
                close_conn(cli, conn->sess_id, 0);
            }
        } else {
            if (SKT_KCP_CONN_ST_CAN_OFF == conn->status) {
                close_conn(cli, conn->sess_id, 0);
            } else {
                if ((now - conn->last_r_tm) >= cli->conf->r_keepalive * 1000l) {
                    // 超时
                    LOG_D("conn_timeout_cb sess_id:%u", conn->sess_id);
                    cli->conn_timeout_cb(conn);
                }
            }
        }
    }
}

static int kcp_output(const char *buf, int len, ikcpcb *kcp, void *user) {
    skt_kcp_conn_t *conn = (skt_kcp_conn_t *)user;
    if (NULL == conn) {
        LOG_E("kcp_output conn is NULL");
        return -1;
    }

    // 加密
    char *out_buf = (char *)buf;
    int out_len = len;
    if (conn->cli->encrypt_cb) {
        out_buf = conn->cli->encrypt_cb(buf, len, &out_len);
    }
    if (out_len > conn->cli->conf->mtu) {
        LOG_E("kcp cli output encrypt len > mtu:%d", conn->cli->conf->mtu);
    }

    int rt = sendto(conn->cli->fd, out_buf, out_len, 0, (struct sockaddr *)&conn->cli->servaddr,
                    sizeof(conn->cli->servaddr));
    if (-1 == rt) {
        LOG_E("output sendto error fd:%d", conn->cli->fd);
        if (conn->cli->encrypt_cb) {
            FREE_IF(out_buf);
        }
        return -1;
    }
    conn->last_w_tm = getmillisecond();

    if (conn->cli->encrypt_cb) {
        FREE_IF(out_buf);
    }

    return 0;
}

static ikcpcb *create_kcp(uint32_t sess_id, skt_kcp_conn_t *conn) {
    ikcpcb *kcp = ikcp_create(sess_id, conn);
    kcp->output = kcp_output;
    skt_kcp_cli_conf_t *conf = conn->cli->conf;
    ikcp_wndsize(kcp, conf->sndwnd, conf->rcvwnd);
    ikcp_nodelay(kcp, conf->nodelay, conf->interval, conf->nodelay, conf->nc);
    ikcp_setmtu(kcp, conf->mtu);
    return kcp;
}

// kcp update 回调
static void kcp_update_cb(struct ev_loop *loop, ev_timer *watcher, int revents) {
    if (EV_ERROR & revents) {
        LOG_E("kcp update got invalid event");
        return;
    }
    skt_kcp_cli_t *cli = (skt_kcp_cli_t *)(watcher->data);
    // 更新所有kcp update
    skt_kcp_conn_t *conn, *tmp;
    HASH_ITER(hh, cli->conn_ht, conn, tmp) { ikcp_update(conn->kcp, clock()); }
}

int skt_kcp_client_send(skt_kcp_cli_t *cli, uint32_t sess_id, char *buf, int len) {
    skt_kcp_conn_t *conn = skt_kcp_client_get_conn(cli, sess_id);
    if (NULL == conn) {
        return -1;
    }

    if (SKT_KCP_CONN_ST_READY == conn->status) {
        LOG_D("skt_kcp_client_send add waiting buf sess_id:%u status:%d", conn->sess_id, conn->status);
        append_wait_buf(conn, buf, len);
        conn->last_w_tm = getmillisecond();  // TODO: 需要？
        return len;
    }

    if (SKT_KCP_CONN_ST_ON != conn->status) {
        LOG_E("skt_kcp_client_send sess status not on sess_id:%u status:%d", conn->sess_id, conn->status);
        return -1;
    }

    if (conn->waiting_buf_q) {
        LOG_D("skt_kcp_client_send send waiting buf sess_id: %d", conn->sess_id);
        waiting_buf_t *wbtmp, *item;
        DL_FOREACH_SAFE(conn->waiting_buf_q, item, wbtmp) {
            ssize_t rt = kcp_send_raw(conn, item->buf, item->len, SKT_KCP_CMD_DATA);
            if (rt < 0) {
                LOG_E("skt_kcp_client_send write error sess_id:%d rt:%zd", conn->sess_id, rt);
                return rt;
            }
            DL_DELETE(conn->waiting_buf_q, item);
            FREE_IF(item);
        }
        conn->waiting_buf_q = NULL;
    }

    return kcp_send_raw(conn, buf, len, SKT_KCP_CMD_DATA);
}

skt_kcp_conn_t *skt_kcp_client_new_conn(skt_kcp_cli_t *cli) {
    skt_kcp_conn_t *conn = malloc(sizeof(skt_kcp_conn_t));
    conn->sess_id = cli->cur_sess_id;
    cli->cur_sess_id++;

    conn->cli = cli;
    conn->kcp = create_kcp(conn->sess_id, conn);
    uint64_t now = getmillisecond();
    conn->last_r_tm = now;
    conn->last_w_tm = now;
    conn->estab_tm = now;
    conn->status = SKT_KCP_CONN_ST_READY;  // TODO:
    conn->tcp_fd = 0;
    conn->waiting_buf_q = NULL;

    // 发送连接请求
    kcp_send_raw(conn, NULL, 0, SKT_KCP_CMD_CONN);

    add_conn(conn->sess_id, conn);

    return conn;
}

static int parse_recv_data(skt_kcp_conn_t *conn, char *buf, int len) {
    skt_kcp_cli_t *cli = conn->cli;

    if (len < 1) {
        LOG_E("parse_recv_data error len:%d", len);
        return SKT_ERROR;
    }

    char cmd = *buf;
    if (SKT_KCP_CMD_CONN_ACK == cmd) {
        if (SKT_KCP_CONN_ST_READY != conn->status) {
            LOG_D("parse_recv_data conn not ready sess_id:%u", conn->sess_id);
            close_conn(cli, conn->sess_id, 0);
            return SKT_ERROR;
        }

        conn->status = SKT_KCP_CONN_ST_ON;
        LOG_D("cmd conn_ack sess_id:%u", conn->sess_id);

        if (conn->waiting_buf_q) {
            LOG_D("skt_kcp_client_send send waiting buf sess_id: %d", conn->sess_id);
            waiting_buf_t *wbtmp, *item;
            DL_FOREACH_SAFE(conn->waiting_buf_q, item, wbtmp) {
                ssize_t rt = kcp_send_raw(conn, item->buf, item->len, SKT_KCP_CMD_DATA);
                if (rt < 0) {
                    LOG_E("skt_kcp_client_send write error sess_id:%d rt:%zd", conn->sess_id, rt);
                    return SKT_ERROR;
                }
                DL_DELETE(conn->waiting_buf_q, item);
                FREE_IF(item);
            }
            conn->waiting_buf_q = NULL;
        }

        return SKT_OK;
    } else if (SKT_KCP_CMD_CLOSE == cmd) {
        close_conn(cli, conn->sess_id, 1);
        return SKT_ERROR;  // 为了阻断执行
    } else if (SKT_KCP_CMD_PING == cmd) {
        // TODO:
        return SKT_OK;
    } else if (SKT_KCP_CMD_DATA == cmd) {
        LOG_D("cmd conn_data sess_id:%u", conn->sess_id);
        char *p = buf + 1;
        return cli->kcp_recv_cb(conn, p, len - 1);
    }

    LOG_E("parse_recv_data error cmd:%c", cmd);
    return SKT_ERROR;
}

// 读回调
static void read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    if (EV_ERROR & revents) {
        LOG_E("read_cb got invalid event");
        return;
    }
    skt_kcp_cli_t *cli = (skt_kcp_cli_t *)(watcher->data);

    char *raw_buf = malloc(cli->conf->r_buf_size);
    // memset(raw_buf, 0, cli->conf->r_buf_size);
    struct sockaddr_in cliaddr;
    socklen_t cliaddr_len = sizeof(cliaddr);
    int32_t bytes = recvfrom(cli->fd, raw_buf, cli->conf->r_buf_size, 0, (struct sockaddr *)&cliaddr, &cliaddr_len);
    // LOG_D("read_cb %d", bytes);
    if (-1 == bytes) {
        LOG_E("read_cb recvfrom errno: %d %s", errno, strerror(errno));
        FREE_IF(raw_buf);
        return;
    }

    // 解密
    char *out_buf = raw_buf;
    int out_len = bytes;
    if (cli->decrypt_cb) {
        out_buf = cli->decrypt_cb(raw_buf, bytes, &out_len);
        FREE_IF(raw_buf);
    }

    // 校验数据头
    if (24 > out_len) {
        LOG_E("read_cb kcp head error en_len: %d", out_len);
        FREE_IF(out_buf);
        return;
    }

    // 从数据包中解析出sessionid
    uint32_t sess_id = ikcp_getconv(out_buf);
    skt_kcp_conn_t *conn = skt_kcp_client_get_conn(cli, sess_id);
    if (NULL == conn) {
        // LOG_E("read_cb conn is NULL sess_id:%d", sess_id);
        FREE_IF(out_buf);
        return;
    }

    ikcp_input(conn->kcp, (char *)out_buf, out_len);
    ikcp_update(conn->kcp, clock());  // TODO: 可以性能优化
    FREE_IF(out_buf);

    char *kcp_recv_buf = malloc(cli->conf->kcp_buf_size);
    memset(kcp_recv_buf, 0, cli->conf->kcp_buf_size);  // TODO: 优化
    int kcp_recv_len = 0;
    while ((kcp_recv_len = skt_kcp_recv(conn, kcp_recv_buf, cli->conf->kcp_buf_size)) > 0) {
        // 触发上层的收数据操作
        conn->last_r_tm = getmillisecond();
        if (parse_recv_data(conn, kcp_recv_buf, kcp_recv_len) != SKT_OK) {
            break;
        }
    }
    FREE_IF(kcp_recv_buf);
    return;
}

skt_kcp_cli_t *skt_kcp_client_init(skt_kcp_cli_conf_t *conf, struct ev_loop *loop, void *data) {
    skt_kcp_cli_t *cli = malloc(sizeof(skt_kcp_cli_t));
    cli->conf = conf;
    cli->data = data;
    cli->loop = loop;
    cli->conn_ht = NULL;
    cli->cur_sess_id = 1;

    if (init_network(cli) != SKT_OK) {
        FREE_IF(cli);
        return NULL;
    }

    // 设置读事件循环
    cli->r_watcher = malloc(sizeof(struct ev_io));
    cli->r_watcher->data = cli;
    ev_io_init(cli->r_watcher, read_cb, cli->fd, EV_READ);
    ev_io_start(cli->loop, cli->r_watcher);

    // 设置kcp定时循环
    cli->kcp_update_watcher = malloc(sizeof(ev_timer));
    double kcp_interval = conf->interval / 1000.0;
    cli->kcp_update_watcher->data = cli;
    ev_init(cli->kcp_update_watcher, kcp_update_cb);
    ev_timer_set(cli->kcp_update_watcher, kcp_interval, kcp_interval);
    ev_timer_start(cli->loop, cli->kcp_update_watcher);

    // 设置超时定时循环
    cli->timeout_watcher = malloc(sizeof(ev_timer));
    cli->timeout_watcher->data = cli;
    ev_init(cli->timeout_watcher, conn_timeout_cb);
    ev_timer_set(cli->timeout_watcher, cli->conf->timeout_interval, cli->conf->timeout_interval);
    ev_timer_start(cli->loop, cli->timeout_watcher);

    return cli;
}

void skt_kcp_client_free(skt_kcp_cli_t *cli) {
    if (cli->r_watcher && ev_is_active(cli->r_watcher)) {
        ev_io_stop(cli->loop, cli->r_watcher);
        FREE_IF(cli->r_watcher);
    }

    if (cli->timeout_watcher && ev_is_active(cli->timeout_watcher)) {
        ev_timer_stop(cli->loop, cli->timeout_watcher);
        FREE_IF(cli->timeout_watcher);
    }

    if (cli->kcp_update_watcher && ev_is_active(cli->kcp_update_watcher)) {
        ev_timer_stop(cli->loop, cli->kcp_update_watcher);
        FREE_IF(cli->kcp_update_watcher);
    }

    skt_kcp_conn_t *conn, *tmp;
    HASH_ITER(hh, cli->conn_ht, conn, tmp) {
        close_conn(cli, conn->sess_id, 0);
        conn = NULL;
    }
    cli->conn_ht = NULL;

    if (cli->fd) {
        close(cli->fd);
    }

    FREE_IF(cli);
    LOG_D("skt_kcp_client_free ok");
    return;
}