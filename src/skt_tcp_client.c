#include "skt_tcp_client.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "3rd/uthash/utlist.h"
#include "skt_utils.h"

#define TIMEOUT_INTERVAL 1  // 超时检查的间隔，单位：秒

static void append_wait_buf(skt_tcp_cli_conn_t *conn, char *buffer, int len) {
    size_t wb_sz = sizeof(waiting_buf_t);
    waiting_buf_t *msg = (waiting_buf_t *)malloc(wb_sz);
    memset(msg, 0, wb_sz);
    memcpy(msg->buf, buffer, len);
    msg->len = len;
    DL_APPEND(conn->waiting_buf_q, msg);
}

skt_tcp_cli_conn_t *skt_tcp_client_get_conn(skt_tcp_cli_t *cli, int fd) {
    skt_tcp_cli_conn_t *conn = NULL;
    HASH_FIND_INT(cli->conn_ht, &fd, conn);
    return conn;
}

static int client_connect(int *fd, struct sockaddr_in servaddr, long recv_timeout, long send_timeout) {
    if (*fd <= 0) {
        *fd = socket(AF_INET, SOCK_STREAM, 0);
        if (-1 == *fd) {
            LOG_E("skt_tcp_client_connect socket error fd: %d", *fd);
            return -1;
        }
    }

    assert(*fd > 0);

    // 设置非阻塞, 设置立即释放端口并可以再次使用
    setnonblock(*fd);
    setreuseaddr(*fd);
    // 设置超时
    set_recv_timeout(*fd, recv_timeout);
    set_send_timeout(*fd, send_timeout);

    int crt = connect(*fd, (struct sockaddr *)&servaddr, sizeof(servaddr));
    if (0 != crt) {
        if (errno != EINPROGRESS) {
            // 连接失败
            LOG_E("skt_tcp_client_connect error fd:%d errno:%s ", *fd, strerror(errno));
            return -1;
        } else {
            // 连接没有立即成功，需进行二次判断
            LOG_D("skt_tcp_client_connect waiting fd:%d errno:%s ", *fd, strerror(errno));
            return 1;
        }
    }

    LOG_D("skt_tcp_client_connect ok fd: %d", *fd);

    return 0;
}

void skt_tcp_client_close_conn(skt_tcp_cli_t *cli, int fd) {
    skt_tcp_cli_conn_t *conn = skt_tcp_client_get_conn(cli, fd);
    if (NULL == conn) {
        return;
    }

    if (skt_tcp_client_get_conn(conn->tcp_cli, conn->fd)) {
        HASH_DEL(conn->tcp_cli->conn_ht, conn);
    }

    if (SKT_TCP_CONN_ST_ON == conn->status) {
        conn->status = SKT_TCP_CONN_ST_OFF;
    }

    if (conn->waiting_buf_q) {
        waiting_buf_t *wbtmp, *item;
        DL_FOREACH_SAFE(conn->waiting_buf_q, item, wbtmp) {
            DL_DELETE(conn->waiting_buf_q, item);
            FREE_IF(item);
        }
        conn->waiting_buf_q = NULL;
    }

    if (conn->r_watcher) {
        ev_io_stop(conn->tcp_cli->loop, conn->r_watcher);
        FREE_IF(conn->r_watcher);
    }

    if (conn->w_watcher) {
        ev_io_stop(cli->loop, conn->w_watcher);
        FREE_IF(conn->w_watcher)
    }

    conn->tcp_cli->conf->close_cb(conn);
    if (conn->fd) {
        close(conn->fd);
        conn->fd = 0;
    }

    FREE_IF(conn);
}

void conn_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    if (EV_ERROR & revents) {
        LOG_E("conn_read_cb error event fd: %d", watcher->fd);
        return;
    }

    skt_tcp_cli_t *cli = (skt_tcp_cli_t *)watcher->data;

    skt_tcp_cli_conn_t *conn = skt_tcp_client_get_conn(cli, watcher->fd);
    if (conn == NULL) {
        LOG_E("conn_read_cb tcpconn is null fd: %d", watcher->fd);
        ev_io_stop(loop, watcher);
        FREE_IF(watcher);
        return;
    }
    if (conn->status != SKT_TCP_CONN_ST_ON) {
        LOG_E("conn_read_cb tcpconn is off fd: %d", watcher->fd);
        skt_tcp_client_close_conn(cli, watcher->fd);
        conn = NULL;
        return;
    }

    char *buffer = malloc(conn->r_buf_size);
    memset(buffer, 0, conn->r_buf_size);  // TODO: 为了性能可以去掉
    int res = 0;
    int32_t bytes = read(watcher->fd, buffer, conn->r_buf_size);
    if (-1 == bytes) {
        // tcp Error
        if (EINTR != errno && EAGAIN != errno && EWOULDBLOCK != errno) {
            res = 1;
            LOG_E("conn_read_cb tcp error fd:%d, errno:%s", watcher->fd, strerror(errno));
        } else {
            LOG_W("conn_read_cb tcp warn fd:%d, errno:%s", watcher->fd, strerror(errno));
        }
    } else if (0 == bytes) {
        if (errno != EINPROGRESS) {
            // tcp Close
            res = 2;
            LOG_E("conn_read_cb tcp close fd:%d, errno:%s", watcher->fd, strerror(errno));
        }
    }

    if (0 != res) {
        //关闭事件循环并释放watcher
        FREE_IF(buffer);
        conn->status = SKT_TCP_CONN_ST_OFF;
        skt_tcp_client_close_conn(cli, conn->fd);
        conn = NULL;
        return;
    }

    if (bytes > 0) {
        if (-1 == cli->conf->recv_cb(conn, buffer, bytes)) {
            LOG_E("tcp_conn_recv_cb recv_cb error fd: %d", conn->fd);
            FREE_IF(buffer);
            conn->status = SKT_TCP_CONN_ST_OFF;
            skt_tcp_client_close_conn(cli, conn->fd);
            conn = NULL;
            return;
        }
    }

    FREE_IF(buffer);
    conn->last_r_tm = getmillisecond();
}

ssize_t skt_tcp_client_send(skt_tcp_cli_t *cli, int fd, char *buf, int len) {
    skt_tcp_cli_conn_t *conn = skt_tcp_client_get_conn(cli, fd);
    if (NULL == conn) {
        return -1;
    }

    if (conn == NULL || conn->fd <= 0) {
        LOG_E("skt_tcp_client_send connection error");
        return -1;
    }

    if (SKT_TCP_CONN_ST_READY == conn->status) {
        // LOG_D("skt_tcp_client_send write waiting buf:%s", buf);
        append_wait_buf(conn, buf, len);
        conn->last_w_tm = getmillisecond();
        return len;
    }

    if (SKT_TCP_CONN_ST_ON == conn->status && conn->waiting_buf_q) {
        // LOG_D("skt_tcp_client_send send waiting buf fd: %d", conn->fd);
        waiting_buf_t *wbtmp, *item;
        DL_FOREACH_SAFE(conn->waiting_buf_q, item, wbtmp) {
            ssize_t rt = write(conn->fd, item->buf, item->len);
            if (rt < 0) {
                LOG_E("skt_tcp_client_send write error fd:%d rt:%zd", conn->fd, rt);
                return rt;
            }
            DL_DELETE(conn->waiting_buf_q, item);
            FREE_IF(item);
        }
        conn->waiting_buf_q = NULL;
    }

    ssize_t rt = len;
    rt = write(conn->fd, buf, len);
    if (rt < 0) {
        LOG_E("skt_tcp_client_send write error fd:%d rt:%zd", conn->fd, rt);
    }

    conn->last_w_tm = getmillisecond();
    // LOG_D("skt_tcp_client_send:%ld", rt);
    return rt;
}

static void conn_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    if (EV_ERROR & revents) {
        LOG_E("conn_write_cb error event fd: %d", watcher->fd);
        return;
    }

    skt_tcp_cli_t *cli = (skt_tcp_cli_t *)watcher->data;

    skt_tcp_cli_conn_t *conn = skt_tcp_client_get_conn(cli, watcher->fd);
    if (conn == NULL) {
        LOG_E("conn_write_cb tcpconn is NULL fd: %d", watcher->fd);
        ev_io_stop(loop, watcher);
        FREE_IF(watcher);
        return;
    }

    conn->status = SKT_TCP_CONN_ST_ON;
    LOG_D("conn_write_cb write chg status on fd: %d", conn->fd);
    ev_io_stop(loop, watcher);
    FREE_IF(watcher);
    conn->w_watcher = NULL;

    if (SKT_TCP_CONN_ST_ON == conn->status && conn->waiting_buf_q) {
        LOG_D("conn_write_cb send waiting buf fd: %d", conn->fd);
        waiting_buf_t *wbtmp, *item;
        DL_FOREACH_SAFE(conn->waiting_buf_q, item, wbtmp) {
            ssize_t rt = write(conn->fd, item->buf, item->len);
            if (rt < 0) {
                LOG_E("skt_tcp_client_send write error fd:%d rt:%zd", conn->fd, rt);
                return;
            }
            DL_DELETE(conn->waiting_buf_q, item);
            FREE_IF(item);
        }
        conn->waiting_buf_q = NULL;
    }
}

skt_tcp_cli_conn_t *skt_tcp_client_create_conn(skt_tcp_cli_t *cli, char *addr, uint16_t port) {
    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    inet_pton(AF_INET, addr, &servaddr.sin_addr);
    servaddr.sin_port = htons(port);

    int tcp_conn_fd = 0;
    int crt = client_connect(&tcp_conn_fd, servaddr, cli->conf->recv_timeout, cli->conf->send_timeout);
    if (crt < 0) {
        LOG_E("connect error addr: %s port: %u fd: %d", addr, port, tcp_conn_fd);
        return NULL;
    }

    LOG_D("skt_tcp_client_create_conn connect ok addr: %s, port: %d", addr, port);

    uint64_t now = getmillisecond();
    skt_tcp_cli_conn_t *conn = malloc(sizeof(skt_tcp_cli_conn_t));
    conn->fd = tcp_conn_fd;
    conn->addr = addr;  // TODO: 注意是否是野指针
    conn->port = port;
    conn->tcp_cli = cli;
    conn->last_r_tm = now;
    conn->last_w_tm = now;
    conn->r_keepalive = cli->conf->r_keepalive;
    conn->w_keepalive = cli->conf->w_keepalive;
    conn->r_buf_size = cli->conf->r_buf_size;
    conn->status = SKT_TCP_CONN_ST_READY;
    conn->sess_id = 0;
    conn->waiting_buf_q = NULL;
    HASH_ADD_INT(cli->conn_ht, fd, conn);

    // 开始tcp事件循环
    conn->r_watcher = (struct ev_io *)malloc(sizeof(struct ev_io));
    conn->r_watcher->data = cli;
    ev_io_init(conn->r_watcher, conn_read_cb, tcp_conn_fd, EV_READ);
    ev_io_start(cli->loop, conn->r_watcher);

    conn->w_watcher = (struct ev_io *)malloc(sizeof(struct ev_io));
    conn->w_watcher->data = cli;
    ev_io_init(conn->w_watcher, conn_write_cb, tcp_conn_fd, EV_WRITE);
    ev_io_start(cli->loop, conn->w_watcher);
    return conn;
}

skt_tcp_cli_t *skt_tcp_client_init(skt_tcp_cli_conf_t *conf, struct ev_loop *loop) {
    skt_tcp_cli_t *cli = malloc(sizeof(skt_tcp_cli_t));
    cli->conn_ht = NULL;
    cli->loop = loop;
    cli->conf = conf;
    return cli;
}

void skt_tcp_client_free(skt_tcp_cli_t *cli) {
    if (NULL == cli) {
        return;
    }

    if (NULL != cli->conn_ht) {
        skt_tcp_cli_conn_t *conn, *tmp;
        HASH_ITER(hh, cli->conn_ht, conn, tmp) {
            LOG_D("skt_tcp_client_free fd: %d", conn->fd);
            skt_tcp_client_close_conn(cli, conn->fd);
            conn = NULL;
        }
    }

    FREE_IF(cli);
    LOG_D("skt_tcp_client_free ok");
}
