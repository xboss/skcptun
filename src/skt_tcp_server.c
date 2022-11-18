#include "skt_tcp_server.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "skt_utils.h"

#define TIMEOUT_INTERVAL 1  // 超时检查的间隔，单位：秒

skt_tcp_serv_conn_t *skt_tcp_server_get_conn(skt_tcp_serv_t *serv, int fd) {
    skt_tcp_serv_conn_t *conn = NULL;
    HASH_FIND_INT(serv->conn_ht, &fd, conn);
    return conn;
}

static void close_conn(skt_tcp_serv_t *serv, int fd) {
    skt_tcp_serv_conn_t *conn = skt_tcp_server_get_conn(serv, fd);
    if (NULL == conn) {
        return;
    }

    conn->serv->conf->close_conn_cb(conn);

    if (conn->serv->conn_ht) {
        HASH_DEL(conn->serv->conn_ht, conn);
    }

    conn->status = SKT_TCP_CONN_ST_OFF;
    if (conn->fd) {
        close(conn->fd);
        conn->fd = 0;
    }

    ev_io_stop(conn->serv->loop, conn->r_watcher);
    FREE_IF(conn->r_watcher)
    ev_timer_stop(conn->serv->loop, conn->timeout_watcher);
    FREE_IF(conn->timeout_watcher)

    FREE_IF(conn);
}

void skt_tcp_server_close_conn(skt_tcp_serv_t *serv, int fd) {
    skt_tcp_serv_conn_t *conn = skt_tcp_server_get_conn(serv, fd);
    if (NULL == conn) {
        return;
    }
    if (SKT_TCP_CONN_ST_ON == conn->status || SKT_TCP_CONN_ST_READY == conn->status) {
        conn->status = SKT_TCP_CONN_ST_CAN_OFF;
    }
}

static void timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents) {
    if (EV_ERROR & revents) {
        LOG_E("timeout_cb got invalid event");
        return;
    }
    skt_tcp_serv_conn_t *conn = (skt_tcp_serv_conn_t *)(watcher->data);

    if (SKT_TCP_CONN_ST_CAN_OFF == conn->status) {
        close_conn(conn->serv, conn->fd);
        return;
    }

    // 判断是否超时
    uint64_t now = getmillisecond();
    if ((now - conn->last_r_tm) >= conn->serv->conf->r_keepalive * 1000 ||
        (now - conn->last_w_tm) >= conn->serv->conf->w_keepalive * 1000) {
        // 超时
        conn->serv->conf->timeout_cb(conn);
        LOG_D("timeout_cb timeout free fd:%d", conn->fd);
        close_conn(conn->serv, conn->fd);
        conn = NULL;
        return;
    }
}

static void read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    if (EV_ERROR & revents) {
        LOG_E("read got invalid event");
        return;
    }

    skt_tcp_serv_t *serv = (skt_tcp_serv_t *)(watcher->data);

    char *buffer = malloc(serv->conf->tcp_r_buf_size);
    memset(buffer, 0, serv->conf->tcp_r_buf_size);  // TODO: 为了性能可以去掉
    int res = 0;
    ssize_t bytes = read(watcher->fd, buffer, serv->conf->tcp_r_buf_size);
    if (-1 == bytes) {
        // tcp Error
        if (EINTR != errno && EAGAIN != errno && EWOULDBLOCK != errno) {
            res = 1;
            LOG_W("read_cb tcp error fd:%d, errno:%d %s", watcher->fd, errno, strerror(errno));
        } else {
            LOG_W("read_cb tcp warn fd:%d, errno:%d %s", watcher->fd, errno, strerror(errno));
        }
    } else if (0 == bytes) {
        if (errno != EINPROGRESS) {
            // tcp Close
            res = 2;
        }
    }

    skt_tcp_serv_conn_t *conn = NULL;
    HASH_FIND_INT(serv->conn_ht, &watcher->fd, conn);
    if (NULL == conn) {
        LOG_E("no conn in read_cb");
        FREE_IF(buffer);
        return;
    }

    if (0 != res) {
        //关闭事件循环并释放watcher
        FREE_IF(buffer)
        conn->status = SKT_TCP_CONN_ST_OFF;
        close_conn(conn->serv, conn->fd);
        conn = NULL;
        return;
    }

    // 业务处理
    int rt = serv->conf->recv_cb(conn, buffer, bytes);
    if (0 != rt) {
        FREE_IF(buffer)
        conn->status = SKT_TCP_CONN_ST_OFF;
        close_conn(conn->serv, conn->fd);
        conn = NULL;
        return;
    }

    conn->last_r_tm = getmillisecond();

    FREE_IF(buffer)
}

static skt_tcp_serv_conn_t *create_conn(skt_tcp_serv_t *serv, int cli_fd) {
    skt_tcp_serv_conn_t *conn = malloc(sizeof(skt_tcp_serv_conn_t));  // TODO: free it
    conn->fd = cli_fd;
    uint64_t now = getmillisecond();
    conn->last_r_tm = now;
    conn->last_w_tm = now;
    conn->serv = serv;
    conn->status = SKT_TCP_CONN_ST_ON;
    conn->sess_id = 0;

    skt_tcp_serv_conn_t *tmp = skt_tcp_server_get_conn(serv, cli_fd);
    if (NULL != tmp) {
        close_conn(conn->serv, conn->fd);
        tmp = NULL;
    }
    HASH_ADD_INT(serv->conn_ht, fd, conn);

    //加入事件循环
    conn->r_watcher = malloc(sizeof(struct ev_io));
    conn->r_watcher->data = serv;
    ev_io_init(conn->r_watcher, read_cb, cli_fd, EV_READ);
    ev_io_start(serv->loop, conn->r_watcher);

    // 设置超时定时循环
    conn->timeout_watcher = malloc(sizeof(struct ev_timer));
    ev_init(conn->timeout_watcher, timeout_cb);
    ev_timer_set(conn->timeout_watcher, TIMEOUT_INTERVAL, TIMEOUT_INTERVAL);
    conn->timeout_watcher->data = conn;
    ev_timer_start(serv->loop, conn->timeout_watcher);

    return conn;
}

static void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    struct sockaddr_in cli_addr;
    socklen_t cli_len = sizeof(cli_addr);
    if (EV_ERROR & revents) {
        LOG_E("accept got invalid event");
        return;
    }

    // accept连接
    int cli_fd = accept(watcher->fd, (struct sockaddr *)&cli_addr, &cli_len);
    if (-1 == cli_fd) {
        return;
    }
    //设置非阻塞
    setnonblock(cli_fd);

    skt_tcp_serv_t *serv = (skt_tcp_serv_t *)(watcher->data);
    set_recv_timeout(cli_fd, serv->conf->recv_timeout);
    set_send_timeout(cli_fd, serv->conf->send_timeout);

    skt_tcp_serv_conn_t *conn = create_conn(serv, cli_fd);
    if (NULL != conn) {
        serv->conf->accept_conn_cb(conn);
    }

    LOG_D("accept fd:%d", cli_fd);
}

ssize_t skt_tcp_server_send(skt_tcp_serv_t *serv, int fd, char *buf, int len) {
    skt_tcp_serv_conn_t *conn = skt_tcp_server_get_conn(serv, fd);
    if (NULL == conn) {
        LOG_E("skt_tcp_server_send conn NULL fd:%d", fd);
        return -1;
    }
    if (conn->fd <= 0) {
        LOG_E("skt_tcp_server_send conn fd error fd:%d", conn->fd);
        return -1;
    }
    assert(conn->fd);

    ssize_t write_len = write(conn->fd, buf, len);
    if (-1 == write_len) {
        LOG_E("skt_tcp_server_send error errno:%d, %s", errno, strerror(errno));
        return -1;
    }
    conn->last_w_tm = getmillisecond();
    return write_len;
}

skt_tcp_serv_t *skt_tcp_server_init(skt_tcp_serv_conf_t *conf, struct ev_loop *loop) {
    // TODO: check param
    skt_tcp_serv_t *serv = malloc(sizeof(skt_tcp_serv_t));
    serv->conn_ht = NULL;
    serv->conf = conf;
    serv->loop = loop;

    serv->listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (-1 == serv->listenfd) {
        FREE_IF(serv);
        return NULL;
    }
    //设置立即释放端口并可以再次使用
    setreuseaddr(serv->listenfd);
    //设置为非阻塞
    setnonblock(serv->listenfd);

    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    if (NULL == conf->serv_addr) {
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        servaddr.sin_addr.s_addr = inet_addr(conf->serv_addr);
    }
    servaddr.sin_port = htons(conf->serv_port);

    if (-1 == bind(serv->listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr))) {
        LOG_E("error bind");
        close(serv->listenfd);
        FREE_IF(serv);
        return NULL;
    }

    if (-1 == listen(serv->listenfd, conf->backlog)) {
        LOG_E("error listen");
        close(serv->listenfd);
        FREE_IF(serv);
        return NULL;
    }

    // 设置tcp服务的事件循环
    serv->accept_watcher = malloc(sizeof(struct ev_io));
    ev_io_init(serv->accept_watcher, accept_cb, serv->listenfd, EV_READ);
    serv->accept_watcher->data = serv;
    ev_io_start(serv->loop, serv->accept_watcher);

    LOG_I("tcp server start ok fd:%d, addr:%s, port:%u", serv->listenfd, serv->conf->serv_addr, serv->conf->serv_port);
    return serv;
}

void skt_tcp_server_free(skt_tcp_serv_t *serv) {
    if (serv->accept_watcher && ev_is_active(serv->accept_watcher)) {
        ev_io_stop(serv->loop, serv->accept_watcher);
        FREE_IF(serv->accept_watcher);
    }

    skt_tcp_serv_conn_t *conn, *tmp;
    HASH_ITER(hh, serv->conn_ht, conn, tmp) {
        conn->status = SKT_TCP_CONN_ST_OFF;
        close_conn(conn->serv, conn->fd);
        conn = NULL;
    }

    if (serv->listenfd) {
        close(serv->listenfd);
    }

    FREE_IF(serv);
    LOG_D("skt_tcp_server_free ok");
}
