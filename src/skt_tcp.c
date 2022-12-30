#include "skt_tcp.h"

#include <errno.h>
#include <unistd.h>

#define TIMEOUT_INTERVAL 1  // 超时检查的间隔，单位：秒

struct waiting_buf_s {
    char buf[TCP_WAITIMG_BUF_SZ];
    int len;
    waiting_buf_t *next, *prev;
};

static int append_wait_buf(skt_tcp_conn_t *conn, char *buffer, int len) {
    if (len > TCP_WAITIMG_BUF_SZ) {
        LOG_E("append wait buf len error %d", len);
        return -1;
    }

    size_t wb_sz = sizeof(waiting_buf_t);
    waiting_buf_t *msg = (waiting_buf_t *)malloc(wb_sz);
    memset(msg, 0, wb_sz);
    memcpy(msg->buf, buffer, len);
    msg->len = len;
    DL_APPEND(conn->waiting_buf_q, msg);
    return len;
}

static int init_serv_network(skt_tcp_t *skt_tcp) {
    skt_tcp->listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (-1 == skt_tcp->listenfd) {
        return SKT_ERROR;
    }
    // 设置立即释放端口并可以再次使用
    setreuseaddr(skt_tcp->listenfd);
    // 设置为非阻塞
    setnonblock(skt_tcp->listenfd);

    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    if (NULL == skt_tcp->conf->serv_addr) {
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        servaddr.sin_addr.s_addr = inet_addr(skt_tcp->conf->serv_addr);
    }
    servaddr.sin_port = htons(skt_tcp->conf->serv_port);

    if (-1 == bind(skt_tcp->listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr))) {
        LOG_E("error bind");
        close(skt_tcp->listenfd);
        return SKT_ERROR;
    }

    if (-1 == listen(skt_tcp->listenfd, skt_tcp->conf->backlog)) {
        LOG_E("error listen");
        close(skt_tcp->listenfd);
        return SKT_ERROR;
    }

    return SKT_OK;
}

static int client_connect(int *fd, struct sockaddr_in servaddr, long recv_timeout, long send_timeout) {
    if (*fd <= 0) {
        *fd = socket(AF_INET, SOCK_STREAM, 0);
        if (-1 == *fd) {
            LOG_E("tcp client_connect socket error fd: %d", *fd);
            return -1;
        }
    }

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
            LOG_W("client_connect error fd:%d errno:%s ", *fd, strerror(errno));
            return -1;
        }
    }

    return 0;
}

static void read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    if (EV_ERROR & revents) {
        LOG_E("accept got invalid event");
        return;
    }
    skt_tcp_t *tcp = (skt_tcp_t *)watcher->data;
    skt_tcp_conn_t *conn = skt_tcp_get_conn(tcp, watcher->fd);
    if (conn == NULL) {
        LOG_E("read_cb tcpconn is null fd: %d", watcher->fd);
        ev_io_stop(loop, watcher);
        FREE_IF(watcher);
        return;
    }
    if (conn->status != SKT_TCP_CONN_ST_ON) {
        LOG_W("read_cb tcpconn is off fd: %d", watcher->fd);
        skt_tcp_close_conn(conn);
        conn = NULL;
        return;
    }

    char *buffer = malloc(conn->r_buf_size);
    memset(buffer, 0, conn->r_buf_size);
    int res = 0;
    int32_t bytes = read(watcher->fd, buffer, conn->r_buf_size);

    // if (bytes <= 0) {
    //     LOG_D("------ read_cb fd: %d bytes: %d status: %d  errno:%d %s", watcher->fd, bytes, conn->status, errno,
    //           strerror(errno));
    // }

    if (bytes < 0) {
        // may error
        if (EINTR != errno && EAGAIN != errno && EWOULDBLOCK != errno && ECONNRESET != errno) {
            res = 1;
            LOG_W("read_cb tcp error fd:%d, errno:%d %s", watcher->fd, errno, strerror(errno));
        }
    } else if (bytes == 0) {
        // close
        if (errno != EINPROGRESS) {
            res = 2;
            // if (errno != ECONNRESET) {
            // LOG_W("read_cb tcp close fd:%d, errno:%d %s", watcher->fd, errno, strerror(errno));
            // }
        }
    }

    if (res) {
        // 关闭事件循环并释放watcher
        // LOG_D("------ read_cb tcp close fd:%d", watcher->fd);
        FREE_IF(buffer);
        conn->status = SKT_TCP_CONN_ST_OFF;
        skt_tcp_close_conn(conn);
        conn = NULL;
        return;
    }

    if (bytes > 0) {
        conn->last_r_tm = getmillisecond();
        if (tcp->conf->recv_cb) {
            tcp->conf->recv_cb(conn, buffer, bytes);
        }
    }

    FREE_IF(buffer);
}

static void write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    if (EV_ERROR & revents) {
        LOG_E("write_cb error event fd: %d", watcher->fd);
        return;
    }

    skt_tcp_t *tcp = (skt_tcp_t *)watcher->data;

    skt_tcp_conn_t *conn = skt_tcp_get_conn(tcp, watcher->fd);
    if (conn == NULL) {
        LOG_E("write_cb tcpconn is NULL fd: %d", watcher->fd);
        ev_io_stop(loop, watcher);
        FREE_IF(watcher);
        return;
    }

    if (SKT_TCP_CONN_ST_READY == conn->status) {
        conn->status = SKT_TCP_CONN_ST_ON;
    }

    if (conn->status != SKT_TCP_CONN_ST_ON) {
        LOG_W("write_cb tcpconn is off fd: %d", watcher->fd);
        skt_tcp_close_conn(conn);
        conn = NULL;
        return;
    }

    if (conn->waiting_buf_q) {
        waiting_buf_t *wbtmp, *item;
        DL_FOREACH_SAFE(conn->waiting_buf_q, item, wbtmp) {
            ssize_t rt = write(conn->fd, item->buf, item->len);
            if (rt <= 0) {
                LOG_E("write_cb write error fd:%d rt:%zd errno:%d %s", conn->fd, rt, errno, strerror(errno));
                return;
            }
            DL_DELETE(conn->waiting_buf_q, item);
            FREE_IF(item);
        }
        conn->waiting_buf_q = NULL;
    }
    ev_io_stop(tcp->loop, conn->w_watcher);
}

static void timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents) {
    if (EV_ERROR & revents) {
        LOG_E("timeout_cb got invalid event");
        return;
    }
    skt_tcp_conn_t *conn = (skt_tcp_conn_t *)(watcher->data);

    if (SKT_TCP_CONN_ST_CAN_OFF == conn->status) {
        skt_tcp_close_conn(conn);
        return;
    }

    // 判断是否超时
    uint64_t now = getmillisecond();
    if ((now - conn->last_r_tm) >= conn->skt_tcp->conf->r_keepalive * 1000
        // || (now - conn->last_w_tm) >= conn->skt_tcp->conf->w_keepalive * 1000
    ) {
        // 超时
        if (conn->skt_tcp->conf->timeout_cb) {
            conn->skt_tcp->conf->timeout_cb(conn);
        }
        LOG_D("timeout_cb timeout close fd:%d", conn->fd);
        skt_tcp_close_conn(conn);
        conn = NULL;
        return;
    }
}

static skt_tcp_conn_t *create_conn(skt_tcp_t *tcp, int fd) {
    uint64_t now = getmillisecond();
    skt_tcp_conn_t *conn = malloc(sizeof(skt_tcp_conn_t));
    conn->fd = fd;
    conn->skt_tcp = tcp;
    conn->last_r_tm = now;
    conn->last_w_tm = now;
    conn->r_keepalive = tcp->conf->r_keepalive;
    conn->w_keepalive = tcp->conf->w_keepalive;
    conn->r_buf_size = tcp->conf->r_buf_size;
    if (SKT_TCP_MODE_SERV == tcp->conf->mode) {
        conn->status = SKT_TCP_CONN_ST_ON;
    } else {
        conn->status = SKT_TCP_CONN_ST_READY;
    }

    conn->sess_id = 0;
    conn->waiting_buf_q = NULL;
    HASH_ADD_INT(tcp->conn_ht, fd, conn);

    // 开始tcp事件循环
    conn->r_watcher = (struct ev_io *)malloc(sizeof(struct ev_io));
    conn->r_watcher->data = tcp;
    ev_io_init(conn->r_watcher, read_cb, fd, EV_READ);
    ev_io_start(tcp->loop, conn->r_watcher);

    conn->w_watcher = (struct ev_io *)malloc(sizeof(struct ev_io));
    conn->w_watcher->data = tcp;
    ev_io_init(conn->w_watcher, write_cb, fd, EV_WRITE);
    ev_io_start(tcp->loop, conn->w_watcher);

    conn->timeout_watcher = malloc(sizeof(struct ev_timer));
    ev_init(conn->timeout_watcher, timeout_cb);
    ev_timer_set(conn->timeout_watcher, TIMEOUT_INTERVAL, TIMEOUT_INTERVAL);
    conn->timeout_watcher->data = conn;
    ev_timer_start(tcp->loop, conn->timeout_watcher);

    return conn;
}

static void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    if (EV_ERROR & revents) {
        LOG_E("accept got invalid event");
        return;
    }

    struct sockaddr_in cli_addr;
    socklen_t cli_len = sizeof(cli_addr);

    // accept连接
    int cli_fd = accept(watcher->fd, (struct sockaddr *)&cli_addr, &cli_len);
    if (-1 == cli_fd) {
        return;
    }
    // 设置非阻塞
    setnonblock(cli_fd);

    skt_tcp_t *tcp = (skt_tcp_t *)(watcher->data);
    set_recv_timeout(cli_fd, tcp->conf->recv_timeout);
    set_send_timeout(cli_fd, tcp->conf->send_timeout);

    skt_tcp_conn_t *conn = create_conn(tcp, cli_fd);
    if (NULL != conn && tcp->conf->accept_cb) {
        tcp->conf->accept_cb(conn);
    }
}

/*****************************************************/

int skt_tcp_send(skt_tcp_conn_t *conn, char *buf, int len) {
    int rt = append_wait_buf(conn, buf, len);
    ev_io_start(conn->skt_tcp->loop, conn->w_watcher);
    return rt;
}

skt_tcp_conn_t *skt_tcp_get_conn(skt_tcp_t *tcp, int fd) {
    skt_tcp_conn_t *conn = NULL;
    HASH_FIND_INT(tcp->conn_ht, &fd, conn);
    return conn;
}

void skt_tcp_close_conn(skt_tcp_conn_t *conn) {
    if (NULL == conn) {
        return;
    }

    if (conn->skt_tcp->conf->close_cb) {
        conn->skt_tcp->conf->close_cb(conn);
    }

    if (conn->skt_tcp->conn_ht) {
        HASH_DEL(conn->skt_tcp->conn_ht, conn);
    }

    conn->status = SKT_TCP_CONN_ST_OFF;
    if (conn->fd) {
        close(conn->fd);
        conn->fd = 0;
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
        ev_io_stop(conn->skt_tcp->loop, conn->r_watcher);
        FREE_IF(conn->r_watcher);
    }

    if (conn->w_watcher) {
        ev_io_stop(conn->skt_tcp->loop, conn->w_watcher);
        FREE_IF(conn->w_watcher);
    }

    if (conn->timeout_watcher) {
        ev_timer_stop(conn->skt_tcp->loop, conn->timeout_watcher);
        FREE_IF(conn->timeout_watcher);
    }

    FREE_IF(conn);
}

skt_tcp_conn_t *skt_tcp_connect(skt_tcp_t *tcp, char *addr, uint16_t port) {
    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    inet_pton(AF_INET, addr, &servaddr.sin_addr);
    servaddr.sin_port = htons(port);

    int tcp_conn_fd = 0;
    int crt = client_connect(&tcp_conn_fd, servaddr, tcp->conf->recv_timeout, tcp->conf->send_timeout);
    if (crt < 0) {
        LOG_E("connect error addr: %s port: %u fd: %d", addr, port, tcp_conn_fd);
        return NULL;
    }

    LOG_D("skt_tcp_connect ok addr: %s, port: %d", addr, port);

    return create_conn(tcp, tcp_conn_fd);
}

skt_tcp_t *skt_tcp_init(skt_tcp_conf_t *conf, struct ev_loop *loop) {
    skt_tcp_t *tcp = malloc(sizeof(skt_tcp_t));
    tcp->conf = conf;
    tcp->conn_ht = NULL;
    tcp->loop = loop;

    if (SKT_TCP_MODE_SERV == tcp->conf->mode) {
        if (init_serv_network(tcp) == SKT_ERROR) {
            FREE_IF(tcp);
            return NULL;
        }

        // 设置tcp服务的accept事件循环
        tcp->accept_watcher = malloc(sizeof(struct ev_io));
        ev_io_init(tcp->accept_watcher, accept_cb, tcp->listenfd, EV_READ);
        tcp->accept_watcher->data = tcp;
        ev_io_start(tcp->loop, tcp->accept_watcher);
        LOG_I("tcp server start ok. fd: %d addr: %s, port: %u", tcp->listenfd, tcp->conf->serv_addr,
              tcp->conf->serv_port);
    }

    return tcp;
}

void skt_tcp_free(skt_tcp_t *tcp) {
    if (SKT_TCP_MODE_SERV == tcp->conf->mode) {
        if (tcp->accept_watcher) {
            ev_io_stop(tcp->loop, tcp->accept_watcher);
            FREE_IF(tcp->accept_watcher);
        }
    }

    skt_tcp_conn_t *conn, *tmp;
    HASH_ITER(hh, tcp->conn_ht, conn, tmp) {
        skt_tcp_close_conn(conn);
        conn = NULL;
    }
    tcp->conn_ht = NULL;

    if (SKT_TCP_MODE_SERV == tcp->conf->mode) {
        if (tcp->listenfd) {
            close(tcp->listenfd);
        }
    }

    FREE_IF(tcp);
    LOG_D("skt_tcp_free ok");
}
