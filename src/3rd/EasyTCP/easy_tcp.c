#include "easy_tcp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>

#include "utlist.h"

/* -------------------------------------------------------------------------- */
/*                               EasyTCP Common                               */
/* -------------------------------------------------------------------------- */

#define _ALLOC(v_type, v_element_size) (v_type *)calloc(1, v_element_size)

#define _FREEIF(p)    \
    do {              \
        if (p) {      \
            free(p);  \
            p = NULL; \
        }             \
    } while (0)

#define _LOG(fmt, args...)   \
    do {                     \
        printf(fmt, ##args); \
        printf("\n");        \
    } while (0)

inline static uint64_t getmillisecond() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t millisecond = (tv.tv_sec * 1000000l + tv.tv_usec) / 1000l;
    return millisecond;
}

inline static int setnonblock(int fd) {
    if (-1 == fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)) {
        _LOG("error fcntl");
        return -1;
    }
    return 0;
}

inline static int setreuseaddr(int fd) {
    int reuse = 1;
    if (-1 == setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))) {
        _LOG("error setsockopt");
        return -1;
    }
    return 0;
}

inline static void set_recv_timeout(int fd, time_t sec) {
    struct timeval timeout;
    timeout.tv_sec = sec;
    timeout.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        _LOG("set_recv_timeout error");
    }
}

inline static void set_send_timeout(int fd, time_t sec) {
    struct timeval timeout;
    timeout.tv_sec = sec;
    timeout.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        _LOG("set_recv_timeout error");
    }
}

// return: >0:success read bytes; 0:close; -1:pending; -2:error
inline static int tcp_read(int fd, char *buf, int len) {
    if (fd <= 0 || !buf || len <= 0) {
        return -2;
    }

    int rt = 0;
    ssize_t bytes = read(fd, buf, len);
    if (bytes == 0) {
        // tcp close
        rt = 0;
    } else if (bytes == -1) {
        if (EINTR == errno || EAGAIN == errno || EWOULDBLOCK == errno) {
            // pending
            rt = -1;
        }
        // error
        rt = -2;
    } else if (bytes < -1) {
        // error
        rt = -2;
    } else {
        rt = bytes;
    }

    return rt;
}

// return: >0:success write bytes; 0:close; -1:pending; -2:error
inline static int tcp_write(int fd, char *buf, int len) {
    if (fd <= 0 || !buf || len <= 0) {
        return -2;
    }

    int rt = 0;
    ssize_t bytes = write(fd, buf, len);
    if (bytes == 0) {
        // tcp close
        rt = 0;
    } else if (bytes == -1) {
        if (EINTR == errno || EAGAIN == errno || EWOULDBLOCK == errno) {
            // pending
            rt = -1;
        }
        // error
        rt = -2;
    } else if (bytes < -1) {
        // error
        rt = -2;
    } else {
        rt = bytes;
    }

    return rt;
}

/* -------------------------------------------------------------------------- */
/*                               EasyTCP Server                               */
/* -------------------------------------------------------------------------- */

/* ------------------------------- private api ------------------------------ */

inline static void add_serv_conn_ht(etcp_serv_t *serv, etcp_serv_conn_t *conn) {
    if (!conn) {
        return;
    }
    etcp_serv_conn_t *conn_tmp = NULL;
    HASH_FIND_INT(serv->conn_ht, &conn->fd, conn_tmp);
    if (!conn_tmp) {
        HASH_ADD_INT(serv->conn_ht, fd, conn);
    }
}

inline static etcp_serv_conn_t *find_serv_conn_ht(etcp_serv_t *serv, int fd) {
    if (fd <= 0) {
        return NULL;
    }
    etcp_serv_conn_t *conn = NULL;
    HASH_FIND_INT(serv->conn_ht, &fd, conn);
    return conn;
}

// no free conn
inline static void del_serv_conn_ht(etcp_serv_t *serv, int fd) {
    if (fd <= 0) {
        return;
    }
    etcp_serv_conn_t *conn = NULL;
    HASH_FIND_INT(serv->conn_ht, &fd, conn);
    if (conn) {
        HASH_DEL(serv->conn_ht, conn);
    }
}

static void serv_timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents) {
    if (EV_ERROR & revents) {
        _LOG("timeout_cb got invalid event");
        return;
    }
    etcp_serv_conn_t *conn = (etcp_serv_conn_t *)(watcher->data);
    etcp_serv_t *serv = conn->serv;

    // 判断是否超时
    uint64_t now = getmillisecond();
    if ((now - conn->last_r_tm) >= serv->conf->r_keepalive * 1000 ||
        (now - conn->last_w_tm) >= serv->conf->w_keepalive * 1000) {
        // 超时
        _LOG("timeout_cb timeout free fd:%d", conn->fd);
        etcp_server_close_conn(serv, conn->fd, 0);
        return;
    }
}

static void serv_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    if (EV_ERROR & revents) {
        _LOG("read got invalid event");
        return;
    }

    etcp_serv_conn_t *conn = (etcp_serv_conn_t *)(watcher->data);
    etcp_serv_t *serv = conn->serv;

    char *buf = _ALLOC(char, serv->conf->r_buf_size);
    int rt = tcp_read(watcher->fd, buf, serv->conf->r_buf_size);

    if (rt == 0) {
        // tcp close
        // _LOG("read_cb tcp close fd:%d, errno:%s", watcher->fd, strerror(errno));
        _FREEIF(buf);
        etcp_server_close_conn(serv, watcher->fd, 0);
        return;
    } else if (rt == -1) {
        // pending
        _LOG("read_cb tcp pending fd:%d, errno:%s", watcher->fd, strerror(errno));
        _FREEIF(buf);
        return;
    } else if (rt == -2) {
        // error
        _LOG("read_cb tcp error fd:%d, errno:%s", watcher->fd, strerror(errno));
        _FREEIF(buf);
        etcp_server_close_conn(serv, watcher->fd, 0);
        return;
    }

    // 业务处理
    serv->conf->on_recv(watcher->fd, buf, rt);
    conn->last_r_tm = getmillisecond();

    _FREEIF(buf);
}

static etcp_serv_conn_t *init_serv_conn(etcp_serv_t *serv, int cli_fd) {
    etcp_serv_conn_t *conn = _ALLOC(etcp_serv_conn_t, sizeof(etcp_serv_conn_t));
    conn->fd = cli_fd;
    uint64_t now = getmillisecond();
    conn->last_r_tm = now;
    conn->last_w_tm = now;
    conn->serv = serv;
    add_serv_conn_ht(serv, conn);

    // 加入事件循环
    conn->r_watcher = malloc(sizeof(struct ev_io));
    conn->r_watcher->data = conn;
    ev_io_init(conn->r_watcher, serv_read_cb, cli_fd, EV_READ);
    ev_io_start(serv->loop, conn->r_watcher);

    // 设置超时定时循环
    conn->timeout_watcher = malloc(sizeof(struct ev_timer));
    ev_init(conn->timeout_watcher, serv_timeout_cb);
    ev_timer_set(conn->timeout_watcher, serv->conf->timeout_interval, serv->conf->timeout_interval);
    conn->timeout_watcher->data = conn;
    ev_timer_start(serv->loop, conn->timeout_watcher);

    return conn;
}

static void serv_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    if (EV_ERROR & revents) {
        _LOG("accept got invalid event");
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

    etcp_serv_t *serv = (etcp_serv_t *)(watcher->data);
    set_recv_timeout(cli_fd, serv->conf->recv_timeout);
    set_send_timeout(cli_fd, serv->conf->send_timeout);

    etcp_serv_conn_t *conn = init_serv_conn(serv, cli_fd);
    if (!conn) {
        return;
    }

    int rt = serv->conf->on_accept(conn->fd);
    if (rt != 0) {
        etcp_server_close_conn(serv, conn->fd, 0);
        return;
    }

    // _LOG("accept fd:%d", conn->fd);
}

/* ------------------------------- public api ------------------------------- */
etcp_serv_t *etcp_init_server(etcp_serv_conf_t *conf, struct ev_loop *loop, void *user_data) {
    etcp_serv_t *serv = _ALLOC(etcp_serv_t, sizeof(etcp_serv_t));
    serv->conf = conf;
    serv->loop = loop;
    serv->conn_ht = NULL;

    serv->serv_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (-1 == serv->serv_fd) {
        _FREEIF(serv);
        return NULL;
    }
    // 设置立即释放端口并可以再次使用
    if (setreuseaddr(serv->serv_fd) != 0) {
        _FREEIF(serv);
        return NULL;
    }

    // 设置为非阻塞
    if (setnonblock(serv->serv_fd) != 0) {
        _FREEIF(serv);
        return NULL;
    }

    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    if (NULL == conf->serv_addr) {
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        servaddr.sin_addr.s_addr = inet_addr(conf->serv_addr);
    }
    servaddr.sin_port = htons(conf->serv_port);

    if (-1 == bind(serv->serv_fd, (struct sockaddr *)&servaddr, sizeof(servaddr))) {
        _LOG("error bind");
        close(serv->serv_fd);
        _FREEIF(serv);
        return NULL;
    }

    if (-1 == listen(serv->serv_fd, conf->backlog)) {
        _LOG("error listen");
        close(serv->serv_fd);
        _FREEIF(serv);
        return NULL;
    }

    // 设置tcp服务的事件循环
    serv->accept_watcher = _ALLOC(struct ev_io, sizeof(struct ev_io));
    ev_io_init(serv->accept_watcher, serv_accept_cb, serv->serv_fd, EV_READ);
    serv->accept_watcher->data = serv;
    ev_io_start(serv->loop, serv->accept_watcher);

    _LOG("tcp server start ok fd:%d, addr:%s, port:%u", serv->serv_fd, serv->conf->serv_addr, serv->conf->serv_port);
    return serv;
}

void etcp_free_server(etcp_serv_t *serv) {
    if (!serv) {
        return;
    }

    if (serv->accept_watcher) {
        ev_io_stop(serv->loop, serv->accept_watcher);
        _FREEIF(serv->accept_watcher);
    }

    if (serv->conn_ht) {
        etcp_serv_conn_t *conn, *tmp;
        HASH_ITER(hh, serv->conn_ht, conn, tmp) {
            HASH_DEL(serv->conn_ht, conn);
            etcp_server_close_conn(serv, conn->fd, 0);
        }
    }

    if (serv->serv_fd) {
        close(serv->serv_fd);
        serv->serv_fd = 0;
    }
    serv->conn_ht = NULL;
    _FREEIF(serv);
}

int etcp_server_send(etcp_serv_t *serv, int fd, char *buf, size_t len) {
    if (!buf || len <= 0) {
        return 0;
    }

    etcp_serv_conn_t *conn = etcp_server_get_conn(serv, fd);
    if (!conn) {
        return 0;
    }

    ssize_t rt = tcp_write(fd, buf, len);
    if (rt == 0) {
        // tcp close
        _LOG("etcp_server_send tcp close fd:%d, errno:%s", fd, strerror(errno));
        etcp_server_close_conn(serv, fd, 0);
        return 0;
    } else if (rt == -1) {
        // pending
        _LOG("etcp_server_send tcp pending fd:%d, errno:%s", fd, strerror(errno));
        return 0;
    } else if (rt == -2) {
        // error
        _LOG("etcp_server_send tcp error fd:%d, errno:%s", fd, strerror(errno));
        etcp_server_close_conn(serv, fd, 0);
        return 0;
    }
    conn->last_w_tm = getmillisecond();
    return rt;
}

void etcp_server_close_conn(etcp_serv_t *serv, int fd, int silent) {
    etcp_serv_conn_t *conn = find_serv_conn_ht(serv, fd);
    if (!conn) {
        _LOG("etcp_server_close_conn conn is NULL");
        return;
    }
    // _LOG("etcp_server_close_conn fd:%d", conn->fd);

    if (!silent) {
        serv->conf->on_close(fd);
    }

    if (conn->r_watcher) {
        ev_io_stop(serv->loop, conn->r_watcher);
        _FREEIF(conn->r_watcher);
    }

    if (conn->timeout_watcher) {
        ev_timer_stop(serv->loop, conn->timeout_watcher);
        _FREEIF(conn->timeout_watcher);
    }

    if (serv->conn_ht) {
        del_serv_conn_ht(serv, fd);
    }

    if (conn->fd) {
        close(conn->fd);
        conn->fd = 0;
    }

    conn->user_data = NULL;
    conn->serv = NULL;

    _FREEIF(conn);
}

etcp_serv_conn_t *etcp_server_get_conn(etcp_serv_t *serv, int fd) {
    etcp_serv_conn_t *conn = find_serv_conn_ht(serv, fd);
    return conn;
}

/* -------------------------------------------------------------------------- */
/*                               EasyTCP Client                               */
/* -------------------------------------------------------------------------- */

struct etcp_send_buf_s {
    int len;
    etcp_send_buf_t *next, *prev;
    char buf[];
};

/* ------------------------------- private api ------------------------------ */

inline static void add_send_buf(etcp_cli_conn_t *conn, char *buf, int len) {
    if (!conn || !buf || len <= 0) {
        return;
    }

    etcp_send_buf_t *sb = _ALLOC(etcp_send_buf_t, sizeof(etcp_send_buf_t) + len);
    // sb->buf = _ALLOC(char, len);
    memcpy(sb->buf, buf, len);
    sb->len = len;
    DL_APPEND(conn->send_buf, sb);
}

inline static void add_cli_conn_ht(etcp_cli_t *cli, etcp_cli_conn_t *conn) {
    if (!conn) {
        return;
    }
    etcp_cli_conn_t *conn_tmp = NULL;
    HASH_FIND_INT(cli->conn_ht, &conn->fd, conn_tmp);
    if (!conn_tmp) {
        HASH_ADD_INT(cli->conn_ht, fd, conn);
    }
}

inline static etcp_cli_conn_t *find_cli_conn_ht(etcp_cli_t *cli, int fd) {
    if (fd <= 0) {
        return NULL;
    }
    etcp_cli_conn_t *conn = NULL;
    HASH_FIND_INT(cli->conn_ht, &fd, conn);
    return conn;
}

// no free conn
inline static void del_cli_conn_ht(etcp_cli_t *cli, int fd) {
    if (fd <= 0) {
        return;
    }
    etcp_cli_conn_t *conn = NULL;
    HASH_FIND_INT(cli->conn_ht, &fd, conn);
    if (conn) {
        HASH_DEL(cli->conn_ht, conn);
    }
}

// return: >0:success fd
static int client_connect(struct sockaddr_in servaddr, long recv_timeout, long send_timeout) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (-1 == fd) {
        _LOG("client_connect socket error fd: %d", fd);
        // error
        return -1;
    }

    // 设置非阻塞, 设置立即释放端口并可以再次使用
    setnonblock(fd);
    setreuseaddr(fd);
    // 设置超时
    set_recv_timeout(fd, recv_timeout);
    set_send_timeout(fd, send_timeout);

    int rt = connect(fd, (struct sockaddr *)&servaddr, sizeof(servaddr));
    if (0 != rt) {
        if (errno != EINPROGRESS) {
            // 连接失败
            _LOG("client_connect error fd:%d errno:%s ", fd, strerror(errno));
            // error
            return -1;
        } else {
            // TODO:  连接没有立即成功，需进行二次判断
            // _LOG("client_connect waiting fd:%d errno:%s ", fd, strerror(errno));
            // pending
        }
    }

    // _LOG("client_connect ok fd: %d", fd);

    return fd;
}

static int cli_send(etcp_cli_conn_t *conn, char *buf, size_t len) {
    if (!conn || !buf || len <= 0) {
        return 0;
    }
    int fd = conn->fd;
    etcp_cli_t *cli = conn->cli;

    ssize_t rt = tcp_write(fd, buf, len);
    if (rt == 0) {
        // tcp close
        _LOG("cli_send tcp close fd:%d, errno:%s", fd, strerror(errno));
        etcp_client_close_conn(cli, fd, 0);
        return 0;
    } else if (rt == -1) {
        // pending
        _LOG("cli_send tcp pending fd:%d, errno:%s", fd, strerror(errno));
        return 0;
    } else if (rt == -2) {
        // error
        _LOG("cli_send tcp error fd:%d, errno:%s", fd, strerror(errno));
        etcp_client_close_conn(cli, fd, 0);
        return 0;
    }
    conn->last_w_tm = getmillisecond();
    return rt;
}

static void cli_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    if (EV_ERROR & revents) {
        _LOG("conn_read_cb error event fd: %d", watcher->fd);
        return;
    }

    etcp_cli_conn_t *conn = (etcp_cli_conn_t *)watcher->data;
    etcp_cli_t *cli = conn->cli;

    char *buf = _ALLOC(char, cli->conf->r_buf_size);
    int rt = tcp_read(watcher->fd, buf, cli->conf->r_buf_size);

    if (rt == 0) {
        // tcp close
        _LOG("read_cb tcp close fd:%d, errno:%s", watcher->fd, strerror(errno));
        _FREEIF(buf);
        etcp_client_close_conn(cli, watcher->fd, 0);
        return;
    } else if (rt == -1) {
        // pending
        _LOG("read_cb tcp pending fd:%d, errno:%s", watcher->fd, strerror(errno));
        _FREEIF(buf);
        return;
    } else if (rt == -2) {
        // error
        _LOG("read_cb tcp error fd:%d, errno:%s", watcher->fd, strerror(errno));
        _FREEIF(buf);
        etcp_client_close_conn(cli, watcher->fd, 0);
        return;
    }

    cli->conf->on_recv(conn->fd, buf, rt);
    _FREEIF(buf);
    conn->last_r_tm = getmillisecond();
}

static void cli_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    if (EV_ERROR & revents) {
        _LOG("write_cb error event fd: %d", watcher->fd);
        return;
    }

    etcp_cli_conn_t *conn = (etcp_cli_conn_t *)watcher->data;
    etcp_cli_t *cli = conn->cli;

    if (conn->send_buf) {
        etcp_send_buf_t *sbtmp, *item;
        DL_FOREACH_SAFE(conn->send_buf, item, sbtmp) {
            int rt = cli_send(conn, item->buf, item->len);
            if (rt <= 0) {
                _LOG("write_cb write error fd:%d rt:%d errno:%d %s", conn->fd, rt, errno, strerror(errno));
                return;
            }
            DL_DELETE(conn->send_buf, item);
            // _FREEIF(item->buf);
            _FREEIF(item);
        }
        conn->send_buf = NULL;
    }
    ev_io_stop(cli->loop, conn->w_watcher);
}

/* ------------------------------- public api ------------------------------- */

etcp_cli_t *etcp_init_client(etcp_cli_conf_t *conf, struct ev_loop *loop, void *user_data) {
    etcp_cli_t *cli = _ALLOC(etcp_cli_t, sizeof(etcp_cli_t));
    cli->conn_ht = NULL;
    cli->loop = loop;
    cli->conf = conf;
    cli->user_data = user_data;
    return cli;
}

void etcp_free_client(etcp_cli_t *cli) {
    if (!cli) {
        return;
    }

    if (cli->conn_ht) {
        etcp_cli_conn_t *conn, *tmp;
        HASH_ITER(hh, cli->conn_ht, conn, tmp) {
            HASH_DEL(cli->conn_ht, conn);
            etcp_client_close_conn(cli, conn->fd, 0);
        }
    }
    cli->conf = NULL;
    cli->user_data = NULL;

    _FREEIF(cli);
}

int etcp_client_send(etcp_cli_t *cli, int fd, char *buf, size_t len) {
    etcp_cli_conn_t *conn = etcp_client_get_conn(cli, fd);
    if (!conn) {
        return 0;
    }
    add_send_buf(conn, buf, len);
    ev_io_start(cli->loop, conn->w_watcher);
    return len;
}

int etcp_client_create_conn(etcp_cli_t *cli, char *addr, uint16_t port, void *user_data) {
    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    inet_pton(AF_INET, addr, &servaddr.sin_addr);
    servaddr.sin_port = htons(port);

    int fd = client_connect(servaddr, cli->conf->recv_timeout, cli->conf->send_timeout);
    if (fd <= 0) {
        _LOG("connect error addr: %s port: %u fd: %d", addr, port, fd);
        return -1;
    }

    // _LOG("etcp_client_create_conn connect ok addr: %s, port: %d", addr, port);

    uint64_t now = getmillisecond();
    etcp_cli_conn_t *conn = _ALLOC(etcp_cli_conn_t, sizeof(etcp_cli_conn_t));
    conn->send_buf = NULL;
    conn->fd = fd;
    conn->addr = servaddr;
    conn->cli = cli;
    conn->last_r_tm = now;
    conn->last_w_tm = now;
    add_cli_conn_ht(cli, conn);

    // 开始tcp事件循环
    conn->r_watcher = (struct ev_io *)malloc(sizeof(struct ev_io));
    conn->r_watcher->data = conn;
    ev_io_init(conn->r_watcher, cli_read_cb, fd, EV_READ);
    ev_io_start(cli->loop, conn->r_watcher);

    conn->w_watcher = (struct ev_io *)malloc(sizeof(struct ev_io));
    conn->w_watcher->data = conn;
    ev_io_init(conn->w_watcher, cli_write_cb, fd, EV_WRITE);
    ev_io_start(cli->loop, conn->w_watcher);

    return conn->fd;
}

void etcp_client_close_conn(etcp_cli_t *cli, int fd, int silent) {
    etcp_cli_conn_t *conn = find_cli_conn_ht(cli, fd);
    if (!conn) {
        _LOG("etcp_client_close_conn conn is NULL");
        return;
    }
    // _LOG("etcp_client_close_conn fd:%d", conn->fd);

    if (!silent) {
        cli->conf->on_close(fd);
    }

    if (conn->r_watcher) {
        ev_io_stop(cli->loop, conn->r_watcher);
        _FREEIF(conn->r_watcher);
    }

    if (conn->w_watcher) {
        ev_io_stop(cli->loop, conn->w_watcher);
        _FREEIF(conn->w_watcher);
    }

    if (conn->send_buf) {
        etcp_send_buf_t *sbtmp, *item;
        DL_FOREACH_SAFE(conn->send_buf, item, sbtmp) {
            DL_DELETE(conn->send_buf, item);
            // _FREEIF(item->buf);
            _FREEIF(item);
        }
        conn->send_buf = NULL;
    }

    if (cli->conn_ht) {
        del_cli_conn_ht(cli, fd);
    }

    if (conn->fd) {
        close(conn->fd);
        conn->fd = 0;
    }

    conn->user_data = NULL;
    conn->cli = NULL;

    _FREEIF(conn);
}

etcp_cli_conn_t *etcp_client_get_conn(etcp_cli_t *cli, int fd) {
    etcp_cli_conn_t *conn = find_cli_conn_ht(cli, fd);
    return conn;
}
