#include "skt_kcp_server.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>

#ifndef NI_MAX_HOST_LEN
#define NI_MAX_HOST_LEN 1025
#endif
#ifndef NI_MAX_SERV_LEN
#define NI_MAX_SERV_LEN 32
#endif

static char *gen_key(uint32_t sess_id, struct sockaddr_in *sock_addr) {
    in_port_t port = sock_addr->sin_port;
    in_addr_t ip = sock_addr->sin_addr.s_addr;
    int key_len = 50;
    char *key = malloc(key_len);
    memset(key, 0, key_len);
    snprintf(key, key_len, "%u:%u:%u", ip, port, sess_id);
    // LOG_D("gen conn key:%s", key);

    return key;
}

static skt_kcp_conn_t *get_conn_by_key(skt_kcp_serv_t *serv, char *key) {
    skt_kcp_conn_t *conn = NULL;
    HASH_FIND_STR(serv->conn_ht, key, conn);

    return conn;
}

skt_kcp_conn_t *skt_kcp_server_get_conn(skt_kcp_serv_t *serv, uint32_t sess_id, struct sockaddr_in *kcp_cli_addr) {
    char *key = gen_key(sess_id, kcp_cli_addr);
    skt_kcp_conn_t *conn = get_conn_by_key(serv, key);
    FREE_IF(key);
    return conn;
}

static int add_conn(char *key, skt_kcp_conn_t *conn) {
    if (NULL == conn) {
        return SKT_ERROR;
    }

    if (NULL == get_conn_by_key(conn->serv, key)) {
        int l = strlen(key) + 1;
        conn->htkey = malloc(l);  // TODO: free it
        memset(conn->htkey, 0, l);
        memcpy(conn->htkey, key, l);
        HASH_ADD_KEYPTR(hh, conn->serv->conn_ht, conn->htkey, l - 1, conn);
    }

    int cnt = HASH_COUNT(conn->serv->conn_ht);
    return SKT_OK;
}

static int del_conn(skt_kcp_conn_t *conn) {
    if (NULL == conn) {
        return SKT_ERROR;
    }
    HASH_DEL(conn->serv->conn_ht, conn);
    return SKT_OK;
}

static int init_network(skt_kcp_serv_t *serv) {
    // 设置服务端
    serv->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (-1 == serv->fd) {
        LOG_E("start kcp server socket error");
        return SKT_ERROR;
    }
    //设置立即释放端口并可以再次使用
    setreuseaddr(serv->fd);
    //设置为非阻塞
    setnonblock(serv->fd);

    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    if (NULL == serv->conf->addr) {
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        servaddr.sin_addr.s_addr = inet_addr(serv->conf->addr);
    }
    servaddr.sin_port = htons(serv->conf->port);

    if (-1 == bind(serv->fd, (struct sockaddr *)&servaddr, sizeof(servaddr))) {
        LOG_E("bind error when start kcp server");
        close(serv->fd);
        return SKT_ERROR;
    }

    LOG_I("udp listening %s %u", serv->conf->addr, serv->conf->port);

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
        char s[2] = {0};
        s[0] = cmd;
        raw_buf = s;
        raw_len = 1;
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

static void close_conn(skt_kcp_serv_t *serv, uint32_t sess_id, struct sockaddr_in *kcp_cli_addr, int close_cmd_flg) {
    skt_kcp_conn_t *conn = skt_kcp_server_get_conn(serv, sess_id, kcp_cli_addr);
    if (NULL == conn) {
        return;
    }

    if (!close_cmd_flg && SKT_KCP_CONN_ST_OFF != conn->status) {
        kcp_send_raw(conn, NULL, 0, SKT_KCP_CMD_CLOSE);
    }

    LOG_D("close_conn sess_id:%u", conn->sess_id);
    conn->status = SKT_KCP_CONN_ST_OFF;
    if (conn->serv->conn_ht) {
        del_conn(conn);
    }

    if (conn->htkey) {
        FREE_IF(conn->htkey);
    }

    if (conn->kcp) {
        ikcp_release(conn->kcp);
        conn->kcp = NULL;
    }

    conn->sess_id = 0;  // TODO: for test

    FREE_IF(conn);
}

void skt_kcp_server_close_conn(skt_kcp_serv_t *serv, uint32_t sess_id, struct sockaddr_in *kcp_cli_addr) {
    skt_kcp_conn_t *conn = skt_kcp_server_get_conn(serv, sess_id, kcp_cli_addr);
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
    skt_kcp_serv_t *serv = (skt_kcp_serv_t *)(watcher->data);
    uint64_t now = getmillisecond();
    skt_kcp_conn_t *conn, *tmp;
    HASH_ITER(hh, serv->conn_ht, conn, tmp) {
        if (SKT_KCP_CONN_ST_READY == conn->status) {
            // 连接管理
            if ((now - conn->estab_tm) >= serv->conf->estab_timeout * 1000l) {
                // 超时
                LOG_D("estab_timeout sess_id:%u", conn->sess_id);
                close_conn(serv, conn->sess_id, &conn->cliaddr, 0);
            }
        } else {
            if (SKT_KCP_CONN_ST_CAN_OFF == conn->status) {
                close_conn(serv, conn->sess_id, &conn->cliaddr, 0);
            } else {
                if ((now - conn->last_r_tm) >= serv->conf->r_keepalive * 1000l) {
                    // 超时
                    LOG_D("conn_timeout_cb sess_id:%u", conn->sess_id);
                    serv->conn_timeout_cb(conn);
                    close_conn(serv, conn->sess_id, &conn->cliaddr, 0);
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
    if (conn->serv->encrypt_cb) {
        out_buf = conn->serv->encrypt_cb(buf, len, &out_len);
    }
    if (out_len > conn->serv->conf->mtu) {
        LOG_E("kcp serv output encrypt len > mtu:%d", conn->serv->conf->mtu);
    }

    int rt = sendto(conn->serv->fd, out_buf, out_len, 0, (struct sockaddr *)&conn->cliaddr, sizeof(conn->cliaddr));
    if (-1 == rt) {
        LOG_E("output sendto error fd:%d", conn->serv->fd);
        if (conn->serv->encrypt_cb) {
            FREE_IF(out_buf);
        }
        return -1;
    }
    conn->last_w_tm = getmillisecond();

    if (conn->serv->encrypt_cb) {
        FREE_IF(out_buf);
    }

    return 0;
}

static ikcpcb *create_kcp(uint32_t sess_id, skt_kcp_conn_t *conn) {
    ikcpcb *kcp = ikcp_create(sess_id, conn);
    kcp->output = kcp_output;
    skt_kcp_serv_conf_t *conf = conn->serv->conf;
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
    skt_kcp_serv_t *serv = (skt_kcp_serv_t *)(watcher->data);
    // 更新所有kcp update
    skt_kcp_conn_t *conn, *tmp;
    HASH_ITER(hh, serv->conn_ht, conn, tmp) { ikcp_update(conn->kcp, clock()); }
}

int skt_kcp_server_send(skt_kcp_serv_t *serv, uint32_t sess_id, char *buf, int len, struct sockaddr_in *kcp_cli_addr) {
    skt_kcp_conn_t *conn = skt_kcp_server_get_conn(serv, sess_id, kcp_cli_addr);
    if (NULL == conn) {
        LOG_E("skt_kcp_server_send conn error");
        return -1;
    }
    if (SKT_KCP_CONN_ST_ON != conn->status) {
        LOG_E("skt_kcp_server_send conn status not on sess_id:%u status:%d", conn->sess_id, conn->status);
        return -1;
    }

    return kcp_send_raw(conn, buf, len, SKT_KCP_CMD_DATA);
}

static skt_kcp_conn_t *new_conn(skt_kcp_serv_t *serv, uint32_t sess_id, char *key) {
    skt_kcp_conn_t *conn = malloc(sizeof(skt_kcp_conn_t));
    conn->sess_id = sess_id;

    conn->serv = serv;
    conn->kcp = create_kcp(conn->sess_id, conn);
    uint64_t now = getmillisecond();
    conn->last_r_tm = now;
    conn->last_w_tm = now;
    conn->estab_tm = now;
    conn->status = SKT_KCP_CONN_ST_READY;  // TODO:
    conn->tcp_fd = 0;
    conn->htkey = NULL;

    add_conn(key, conn);

    LOG_D("skt_kcp_server_new_conn sess_id:%u", conn->sess_id);
    return conn;
}

static int parse_recv_data(skt_kcp_conn_t *conn, char *buf, int len) {
    skt_kcp_serv_t *serv = conn->serv;

    if (len < 1) {
        LOG_E("parse_recv_data error len:%d", len);
        return SKT_ERROR;
    }

    char cmd = *buf;
    if (SKT_KCP_CMD_CONN == cmd) {
        if (SKT_KCP_CONN_ST_READY != conn->status) {
            LOG_D("parse_recv_data conn not ready sess_id:%u", conn->sess_id);
            close_conn(serv, conn->sess_id, &conn->cliaddr, 0);
            return SKT_ERROR;
        }

        kcp_send_raw(conn, NULL, 0, SKT_KCP_CMD_CONN_ACK);
        conn->status = SKT_KCP_CONN_ST_ON;
        conn->serv->new_conn_cb(conn);
        LOG_D("cmd conn sess_id:%u", conn->sess_id);
        return SKT_OK;
    } else if (SKT_KCP_CMD_CLOSE == cmd) {
        conn->status = SKT_KCP_CONN_ST_OFF;
        close_conn(serv, conn->sess_id, &conn->cliaddr, 1);
        return SKT_ERROR;  // 为了阻断执行
    } else if (SKT_KCP_CMD_PING == cmd) {
        if (SKT_KCP_CONN_ST_ON != conn->status) {
            LOG_D("parse_recv_data conn not on sess_id:%u", conn->sess_id);
            close_conn(serv, conn->sess_id, &conn->cliaddr, 0);
            return SKT_ERROR;
        }
        // TODO:
        return SKT_OK;
    } else if (SKT_KCP_CMD_DATA == cmd) {
        if (SKT_KCP_CONN_ST_ON != conn->status) {
            LOG_D("parse_recv_data conn not on sess_id:%u", conn->sess_id);
            close_conn(serv, conn->sess_id, &conn->cliaddr, 0);
            return SKT_ERROR;
        }
        LOG_D("cmd conn_data sess_id:%u", conn->sess_id);
        char *p = buf + 1;
        return serv->kcp_recv_cb(conn, p, len - 1);
    }

    LOG_W("parse_recv_data error cmd:%c", cmd);
    return SKT_ERROR;
}

// 读回调
static void read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    if (EV_ERROR & revents) {
        LOG_E("read_cb got invalid event");
        return;
    }
    skt_kcp_serv_t *serv = (skt_kcp_serv_t *)(watcher->data);

    char *raw_buf = malloc(serv->conf->r_buf_size);  // TODO: free it
    // memset(raw_buf, 0, serv->conf->r_buf_size);
    struct sockaddr_in cliaddr;
    socklen_t cliaddr_len = sizeof(cliaddr);
    int32_t bytes = recvfrom(serv->fd, raw_buf, serv->conf->r_buf_size, 0, (struct sockaddr *)&cliaddr, &cliaddr_len);
    if (-1 == bytes) {
        LOG_E("read_cb recvfrom errno: %d %s", errno, strerror(errno));
        FREE_IF(raw_buf);
        return;
    }

    // 解密
    char *out_buf = raw_buf;
    int out_len = bytes;
    if (serv->decrypt_cb) {
        out_buf = serv->decrypt_cb(raw_buf, bytes, &out_len);
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
    char *key = gen_key(sess_id, &cliaddr);
    skt_kcp_conn_t *conn = get_conn_by_key(serv, key);
    if (NULL == conn) {
        conn = new_conn(serv, sess_id, key);
        conn->cliaddr = cliaddr;
    }
    FREE_IF(key);

    ikcp_input(conn->kcp, (char *)out_buf, out_len);
    ikcp_update(conn->kcp, clock());  // TODO: 可以性能优化
    FREE_IF(out_buf);

    char *kcp_recv_buf = malloc(serv->conf->kcp_buf_size);
    memset(kcp_recv_buf, 0, serv->conf->kcp_buf_size);  // TODO: 优化
    int kcp_recv_len = 0;
    while ((kcp_recv_len = skt_kcp_recv(conn, kcp_recv_buf, serv->conf->kcp_buf_size)) > 0) {
        // 触发上层的收数据操作
        conn->last_r_tm = getmillisecond();
        if (parse_recv_data(conn, kcp_recv_buf, kcp_recv_len) != SKT_OK) {
            break;
        }
    }
    FREE_IF(kcp_recv_buf);
    return;
}

skt_kcp_serv_t *skt_kcp_server_init(skt_kcp_serv_conf_t *conf, struct ev_loop *loop, void *data) {
    skt_kcp_serv_t *serv = malloc(sizeof(skt_kcp_serv_t));  // TODO: free it
    serv->conf = conf;
    serv->data = data;
    serv->loop = loop;
    serv->conn_ht = NULL;

    if (init_network(serv) != SKT_OK) {
        FREE_IF(serv);
        return NULL;
    }

    // 设置读事件循环
    serv->r_watcher = malloc(sizeof(struct ev_io));  // TODO: free it
    serv->r_watcher->data = serv;
    ev_io_init(serv->r_watcher, read_cb, serv->fd, EV_READ);
    ev_io_start(serv->loop, serv->r_watcher);

    // 设置kcp定时循环
    serv->kcp_update_watcher = malloc(sizeof(ev_timer));  // TODO: free it
    double kcp_interval = conf->interval / 1000.0;
    serv->kcp_update_watcher->data = serv;
    ev_init(serv->kcp_update_watcher, kcp_update_cb);
    ev_timer_set(serv->kcp_update_watcher, kcp_interval, kcp_interval);
    ev_timer_start(serv->loop, serv->kcp_update_watcher);

    // 设置超时定时循环
    serv->timeout_watcher = malloc(sizeof(ev_timer));  // TODO: free it
    serv->timeout_watcher->data = serv;
    ev_init(serv->timeout_watcher, conn_timeout_cb);
    ev_timer_set(serv->timeout_watcher, serv->conf->timeout_interval, serv->conf->timeout_interval);
    ev_timer_start(serv->loop, serv->timeout_watcher);

    return serv;
}

void skt_kcp_server_free(skt_kcp_serv_t *serv) {
    ev_io_stop(serv->loop, serv->r_watcher);
    FREE_IF(serv->r_watcher);

    ev_timer_stop(serv->loop, serv->timeout_watcher);
    FREE_IF(serv->timeout_watcher);

    ev_timer_stop(serv->loop, serv->kcp_update_watcher);
    FREE_IF(serv->kcp_update_watcher);

    // serv->conf->free_cb(evkcp);

    skt_kcp_conn_t *conn, *tmp;
    HASH_ITER(hh, serv->conn_ht, conn, tmp) {
        close_conn(serv, conn->sess_id, &conn->cliaddr, 0);
        conn = NULL;
    }
    serv->conn_ht = NULL;
    if (serv->fd) {
        close(serv->fd);
    }

    FREE_IF(serv);
    return;
}