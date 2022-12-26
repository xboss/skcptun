
#include <arpa/inet.h>
#include <ev.h>

#include "skt_tcp.h"
#include "skt_utils.h"

static void tcp_accept_cb(skt_tcp_conn_t *tcp_conn) {
    LOG_D("tcp serv accept_conn_cb fd:%d", tcp_conn->fd);

    return;
}
static void tcp_close_cb(skt_tcp_conn_t *tcp_conn) {
    LOG_D("tcp serv tcp_close_cb fd:%d", tcp_conn->fd);
    return;
}

static void tcp_recv_cb(skt_tcp_conn_t *tcp_conn, const char *buf, int len) {
    LOG_D("tcp serv tcp_recv_cb fd:%d len:%d", tcp_conn->fd, len);
    skt_tcp_send(tcp_conn, (char *)buf, len);

    return;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Invalid parameter.\nUsage:\n    %s host port\n", argv[0]);
        return -1;
    }

#if (defined(__linux__) || defined(__linux))
    struct ev_loop *loop = ev_loop_new(EVBACKEND_EPOLL);
#elif defined(__APPLE__)
    struct ev_loop *loop = ev_loop_new(EVBACKEND_KQUEUE);
#else
    struct ev_loop *loop = ev_default_loop(0);
#endif

    skt_tcp_conf_t *tcp_conf = malloc(sizeof(skt_tcp_conf_t));
    tcp_conf->serv_addr = argv[1];
    tcp_conf->serv_port = atoi(argv[2]);
    tcp_conf->backlog = 1024;
    tcp_conf->r_buf_size = 900;
    tcp_conf->r_keepalive = 600;
    tcp_conf->w_keepalive = 600;
    tcp_conf->recv_timeout = 10l;  // 1000l;
    tcp_conf->send_timeout = 10l;  // 1000l;

    tcp_conf->accept_cb = tcp_accept_cb;
    tcp_conf->close_cb = tcp_close_cb;
    tcp_conf->recv_cb = tcp_recv_cb;
    tcp_conf->timeout_cb = NULL;
    tcp_conf->mode = SKT_TCP_MODE_SERV;

    skt_tcp_t *tcp_serv = skt_tcp_init(tcp_conf, loop);
    if (NULL == tcp_serv) {
        LOG_E("start tcp server error addr:%s port:%u", tcp_conf->serv_addr, tcp_conf->serv_port);
        return -1;
    }

    LOG_D("client loop run");
    ev_run(loop, 0);
    LOG_D("loop end");

    skt_tcp_free(tcp_serv);

    return 0;
}