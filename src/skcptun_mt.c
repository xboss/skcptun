#include <ev.h>
#include <netinet/ip.h>
#include <unistd.h>

#include "skcp.h"
#include "skt_config.h"
#include "skt_tuntap.h"
#include "skt_utils.h"

/* -------------------------------------------------------------------------- */
/*                                   common                                   */
/* -------------------------------------------------------------------------- */
#define SKT_CMD_PUSH 'P'
#define SKT_CMD_PING 'I'
#define SKT_CMD_PONG 'O'
#define SKT_CMD_ACCEPT 'A'
#define SKT_CMD_CLOSE 'C'

typedef struct {
    char *buf;
    int buf_len;
} skt_q_msg_t;

static struct ev_loop *g_loop = NULL;
static struct ev_loop *g_skcp_loop = NULL;

static int g_tun_fd = -1;
static skt_config_t *g_conf = NULL;

static skcp_t *g_skcp = NULL;
// static int g_skcp_mode;

static uint32_t g_cid = 0;
// static skt_queue_t *g_skcp_input_queue = NULL;
static skcp_queue_t *g_tun_in_box = NULL;
static skcp_queue_t *g_tun_out_box = NULL;
static uint64_t ping_tm = 0;

static void sig_cb(struct ev_loop *loop, ev_signal *w, int revents) {
    LOG_I("sig_cb signal:%d", w->signum);
    if (w->signum == SIGPIPE) {
        return;
    }

    ev_break(loop, EVBREAK_ALL);
    LOG_I("sig_cb loop break all event ok");
}

static void finish() {
    if (g_loop) {
        ev_break(g_loop, EVBREAK_ALL);
    }

    if (g_conf) {
        skt_free_conf(g_conf);
        g_conf = NULL;
    }

    if (g_tun_fd >= 0) {
        close(g_tun_fd);
        g_tun_fd = -1;
    }
}

static int init_vpn() {
    char dev_name[32] = {0};
    int utunfd = skt_tuntap_open(dev_name, 32);

    if (utunfd == -1) {
        LOG_E("open tuntap error");
        return -1;
    }

    // 设置为非阻塞
    setnonblock(utunfd);

    skt_tuntap_setup(dev_name, g_conf->tun_ip, g_conf->tun_mask);

    return utunfd;
}

/* -------------------------------------------------------------------------- */
/*                                  callbacks                                 */
/* -------------------------------------------------------------------------- */

static void on_skcp_server_created_conn(skcp_t *skcp, uint32_t cid) {
    LOG_I("on_skcp_server_created_conn cid: %u", cid);
    g_cid = cid;
}

static void on_skcp_server_recv(skcp_t *skcp, uint32_t cid, char *buf, int len) {
    char cmd = *buf;
    // LOG_I("cmd: %c", cmd);
    if (cmd == SKT_CMD_PING) {
        // ping
        uint64_t now = getmillisecond();
        LOG_I("cid: %u ping interval: %llu", cid, now - ping_tm);

        char *raw = (char *)calloc(1, len);
        memcpy(raw, buf, len);
        *raw = SKT_CMD_PONG;
        skcp_send(g_skcp, g_cid, raw, len);
        FREE_IF(raw);

        ping_tm = now;
    } else if (cmd == SKT_CMD_PUSH) {
        // push
        if (skt_tuntap_write(g_tun_fd, buf + 1, len - 1) < 0) {
            LOG_E("on_skcp_server_recv_data skt_tuntap_write error");
        }
    } else {
        // error cmd
        LOG_E("on_skcp_server_recv_data error cmd %x", cmd);
    }
}
static void on_skcp_server_close(skcp_t *skcp, uint32_t cid, u_char type) {
    LOG_I("on_skcp_server_close cid: %u type: %x", cid, type);
    g_cid = 0;
}

static int on_skcp_server_auth(skcp_t *skcp, char *ticket, int len) { return 0; }

static void on_skcp_client_created_conn(skcp_t *skcp, uint32_t cid) {
    LOG_I("on_skcp_recv_cid cid: %u", cid);
    g_cid = cid;
}
static void on_skcp_client_recv(skcp_t *skcp, uint32_t cid, char *buf, int len) {
    char cmd = *buf;
    if (cmd == SKT_CMD_PONG) {
        // pong
        uint64_t now = getmillisecond();
        char s[32] = {0};
        memcpy(s, buf + 1, len);
        uint64_t ptm = atoll(s);
        // LOG_I("tid: %lu rtt: %llu", (unsigned long)pthread_self(), now - ptm);
        LOG_I("cid: %u rtt: %llu", cid, now - ptm);
    } else if (cmd == SKT_CMD_PUSH) {
        // push
        if (skt_tuntap_write(g_tun_fd, buf + 1, len - 1) < 0) {
            LOG_E("on_skcp_client_recv_data skt_tuntap_write error");
        }

        // skt_q_msg_t *msg = (skt_q_msg_t *)calloc(1, sizeof(skt_q_msg_t));
        // msg->buf = (char *)calloc(1, len - 1);
        // memcpy(msg->buf, buf + 1, len - 1);
        // msg->buf_len = len - 1;
        // if (skt_push_queue(g_tun_input_queue, msg) != 0) {
        //     LOG_E("on_skcp_client_recv_data skt_push_queue error");
        //     return;
        // }
        // LOG_I("g_tun_input_queue push data size: %d", g_tun_input_queue->size);
    } else {
        // error cmd
        LOG_E("on_skcp_client_recv_data error cmd %x", cmd);
    }
}
static void on_skcp_client_close(skcp_t *skcp, uint32_t cid, u_char type) {
    LOG_I("on_skcp_client_close cid: %u type: %x", cid, type);
    g_cid = 0;
}

static void on_beat(struct ev_loop *loop, struct ev_timer *watcher, int revents) {
    if (EV_ERROR & revents) {
        LOG_E("on_beat got invalid event");
        return;
    }

    // LOG_I("on_beat tid: %lu", (unsigned long)pthread_self());
    // if (g_skcp->in_box->size > 0 || g_skcp->out_box->size > 0 || g_tun_in_box->size > 0 || g_tun_out_box->size ||
    //     g_skcp->wait_snd > 100) {
    //     LOG_I("on_beat cid: %u wait_snd: %d k_in: %d k_out: %d t_in: %d, t_out: %d", g_cid, g_skcp->wait_snd,
    //           g_skcp->in_box->size, g_skcp->out_box->size, g_tun_in_box->size, g_tun_out_box->size);
    // }

    if (g_skcp->conf->mode == SKCP_IO_MODE_CLIENT) {
        // only client mode
        if (g_cid <= 0) {
            if (skcp_req_cid(g_skcp, g_conf->skcp_cli_conf_list[0]->ticket, 32) < 0) {
                LOG_E("skcp_req_cid error");
            }
            LOG_I("skcp_req_cid ok");
            return;
        }

        // ping
        char raw[32] = {0};
        uint64_t now = getmillisecond();
        snprintf(raw, 32, "%c%llu", SKT_CMD_PING, now);
        // LOG_I("ping raw: %s", raw);
        int raw_len = strlen(raw);
        skcp_send(g_skcp, g_cid, raw, raw_len);
    }
}

#define SKT_TUN_RD_BUF_LEN 1500
static void on_tun_read(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    if (EV_ERROR & revents) {
        LOG_E("on_tun_read got invalid event");
        return;
    }

    // LOG_I("stat on_tun_read");
    if (g_cid == 0) {
        return;
    }

    char buf[SKT_TUN_RD_BUF_LEN];
    int len = skt_tuntap_read(g_tun_fd, buf, SKT_TUN_RD_BUF_LEN);
    if (len <= 0) {
        LOG_E("skt_tuntap_read error tun_fd: %d", g_tun_fd);
        return;
    }

    struct ip *ip = (struct ip *)buf;
    char src_ip[20] = {0};
    char dest_ip[20] = {0};
    inet_ntop(AF_INET, &(ip->ip_src.s_addr), src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &(ip->ip_dst.s_addr), dest_ip, sizeof(dest_ip));
    if (strcmp(src_ip, "0.0.0.0") == 0) {
        LOG_I("on_tun_read src_ip: %s dest_ip: %s", src_ip, dest_ip);
        return;
    }
    // LOG_I("on_tun_read ok src_ip: %s dest_ip: %s", src_ip, dest_ip);

    size_t raw_len = len + 1;
    // char *raw = (char *)calloc(1, raw_len);
    char raw[SKT_TUN_RD_BUF_LEN + 1] = {0};
    raw[0] = SKT_CMD_PUSH;
    memcpy(raw + 1, buf, len);
    skcp_send(g_skcp, g_cid, raw, raw_len);
    // FREE_IF(raw);
}

// void dispatch_skcp_msg() {
//     while (g_skcp->out_box->size > 0) {
//         skcp_msg_t *msg = (skcp_msg_t *)skcp_pop_queue(g_skcp->out_box);
//         if (!msg) {
//             LOG_E("notify_from_skcp msg is null");
//             continue;
//         }
//         if (msg->type == SKCP_MSG_T_RECV) {
//             // recive skcp msg
//             if (g_skcp_mode == SKCP_MODE_SERV) {
//                 // server mode
//                 on_skcp_server_recv_data(msg->cid, msg->buf, msg->buf_len);
//             } else {
//                 // client mode
//                 on_skcp_client_recv_data(msg->cid, msg->buf, msg->buf_len);
//             }
//         } else if (msg->type == SKCP_MSG_T_ACCEPT) {
//             on_skcp_server_accept(msg->cid);
//         } else if (msg->type == SKCP_MSG_T_RECV_CID) {
//             on_skcp_client_recv_cid(msg->cid);
//         } else if (msg->type == SKCP_MSG_T_CLOSE_CONN) {
//             if (g_skcp_mode == SKCP_MODE_SERV) {
//                 // server mode
//                 on_skcp_server_close(msg->cid);
//             } else {
//                 // client mode
//                 on_skcp_client_close(msg->cid);
//             }
//             // TODO: } else if (msg->type == SKCP_MSG_T_CK_TICKET) {
//             //     on_skcp_server_check_ticket(msg->buf, msg->buf_len);
//         } else {
//             LOG_E("dispatch_skcp_msg error msg type");
//         }
//     }
// }

/* -------------------------------------------------------------------------- */
/*                                    main                                    */
/* -------------------------------------------------------------------------- */

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("param error\n");
        return -1;
    }

    const char *conf_file = argv[1];
    LOG_I("load config file:%s", conf_file);
    // read config file
    g_conf = skt_init_conf(conf_file);
    if (!g_conf) {
        return -1;
    }

    // init libev
#if (defined(__linux__) || defined(__linux))
    g_loop = ev_loop_new(EVBACKEND_EPOLL);
#elif defined(__APPLE__)
    g_loop = ev_loop_new(EVBACKEND_KQUEUE);
#else
    g_loop = ev_default_loop(0);
#endif

    skcp_conf_t *skcp_conf = NULL;
    if (g_conf->skcp_serv_conf_list_size > 0) {
        // g_skcp_mode = SKCP_IO_MODE_SERVER;
        skcp_conf = g_conf->skcp_serv_conf_list[0];
        skcp_conf->mode = SKCP_IO_MODE_SERVER;
        g_skcp = skcp_init(skcp_conf, g_loop, on_skcp_server_created_conn, on_skcp_server_recv, on_skcp_server_close,
                           on_skcp_server_auth, NULL);
    }

    if (g_conf->skcp_cli_conf_list_size > 0) {
        // g_skcp_mode = SKCP_IO_MODE_CLIENT;
        skcp_conf = g_conf->skcp_cli_conf_list[0];
        skcp_conf->mode = SKCP_IO_MODE_CLIENT;
        g_skcp = skcp_init(skcp_conf, g_loop, on_skcp_client_created_conn, on_skcp_client_recv, on_skcp_client_close,
                           NULL, NULL);
    }

    g_tun_in_box = skcp_init_queue(-1);
    g_tun_out_box = skcp_init_queue(-1);

    if (g_conf->tun_ip > 0 && g_conf->tun_mask) {
        // init tuntap
        g_tun_fd = init_vpn();
        if (g_tun_fd < 0) {
            finish();
            return -1;
        }

        // 设置tun读事件循环
        struct ev_io r_watcher;
        ev_io_init(&r_watcher, on_tun_read, g_tun_fd, EV_READ);
        ev_io_start(g_loop, &r_watcher);
    }

    // 定时
    struct ev_timer bt_watcher;
    ev_init(&bt_watcher, on_beat);
    ev_timer_set(&bt_watcher, 1, 1);
    ev_timer_start(g_loop, &bt_watcher);

    ev_signal sig_pipe_watcher;
    ev_signal_init(&sig_pipe_watcher, sig_cb, SIGPIPE);
    ev_signal_start(g_loop, &sig_pipe_watcher);

    ev_signal sig_int_watcher;
    ev_signal_init(&sig_int_watcher, sig_cb, SIGINT);
    ev_signal_start(g_loop, &sig_int_watcher);

    ev_signal sig_stop_watcher;
    ev_signal_init(&sig_stop_watcher, sig_cb, SIGSTOP);
    ev_signal_start(g_loop, &sig_stop_watcher);

    // sleep(1);

    ev_run(g_loop, 0);
    finish();
    LOG_I("bye");
    return 0;
}
