#include <ev.h>
#include <netinet/ip.h>
#include <unistd.h>

#include "skcp_mt.h"
#include "skt_config.h"
#include "skt_tuntap.h"
#include "skt_utils.h"

// /* -------------------------------------------------------------------------- */
// /*                                 safe queue                                 */
// /* -------------------------------------------------------------------------- */
// typedef struct skt_queue_node_s {
//     void *data;
//     struct skt_queue_node_s *next;
//     struct skt_queue_node_s *prev;
// } skt_queue_node_t;

// typedef struct {
//     skt_queue_node_t *head;
//     skt_queue_node_t *tail;
//     int size;
//     int capacity;
//     pthread_mutex_t lock;
//     pthread_cond_t not_empty_cond;
//     pthread_cond_t not_full_cond;
// } skt_queue_t;

// /**
//  * @param capacity <0: unlimited
//  * @return skt_queue_t*
//  */
// skt_queue_t *skt_init_queue(int capacity) {
//     skt_queue_t *q = (skt_queue_t *)calloc(1, sizeof(skt_queue_t));
//     q->head = NULL;
//     q->tail = NULL;
//     q->size = 0;
//     q->capacity = capacity;
//     // if (pthread_mutex_init(&q->lock, NULL) != 0) {
//     //     FREE_IF(q);
//     //     LOG_E("init lock error in skt_init_queue");
//     //     return NULL;
//     // }
//     if (pthread_mutex_init(&q->lock, NULL) != 0 || pthread_cond_init(&q->not_empty_cond, NULL) != 0 ||
//         pthread_cond_init(&q->not_full_cond, NULL) != 0) {
//         FREE_IF(q);
//         LOG_E("init lock or cond error in skt_init_block_queue");
//         return NULL;
//     }
//     return q;
// }
// /**
//  * @param q
//  * @return full: return 1; not full: return 0;
//  */
// int skt_is_queue_full(skt_queue_t *q) {
//     if (q->capacity < 0) {
//         return 0;
//     }

//     if (q->size >= q->capacity) {
//         return 1;
//     }
//     return 0;
// }

// /**
//  * @param q
//  * @return empty: return 1; not empty: return 0;
//  */
// int skt_is_queue_empty(skt_queue_t *q) {
//     if (q->size == 0) {
//         return 1;
//     }
//     return 0;
// }

// /**
//  * @param q
//  * @param data
//  * @return int ok:0; error:-1
//  */
// int skt_push_queue(skt_queue_t *q, void *data) {
//     // LOG_I("skt_push_queue size: %d", q->size);
//     if (skt_is_queue_full(q)) {
//         LOG_E("safe queue is full");
//         return -1;
//     }

//     pthread_mutex_lock(&q->lock);
//     skt_queue_node_t *node = (skt_queue_node_t *)calloc(1, sizeof(skt_queue_node_t));
//     node->data = data;
//     node->prev = NULL;
//     node->next = NULL;
//     if (skt_is_queue_empty(q)) {
//         q->head = node;
//         q->tail = node;
//     } else {
//         node->next = q->head;
//         q->head->prev = node;
//         q->head = node;
//     }
//     q->size++;
//     pthread_cond_signal(&q->not_empty_cond);
//     pthread_mutex_unlock(&q->lock);
//     return 0;
// }

// void *skt_pop_queue(skt_queue_t *q) {
//     // LOG_I("skt_pop_queue size: %d", q->size);
//     if (skt_is_queue_empty(q)) {
//         return NULL;
//     }

//     pthread_mutex_lock(&q->lock);
//     skt_queue_node_t *node = q->tail;
//     if (q->size == 1) {
//         // 只有一个节点
//         q->tail = NULL;
//         q->head = NULL;
//     } else {
//         // 多个节点
//         q->tail->prev->next = NULL;
//         q->tail = q->tail->prev;
//     }

//     q->size--;
//     void *data = node->data;
//     FREE_IF(node);
//     pthread_mutex_unlock(&q->lock);
//     return data;
// }

// void *skt_pop_block_queue(skt_queue_t *q) {
//     pthread_mutex_lock(&q->lock);
//     if (skt_is_queue_empty(q)) {
//         pthread_cond_wait(&q->not_empty_cond, &q->lock);
//     }
//     // LOG_I("skt_pop_block_queue size: %d", q->size);
//     skt_queue_node_t *node = q->tail;
//     if (q->size == 1) {
//         // 只有一个节点
//         q->tail = NULL;
//         q->head = NULL;
//     } else {
//         // 多个节点
//         q->tail->prev->next = NULL;
//         q->tail = q->tail->prev;
//     }

//     q->size--;
//     void *data = node->data;
//     FREE_IF(node);
//     pthread_mutex_unlock(&q->lock);
//     return data;
// }

// // void skt_free_queue(skt_queue_t *q) {
// //     if (!q) {
// //         return;
// //     }
// //     pthread_mutex_destroy(&q->lock);
// //     while (q->size > 0) {
// //     }
// //     FREE_IF(q);
// // }

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

static skcp_mt_t *g_smt = NULL;
static SKCP_MODE g_skcp_mode;

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

static void on_skcp_server_accept(uint32_t cid) {
    LOG_I("on_skcp_server_accept cid: %u", cid);
    g_cid = cid;
}

static void on_skcp_server_recv_data(uint32_t cid, char *buf, int len) {
    char cmd = *buf;
    // LOG_I("cmd: %c", cmd);
    if (cmd == SKT_CMD_PING) {
        // ping
        uint64_t now = getmillisecond();
        LOG_I("ping interval: %llu", now - ping_tm);

        char *raw = (char *)calloc(1, len);
        memcpy(raw, buf, len);
        *raw = SKT_CMD_PONG;
        skcp_mt_send(g_smt, g_cid, raw, len);
        FREE_IF(raw);

        // skt_q_msg_t *msg = (skt_q_msg_t *)calloc(1, sizeof(skt_q_msg_t));
        // msg->buf = (char *)calloc(1, len);
        // memcpy(msg->buf, buf, len);
        // *msg->buf = SKT_CMD_PONG;
        // msg->buf_len = len;
        // if (skt_push_queue(g_skcp_input_queue, msg) != 0) {
        //     LOG_E("on_skcp_server_recv_data skt_push_queue error");
        //     return;
        // }
        // // *buf = SKT_CMD_PONG;
        // // if (skcp_send(skcp, g_cid, buf, len) < 0) {
        // //     LOG_E("on_skcp_server_recv_data skcp_send error");
        // //     return;
        // // }
        ping_tm = now;
    } else if (cmd == SKT_CMD_PUSH) {
        // push
        if (skt_tuntap_write(g_tun_fd, buf + 1, len - 1) < 0) {
            LOG_E("on_skcp_server_recv_data skt_tuntap_write error");
        }

        // skt_q_msg_t *msg = (skt_q_msg_t *)calloc(1, sizeof(skt_q_msg_t));
        // msg->buf = (char *)calloc(1, len - 1);
        // memcpy(msg->buf, buf + 1, len - 1);
        // msg->buf_len = len - 1;
        // if (skt_push_queue(g_tun_input_queue, msg) != 0) {
        //     LOG_E("on_skcp_server_recv_data skt_push_queue error");
        //     return;
        // }
        // LOG_I("g_tun_input_queue push data size: %d", g_tun_input_queue->size);
    } else {
        // error cmd
        LOG_E("on_skcp_server_recv_data error cmd %x", cmd);
    }
}
static void on_skcp_server_close(uint32_t cid) {
    LOG_I("on_skcp_server_close cid: %u", cid);
    g_cid = 0;
}

static int on_skcp_server_check_ticket(char *ticket, int len) { return 0; }

static void on_skcp_client_recv_cid(uint32_t cid) {
    LOG_I("on_skcp_recv_cid cid: %u", cid);
    g_cid = cid;
}
static void on_skcp_client_recv_data(uint32_t cid, char *buf, int len) {
    char cmd = *buf;
    if (cmd == SKT_CMD_PONG) {
        // pong
        uint64_t now = getmillisecond();
        char s[32] = {0};
        memcpy(s, buf + 1, len);
        uint64_t ptm = atoll(s);
        LOG_I("tid: %lu rtt: %llu", (unsigned long)pthread_self(), now - ptm);
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
static void on_skcp_client_close(uint32_t cid) {
    LOG_I("on_skcp_client_close cid: %u", cid);
    g_cid = 0;
}

static void on_beat(struct ev_loop *loop, struct ev_timer *watcher, int revents) {
    if (EV_ERROR & revents) {
        LOG_E("on_beat got invalid event");
        return;
    }

    // LOG_I("on_beat tid: %lu", (unsigned long)pthread_self());
    LOG_I("on_beat k_in: %d k_out: %d t_in: %d, t_out: %d", g_smt->in_box->size, g_smt->out_box->size,
          g_tun_in_box->size, g_tun_out_box->size);

    if (g_skcp_mode == SKCP_MODE_CLI) {
        // only client mode
        if (g_cid <= 0) {
            if (skcp_mt_req_cid(g_smt, g_conf->skcp_cli_conf_list[0]->ticket, 32) < 0) {
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
        skcp_mt_send(g_smt, g_cid, raw, raw_len);
    }
}

#define SKT_TUN_RD_BUF_LEN 1500
static void on_tun_read(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    if (EV_ERROR & revents) {
        LOG_E("on_tun_read got invalid event");
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

    size_t raw_len = len + 1;
    // char *raw = (char *)calloc(1, raw_len);
    char raw[SKT_TUN_RD_BUF_LEN + 1] = {0};
    raw[0] = SKT_CMD_PUSH;
    memcpy(raw + 1, buf, len);
    skcp_mt_send(g_smt, g_cid, raw, raw_len);
    // FREE_IF(raw);

    // skt_q_msg_t *msg = (skt_q_msg_t *)calloc(1, sizeof(skt_q_msg_t));
    // msg->buf = (char *)calloc(1, len + 1);
    // *msg->buf = SKT_CMD_PUSH;
    // memcpy(msg->buf + 1, buf, len);
    // msg->buf_len = len + 1;
    // if (skt_push_queue(g_skcp_input_queue, msg) != 0) {
    //     LOG_E("on_tun_read skt_push_queue error");
    //     return;
    // }
    // LOG_I("g_skcp_input_queue push data size: %d", g_skcp_input_queue->size);
}

// static void skcp_async_cb(struct ev_loop *loop, ev_async *watcher, int revents) {
//     fprintf(stdout, "get the order, start move...\n");
// }

// void *skcp_thread_fn(void *arg) {
// #if (defined(__linux__) || defined(__linux))
//     g_skcp_loop = ev_loop_new(EVBACKEND_EPOLL);
// #elif defined(__APPLE__)
//     g_skcp_loop = ev_loop_new(EVBACKEND_KQUEUE);
// #else
//     g_skcp_loop = ev_default_loop(0);
// #endif

//     // skcp server
//     if (skcp_mode == SKCP_MODE_SERV) {
//         g_conf->skcp_serv_conf_list[0]->on_accept = on_skcp_server_accept;
//         g_conf->skcp_serv_conf_list[0]->on_check_ticket = on_skcp_server_check_ticket;
//         g_conf->skcp_serv_conf_list[0]->on_close = on_skcp_server_close;
//         g_conf->skcp_serv_conf_list[0]->on_recv_data = on_skcp_server_recv_data;

//         skcp_t *skcp_serv = skcp_init(g_conf->skcp_serv_conf_list[0], g_skcp_loop, NULL, SKCP_MODE_SERV);
//         if (!skcp_serv) {
//             LOG_E("init skcp server error");
//             return NULL;
//         }
//         LOG_I("skcp server ok %s %u", g_conf->skcp_serv_conf_list[0]->addr, g_conf->skcp_serv_conf_list[0]->port);
//         skcp = skcp_serv;
//     }

//     // skcp client
//     if (skcp_mode == SKCP_MODE_CLI) {
//         g_conf->skcp_cli_conf_list[0]->on_close = on_skcp_client_close;
//         g_conf->skcp_cli_conf_list[0]->on_recv_cid = on_skcp_client_recv_cid;
//         g_conf->skcp_cli_conf_list[0]->on_recv_data = on_skcp_client_recv_data;
//         skcp_t *skcp_cli = skcp_init(g_conf->skcp_cli_conf_list[0], g_skcp_loop, NULL, SKCP_MODE_CLI);
//         if (!skcp_cli) {
//             LOG_E("init skcp client error");
//             return NULL;
//         }
//         LOG_I("skcp client ok %s %u", g_conf->skcp_cli_conf_list[0]->addr, g_conf->skcp_cli_conf_list[0]->port);
//         skcp = skcp_cli;
//     }

//     // 定时
//     struct ev_timer bt_watcher;
//     ev_init(&bt_watcher, on_beat);
//     ev_timer_set(&bt_watcher, 1, 1);
//     ev_timer_start(g_loop, &bt_watcher);

//     // char raw[1500] = {0};  // TODO:
//     while (1) {
//         LOG_I("g_skcp_input_queue pop size: %d tid: %lu", g_skcp_input_queue->size, (unsigned long)pthread_self());
//         skt_q_msg_t *msg = (skt_q_msg_t *)skt_pop_block_queue(g_skcp_input_queue);
//         if (!msg) {
//             LOG_E("pop skcp_input_queue NULL");
//             break;
//         }
//         // assert(msg->buf_len + 1 <= 1500);
//         // raw[0] = SKT_CMD_PUSH;
//         // memcpy(raw, msg->buf + 1, msg->buf_len);

//         if (skcp_send(skcp, g_cid, msg->buf, msg->buf_len) < 0) {
//             LOG_E("skcp_thread_fn skcp_send error");
//             // TODO: 按顺序放回队列
//         }
//         // LOG_I("skcp_thread_fn skcp_send ok");
//         FREE_IF(msg->buf);
//         FREE_IF(msg);
//     }

//     return NULL;
// }

// void *tun_thread_fn(void *arg) {
//     while (1) {
//         LOG_I("g_tun_input_queue pop size: %d", g_tun_input_queue->size);
//         skt_q_msg_t *msg = (skt_q_msg_t *)skt_pop_block_queue(g_tun_input_queue);
//         if (!msg) {
//             LOG_E("pop tun_input_queue NULL");
//             break;
//         }

//         if (skt_tuntap_write(g_tun_fd, msg->buf, msg->buf_len) < 0) {
//             LOG_E("tun_thread_fn skt_tuntap_write error");
//             // TODO: 按顺序放回队列
//         }
//         // LOG_I("tun_thread_fn skt_tuntap_write ok");
//         FREE_IF(msg->buf);
//         FREE_IF(msg);
//     }

//     return NULL;
// }

void dispatch_skcp_msg() {
    while (g_smt->out_box->size > 0) {
        skcp_msg_t *msg = (skcp_msg_t *)skcp_pop_queue(g_smt->out_box);
        if (!msg) {
            LOG_E("notify_from_skcp msg is null");
            continue;
        }
        if (msg->type == SKCP_MSG_T_RECV) {
            // recive skcp msg
            if (g_skcp_mode == SKCP_MODE_SERV) {
                // server mode
                on_skcp_server_recv_data(msg->cid, msg->buf, msg->buf_len);
            } else {
                // client mode
                on_skcp_client_recv_data(msg->cid, msg->buf, msg->buf_len);
            }
        } else if (msg->type == SKCP_MSG_T_ACCEPT) {
            on_skcp_server_accept(msg->cid);
        } else if (msg->type == SKCP_MSG_T_RECV_CID) {
            on_skcp_client_recv_cid(msg->cid);
        } else if (msg->type == SKCP_MSG_T_CLOSE_CONN) {
            if (g_skcp_mode == SKCP_MODE_SERV) {
                // server mode
                on_skcp_server_close(msg->cid);
            } else {
                // client mode
                on_skcp_client_close(msg->cid);
            }
            // TODO: } else if (msg->type == SKCP_MSG_T_CK_TICKET) {
            //     on_skcp_server_check_ticket(msg->buf, msg->buf_len);
        } else {
            LOG_E("dispatch_skcp_msg error msg type");
        }
    }
}

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

    skcp_conf_t *skcp_conf = NULL;
    if (g_conf->skcp_serv_conf_list_size > 0) {
        g_skcp_mode = SKCP_MODE_SERV;
        skcp_conf = g_conf->skcp_serv_conf_list[0];
    }

    if (g_conf->skcp_cli_conf_list_size > 0) {
        g_skcp_mode = SKCP_MODE_CLI;
        skcp_conf = g_conf->skcp_cli_conf_list[0];
    }

    g_tun_in_box = skcp_init_queue(-1);
    g_tun_out_box = skcp_init_queue(-1);

    // init libev
#if (defined(__linux__) || defined(__linux))
    g_loop = ev_loop_new(EVBACKEND_EPOLL);
#elif defined(__APPLE__)
    g_loop = ev_loop_new(EVBACKEND_KQUEUE);
#else
    g_loop = ev_default_loop(0);
#endif

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

    g_smt = skcp_mt_init(skcp_conf, NULL, g_skcp_mode, dispatch_skcp_msg);

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

/* ---------------------------------- test ---------------------------------- */
// void *test_thread_fn(void *arg) {
//     while (1) {
//         // LOG_I("g_skcp_input_queue size: %d", g_skcp_input_queue->size);
//         skt_q_msg_t *msg = (skt_q_msg_t *)skt_pop_block_queue(g_skcp_input_queue);
//         if (!msg) {
//             LOG_E("pop skcp_input_queue NULL");
//             break;
//         }

//         // LOG_I("test_thread_fn ok %s %d", msg->buf, msg->buf_len);
//         FREE_IF(msg->buf);
//         FREE_IF(msg);
//         sleep(1);
//     }
//     return NULL;
// }

// int main(int argc, char *argv[]) {
//     g_skcp_input_queue = skt_init_queue(-1);

//     pthread_t tid = 0;
//     if (pthread_create(&tid, NULL, test_thread_fn, NULL)) {
//         LOG_E("start thread error");
//         finish();
//         return -1;
//     }

//     // for (size_t i = 0; i < 30; i++) {
//     while (1) {
//         char *s = "hello";
//         int l = strlen(s);
//         skt_q_msg_t *msg = (skt_q_msg_t *)calloc(1, sizeof(skt_q_msg_t));
//         msg->buf = (char *)calloc(1, l + 1);
//         memcpy(msg->buf, s, l + 1);
//         msg->buf_len = l + 1;
//         if (skt_push_queue(g_skcp_input_queue, msg) != 0) {
//             LOG_E("on_tun_read skt_push_queue error");
//             return -1;
//         }
//         sleep(3);
//     }

//     // for (size_t i = 0; i < 30; i++) {
//     //     // LOG_I("g_skcp_input_queue size: %d", g_skcp_input_queue->size);
//     //     skt_q_msg_t *msg = (skt_q_msg_t *)skt_pop_block_queue(g_skcp_input_queue);
//     //     // skt_q_msg_t *msg = (skt_q_msg_t *)skt_pop_queue(g_skcp_input_queue);
//     //     if (!msg) {
//     //         LOG_E("pop skcp_input_queue NULL");
//     //         break;
//     //     }

//     //     // LOG_I("test_thread_fn ok %s %d", msg->buf, msg->buf_len);
//     //     FREE_IF(msg->buf);
//     //     FREE_IF(msg);
//     // }

//     return 0;
// }