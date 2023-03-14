#include "skt_client.h"
#include "skt_config.h"
#include "skt_proxy_client.h"
#include "skt_proxy_server.h"
#include "skt_server.h"
#include "skt_utils.h"

static void sig_cb(struct ev_loop *loop, ev_signal *w, int revents) {
    LOG_I("sig_cb signal:%d", w->signum);
    if (w->signum == SIGPIPE) {
        return;
    }

    ev_break(loop, EVBREAK_ALL);
    LOG_I("sig_cb loop break all event ok");
}

/* -------------------------------------------------------------------------- */
/*                                proxy server                                */
/* -------------------------------------------------------------------------- */

static int start_proxy_server(struct ev_loop *loop, skt_config_t *conf) {
    if (NULL == loop) {
        LOG_E("loop create failed");
        return -1;
    }

    if (skt_proxy_server_init(conf->skcp_conf, conf->etcp_cli_conf, loop, conf->tcp_target_addr,
                              conf->tcp_target_port) != 0) {
        return -1;
    }

    LOG_D("proxy server loop run");
    ev_run(loop, 0);
    LOG_D("loop end");

    skt_proxy_server_free();
    return 0;
}

/* -------------------------------------------------------------------------- */
/*                                proxy client                                */
/* -------------------------------------------------------------------------- */

static int start_proxy_client(struct ev_loop *loop, skt_config_t *conf) {
    if (NULL == loop) {
        LOG_E("loop create failed");
        return -1;
    }

    if (skt_proxy_client_init(conf->skcp_conf, conf->etcp_serv_conf, loop) != 0) {
        return -1;
    }

    LOG_D("proxy client loop run");
    ev_run(loop, 0);
    LOG_D("loop end");

    skt_proxy_client_free();
    return 0;
}

/* -------------------------------------------------------------------------- */
/*                                tunnel server                               */
/* -------------------------------------------------------------------------- */

static int start_tun_server(struct ev_loop *loop, skt_config_t *conf) {
    if (NULL == loop) {
        LOG_E("loop create failed");
        return -1;
    }

    if (skt_server_init(conf->skcp_conf, loop, conf->tun_ip, conf->tun_mask) != 0) {
        return -1;
    }

    LOG_D("tun server loop run");
    ev_run(loop, 0);
    LOG_D("loop end");

    skt_server_free();
    return 0;
}

/* -------------------------------------------------------------------------- */
/*                                tunnel client                               */
/* -------------------------------------------------------------------------- */

static int start_tun_client(struct ev_loop *loop, skt_config_t *conf) {
    if (NULL == loop) {
        LOG_E("loop create failed");
        return -1;
    }

    if (skt_client_init(conf->skcp_conf, loop, conf->tun_ip, conf->tun_mask) != 0) {
        return -1;
    }

    LOG_D("tun client loop run");
    ev_run(loop, 0);
    LOG_D("loop end");

    skt_client_free();
    return 0;
}

/* -------------------------------------------------------------------------- */
/*                                    main                                    */
/* -------------------------------------------------------------------------- */

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("param error!\n kcptun configfile\n");
        return -1;
    }

    const char *conf_file = argv[1];
    LOG_D("config file:%s", conf_file);

    // read config file
    skt_config_t *conf = skt_init_conf(conf_file);
    if (!conf) {
        return -1;
    }

#if (defined(__linux__) || defined(__linux))
    struct ev_loop *loop = ev_loop_new(EVBACKEND_EPOLL);
#elif defined(__APPLE__)
    struct ev_loop *loop = ev_loop_new(EVBACKEND_KQUEUE);
#else
    struct ev_loop *loop = ev_default_loop(0);
#endif
    ev_signal sig_pipe_watcher;
    ev_signal_init(&sig_pipe_watcher, sig_cb, SIGPIPE);
    ev_signal_start(loop, &sig_pipe_watcher);

    ev_signal sig_int_watcher;
    ev_signal_init(&sig_int_watcher, sig_cb, SIGINT);
    ev_signal_start(loop, &sig_int_watcher);

    ev_signal sig_stop_watcher;
    ev_signal_init(&sig_stop_watcher, sig_cb, SIGSTOP);
    ev_signal_start(loop, &sig_stop_watcher);

    int rt = 0;
    if (conf->mode == SKT_TUN_SERV_MODE) {
        rt = start_tun_server(loop, conf);
    }

    if (conf->mode == SKT_TUN_CLI_MODE) {
        rt = start_tun_client(loop, conf);
    }

    if (conf->mode == SKT_PROXY_SERV_MODE) {
        rt = start_proxy_server(loop, conf);
    }

    if (conf->mode == SKT_PROXY_CLI_MODE) {
        rt = start_proxy_client(loop, conf);
    }

    skt_free_conf(conf);
    LOG_I("bye");
    return rt;
}
