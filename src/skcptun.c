// #define _DEBUG

#if (defined(__linux__) || defined(__linux)) && defined(_DEBUG)
#include <mcheck.h>
#endif

#include "skt_client.h"
#include "skt_config.h"
#include "skt_server.h"
#include "skt_utils.h"

static void sig_cb(struct ev_loop *loop, ev_signal *w, int revents) {
    LOG_I("sig_cb signal:%d", w->signum);
    if (w->signum == SIGPIPE) {
        return;
    }

    ev_break(loop, EVBREAK_ALL);
}

/**********  server config **********/

static skt_serv_t *start_server(struct ev_loop *loop, const char *conf_file) {
    if (NULL == loop) {
        LOG_E("loop create failed");
        return NULL;
    }

    skt_serv_conf_t *conf = skt_init_server_conf(conf_file);
    if (NULL == conf) {
        return NULL;
    }

    skt_serv_t *serv = skt_server_init(conf, loop);
    if (NULL == serv) {
        skt_free_server_conf(conf);
        return NULL;
    }

    LOG_D("server loop run");
    ev_run(loop, 0);
    LOG_D("loop end");

    skt_server_free();
    skt_free_server_conf(conf);
    return serv;
}

/**********  client config **********/

static skt_cli_t *start_client(struct ev_loop *loop, const char *conf_file) {
    if (NULL == loop) {
        LOG_E("loop create failed");
        return NULL;
    }

    skt_cli_conf_t *conf = skt_init_client_conf(conf_file);
    if (NULL == conf) {
        return NULL;
    }
    skt_cli_t *cli = skt_client_init(conf, loop);
    if (NULL == cli) {
        skt_free_client_conf(conf);
        return NULL;
    }

    LOG_D("client loop run");
    ev_run(loop, 0);
    LOG_D("loop end");

    skt_client_free();
    skt_free_client_conf(conf);
    return cli;
}

///////////////////////////////

int main(int argc, char *argv[]) {
#if (defined(__linux__) || defined(__linux)) && defined(_DEBUG)
    setenv("MALLOC_TRACE", "/tmp/mtrace_skcptun.log", 1);
    mtrace();
#endif

    if (argc < 3) {
        LOG_E("param error!\n kcptn param \n s:server\n c:client configfile");
        return -1;
    }

    const char *conf_file = argv[2];
    LOG_D("mode:%s config file:%s", argv[1], conf_file);

    struct ev_loop *loop = ev_default_loop(0);  // ev_loop_new(EVBACKEND_KQUEUE);  // ev_loop_new(EVBACKEND_EPOLL);//
    ev_signal sig_pipe_watcher;
    ev_signal_init(&sig_pipe_watcher, sig_cb, SIGPIPE);
    ev_signal_start(loop, &sig_pipe_watcher);

    ev_signal sig_int_watcher;
    ev_signal_init(&sig_int_watcher, sig_cb, SIGINT);
    ev_signal_start(loop, &sig_int_watcher);

    ev_signal sig_stop_watcher;
    ev_signal_init(&sig_stop_watcher, sig_cb, SIGSTOP);
    ev_signal_start(loop, &sig_stop_watcher);

    if (strcmp(argv[1], "s") == 0) {
        skt_serv_t *serv = start_server(loop, conf_file);  // TODO:
        if (NULL == serv) {
            return -1;
        }

    } else if (strcmp(argv[1], "c") == 0) {
        skt_cli_t *cli = start_client(loop, conf_file);  // TODO:
        if (NULL == cli) {
            return -1;
        }
    } else {
        LOG_E("param error!\n kcptn param \n s:server\n c:client");
        return -1;
    }

#if (defined(__linux__) || defined(__linux)) && defined(_DEBUG)
    muntrace();
#endif

    return 0;
}
