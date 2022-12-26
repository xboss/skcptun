#include "skt_client_tt.h"

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

    skt_kcp_conf_t kcp_conf;
    skcp_conf_t skcp_conf;
    skcp_conf.interval = 10;
    skcp_conf.mtu = 1024;  // TODO: 和IP包大小保持一致
    skcp_conf.rcvwnd = 128;
    skcp_conf.sndwnd = 128;
    skcp_conf.nodelay = 1;
    skcp_conf.resend = 2;
    skcp_conf.nc = 1;
    skcp_conf.r_keepalive = 15;  // 600;
    skcp_conf.w_keepalive = 15;  // 600;
    skcp_conf.estab_timeout = 100;

    kcp_conf.skcp_conf = &skcp_conf;
    kcp_conf.addr = argv[1];  //"127.0.0.1";
    kcp_conf.port = atoi(argv[2]);
    kcp_conf.key = "12345678123456781234567812345678";
    kcp_conf.r_buf_size = skcp_conf.mtu;
    kcp_conf.kcp_buf_size = 5000;  // 2048;
    kcp_conf.timeout_interval = 1;

    skt_cli_tt_conf_t conf;
    conf.kcp_conf = &kcp_conf;
    int rt = skt_client_tt_init(&conf, loop);
    if (rt != 0) {
        LOG_E("skt_client_tt_init error");
        return 1;
    }

    LOG_D("loop run");
    ev_run(loop, 0);
    LOG_D("loop end");

    skt_client_tt_free();

    return 0;
}