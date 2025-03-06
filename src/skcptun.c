#include "skcptun.h"
#include <stdio.h>

void handle_tcp(int fd, sstcp_server_t* server) {
    /* TODO: */
}
skcptun_t* skt_init(skt_config_t* conf) {
    skcptun_t* skt = (skcptun_t*)calloc(1, sizeof(skcptun_t));
    if (skt == NULL) {
        perror("calloc");
        return NULL;
    }
    skt->conf = conf;
    skt->tcp_server = sstcp_create_server(conf->listen_ip, conf->listen_port, handle_tcp, skt);
    if (skt->tcp_server == NULL) {
        free(skt);
        return NULL;
    }

    /* TODO: */
    return NULL;
}

int skt_start(skcptun_t* skt) {
    /* TODO: */
    return _OK;
}

void skt_stop(skcptun_t* skt) {
    /* TODO: */
    return;
}

void skt_free(skcptun_t* skt) {
    /* TODO: */
    return;
}
