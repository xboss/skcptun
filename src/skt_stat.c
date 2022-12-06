#include "skt_stat.h"

skt_stat_t *skt_stat_init(struct ev_loop *loop) {
    skt_stat_t *stat = malloc(sizeof(skt_stat_t));
    stat->loop = loop;
    stat->skt_kcp;
}

void skt_stat_free(skt_stat_t *stat) {}