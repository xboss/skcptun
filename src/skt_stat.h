#ifndef _SKT_STAT_H
#define _SKT_STAT_H

#include "skt_kcp.h"

typedef struct {
    int min_rtt;
    int max_rtt;
    int avg_rtt;
    int last_rtt;
    int sum_rtt;
    uint32_t rtt_cnt;
} skt_kcp_stat_t;

typedef struct {
    struct ev_loop *loop;
    skt_kcp_t *skt_kcp;
    skt_kcp_stat_t *kcp_stat;
} skt_stat_t;

skt_stat_t *skt_stat_init(struct ev_loop *loop);
void skt_stat_free(skt_stat_t *stat);

#endif