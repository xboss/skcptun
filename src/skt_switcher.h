#ifndef _SKT_SWITCHER_H
#define _SKT_SWITCHER_H

#include <stdlib.h>

#include "skcp.h"
#include "uthash.h"

#define SKT_SW_RTT_MAX_CNT 10
#define SKT_SW_UP_T_CID 0
#define SKT_SW_UP_T_SND 1
#define SKT_SW_UP_T_RTT 2

struct skt_channel_s {
    int fd;
    uint32_t cid;
    skcp_t *skcp;
    size_t rtt[SKT_SW_RTT_MAX_CNT];
    size_t rtt_idx;
    size_t max_rtt;
    size_t avg_rtt;
    size_t min_rtt;
    size_t pkt_snd;
    size_t pkt_recv;
    uint64_t up_time;
    UT_hash_handle hh;
};
typedef struct skt_channel_s skt_channel_t;

void skt_switcher_init();
void skt_switcher_add(skcp_t *skcp);
void skt_switcher_update(int fd, int type, uint32_t cid, size_t rtt);
skt_channel_t *skt_switch();
void skt_switcher_iter(void (*iter_fn)(skt_channel_t *chan));
void skt_switcher_free();

#endif