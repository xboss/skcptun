#include "skt_switcher.h"

#include "skt_utils.h"

typedef struct {
    skt_channel_t *chans_ht;
    skt_channel_t *best_chan;
} skt_switcher_t;

static skt_switcher_t *g_ctx;

void skt_switcher_init() {
    g_ctx = (skt_switcher_t *)calloc(1, sizeof(skt_switcher_t));
    g_ctx->chans_ht = NULL;
    g_ctx->best_chan = NULL;
}

void skt_switcher_add(skcp_t *skcp) {
    skt_channel_t *chan = NULL;
    HASH_FIND_INT(g_ctx->chans_ht, &skcp->fd, chan);
    if (!chan) {
        chan = (skt_channel_t *)calloc(1, sizeof(skt_channel_t));
        chan->skcp = skcp;
        chan->fd = skcp->fd;
        chan->cid = 0;
        chan->min_rtt = 999999999;
        chan->max_rtt = 0;
        chan->avg_rtt = 0;
        chan->pkt_snd = 0;
        chan->pkt_recv = 0;
        chan->rtt_idx = 0;
        chan->up_time = getmillisecond();
        HASH_ADD_INT(g_ctx->chans_ht, fd, chan);
        if (!g_ctx->best_chan) g_ctx->best_chan = chan;
    }
}

void skt_switcher_update(int fd, int type, uint32_t cid, size_t rtt) {
    skt_channel_t *chan = NULL;
    HASH_FIND_INT(g_ctx->chans_ht, &fd, chan);
    if (!chan) {
        LOG_E("skt_switcher_update can not find channel by fd: %d", fd);
        return;
    }

    if (type == SKT_SW_UP_T_CID) {
        chan->cid = cid;
    }

    if (type == SKT_SW_UP_T_SND) {
        chan->pkt_snd++;
    }

    if (type == SKT_SW_UP_T_RTT) {
        chan->up_time = getmillisecond();
        chan->rtt[chan->rtt_idx] = rtt;
        chan->rtt_idx++;
        chan->rtt_idx = chan->rtt_idx % SKT_SW_RTT_MAX_CNT;

        size_t sum_rtt = 0, i = 0, rtt_cnt = 0;
        for (; i < SKT_SW_RTT_MAX_CNT; i++) {
            if (chan->rtt[i] == 0) {
                continue;
            }
            sum_rtt += chan->rtt[i];
            if (chan->max_rtt < chan->rtt[i]) chan->max_rtt = chan->rtt[i];
            if (chan->min_rtt > chan->rtt[i]) chan->min_rtt = chan->rtt[i];
            rtt_cnt++;
        }

        if (i > 0) chan->avg_rtt = sum_rtt / rtt_cnt;
        chan->pkt_recv++;

        if (chan->pkt_snd > 99999999 || chan->pkt_recv > 99999999) {
            chan->pkt_snd = 0;
            chan->pkt_recv = 0;
        }
    }

    uint64_t now = getmillisecond();
    skt_channel_t *item, *tmp;
    HASH_ITER(hh, g_ctx->chans_ht, item, tmp) {
        LOG_I("------ skt_switch fd: %d cid: %u avg_rtt: %lu pkt_snd: %lu pkt_recv: %lu", item->fd, item->cid,
              item->avg_rtt, item->pkt_snd, item->pkt_recv);
        int best_time_diff = now - g_ctx->best_chan->up_time;
        int item_time_diff = now - item->up_time;
        // skt_channel_t *oldchan = g_ctx->best_chan;
        if (item->avg_rtt < g_ctx->best_chan->avg_rtt) {
            g_ctx->best_chan = item;
            LOG_I("chg 1111111");
        }
        if (item_time_diff < best_time_diff) {
            g_ctx->best_chan = item;
            LOG_I("chg 2222222");
        }
    }
}

void skt_switcher_iter(void (*iter_fn)(skt_channel_t *chan)) {
    skt_channel_t *item, *tmp;
    HASH_ITER(hh, g_ctx->chans_ht, item, tmp) { iter_fn(item); }
}

skt_channel_t *skt_switch() {
    LOG_I("++++++ skt_switch fd: %d cid: %u avg_rtt: %lu", g_ctx->best_chan->fd, g_ctx->best_chan->cid,
          g_ctx->best_chan->avg_rtt);
    return g_ctx->best_chan;
}

void skt_switcher_free() {
    if (!g_ctx) {
        return;
    }
    if (g_ctx->chans_ht) {
        skt_channel_t *item, *tmp;
        HASH_ITER(hh, g_ctx->chans_ht, item, tmp) {
            HASH_DEL(g_ctx->chans_ht, item);
            // TODO: free skcp
            FREE_IF(item);
        }
        g_ctx->chans_ht = NULL;
    }
    g_ctx->best_chan = NULL;
    FREE_IF(g_ctx);
}

/* ---------------------------------- test ---------------------------------- */

// int main(int argc, char const *argv[]) {
//     skt_switcher_init();
//     struct ev_loop *loop = ev_default_loop(0);
//     srand((unsigned)time(NULL));

//     skcp_conf_t *conf = calloc(1, sizeof(skcp_conf_t));
//     SKCP_DEF_CONF(conf);
//     conf->addr = "127.0.0.1";

//     skcp_t *skcp = skcp_init(conf, loop, NULL, SKCP_MODE_CLI);
//     skcp->fd = 101;
//     uint32_t cid = 201;
//     int rtt = rand() % 100;
//     skt_switcher_add(skcp);
//     skt_switcher_update(skcp->fd, SKT_SW_UP_T_SND, 0, 0);
//     skt_switcher_update(skcp->fd, SKT_SW_UP_T_CID, cid, 0);
//     skt_switcher_update(skcp->fd, SKT_SW_UP_T_RTT, cid, rtt);
//     LOG_I("add fd: %d cid: %u rtt: %d", skcp->fd, cid, rtt);

//     skcp = skcp_init(conf, loop, NULL, SKCP_MODE_CLI);
//     skcp->fd = 102;
//     cid = 202;
//     rtt = rand() % 100;
//     skt_switcher_add(skcp);
//     skt_switcher_update(skcp->fd, SKT_SW_UP_T_SND, 0, 0);
//     skt_switcher_update(skcp->fd, SKT_SW_UP_T_CID, cid, 0);
//     skt_switcher_update(skcp->fd, SKT_SW_UP_T_RTT, cid, rtt);
//     LOG_I("add fd: %d cid: %u rtt: %d", skcp->fd, cid, rtt);

//     skcp = skcp_init(conf, loop, NULL, SKCP_MODE_CLI);
//     skcp->fd = 103;
//     cid = 203;
//     rtt = rand() % 100;
//     skt_switcher_add(skcp);
//     skt_switcher_update(skcp->fd, SKT_SW_UP_T_SND, 0, 0);
//     skt_switcher_update(skcp->fd, SKT_SW_UP_T_CID, cid, 0);
//     skt_switcher_update(skcp->fd, SKT_SW_UP_T_RTT, cid, rtt);
//     LOG_I("add fd: %d cid: %u rtt: %d", skcp->fd, cid, rtt);

//     skt_channel_t *chan = skt_switch();
//     assert(chan->skcp);
//     LOG_I("switch fd: %d cid: %u", chan->fd, chan->cid);

//     return 0;
// }