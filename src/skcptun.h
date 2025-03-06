#ifndef _SKCPTUN_H
#define _SKCPTUN_H

#include "skt.h"

typedef struct {
    skt_config_t *conf;
} skcptun_t;

skcptun_t* skt_init(skt_config_t* conf);
int skt_start(skcptun_t* skt);
void skt_stop(skcptun_t* skt);
void skt_free(skcptun_t* skt);

#endif /* _SKCPTUN_H */