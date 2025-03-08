#ifndef _SKT_CTRL_SERVER_H
#define _SKT_CTRL_SERVER_H

#include "skt.h"

typedef struct {
    int fd;
    void *user_data;
} skt_ctrl_server_t;

skt_ctrl_server_t* skt_ctrl_server_init(struct ev_loop* loop, skt_config_t* conf, void *user_data);
int skt_ctrl_server_start(skt_ctrl_server_t* server);
void skt_ctrl_server_stop(skt_ctrl_server_t* server);
void skt_ctrl_server_free(skt_ctrl_server_t* server);

#endif /* _SKT_CTRL_SERVER_H */