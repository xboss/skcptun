#ifndef _SKT_TCP_H
#define _SKT_TCP_H

#include "skt_utils.h"

typedef enum {
    SKT_TCP_CONN_ST_ON = 1,
    SKT_TCP_CONN_ST_READY,
    SKT_TCP_CONN_ST_OFF,
    SKT_TCP_CONN_ST_CAN_OFF,
} SKT_TCP_CONN_ST;

#endif