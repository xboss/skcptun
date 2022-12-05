#ifndef _SKT_ROUTE_H
#define _SKT_ROUTE_H

#include "skt_kcp.h"
#include "skt_tcp.h"

#define SKT_ROUTE_NEW_ENTITY(ventity, vtcp_fd, vhtkey, vskt_kcp) \
    do {                                                         \
        (ventity) = malloc(sizeof(skt_route_entity_t));          \
        (ventity)->tcp_fd = vtcp_fd;                             \
        (ventity)->htkey = vhtkey;                               \
        (ventity)->skt_kcp = vskt_kcp;                           \
    } while (0)

// #define SKT_ROUTE_ENTITY_GET(ventity, vfield) (ventity) == NULL ? NULL : (ventity)->vfield

typedef struct {
    int tcp_fd;
    char *htkey;
    // skcp_conn_t *skcp_conn;
    // skt_tcp_conn_t *tcp_conn;
    skt_kcp_t *skt_kcp;
    // int status;
    UT_hash_handle hh;
} skt_route_entity_t;

// typedef struct {
//     int tcp_fd;
//     skt_route_entity_t *entity;
//     UT_hash_handle hh;
// } skt_route_t2k_t;

// typedef struct {
//     char *htkey;
//     skt_route_entity_t *entity;
//     UT_hash_handle hh;
// } skt_route_k2t_t;

typedef struct {
    // skt_route_t2k_t *t2k_ht;
    // skt_route_k2t_t *k2t_ht;
    skt_route_entity_t *t2k_ht;
    skt_route_entity_t *k2t_ht;
} skt_route_t;

/****** API ******/

skt_route_t *skt_route_init();
void skt_route_free(skt_route_t *route);
int skt_route_add(skt_route_t *route, skt_route_entity_t *entity);
skt_route_entity_t *skt_route_switch(skt_route_t *route, skt_kcp_t **channels, int chan_cnt);
int skt_route_del(skt_route_t *route, skt_route_entity_t *entity);
skt_route_entity_t *skt_route_t2k(skt_route_t *route, int tcp_fd);
skt_route_entity_t *skt_route_k2t(skt_route_t *route, char *htkey);

#endif