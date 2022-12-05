#include "skt_route.h"

static skt_route_entity_t *find_t2k(skt_route_t *route, int fd) {
    skt_route_entity_t *entity = NULL;
    if (route->t2k_ht) {
        HASH_FIND_INT(route->t2k_ht, &fd, entity);
    }
    return entity;
}

static skt_route_entity_t *find_k2t(skt_route_t *route, char *htkey) {
    skt_route_entity_t *entity = NULL;
    if (route->k2t_ht && htkey) {
        HASH_FIND_STR(route->k2t_ht, htkey, entity);
    }
    return entity;
}

///////////////////////////////////////

skt_route_t *skt_route_init() {
    skt_route_t *route = malloc(sizeof(skt_route_t));
    route->k2t_ht = NULL;
    route->t2k_ht = NULL;
    return route;
}

void skt_route_free(skt_route_t *route) {
    if (!route) {
        return;
    }
    skt_route_entity_t *entity, *tmp;
    HASH_ITER(hh, route->t2k_ht, entity, tmp) { FREE_IF(entity); }
    route->t2k_ht = NULL;

    entity = tmp = NULL;
    HASH_ITER(hh, route->k2t_ht, entity, tmp) { FREE_IF(entity); }
    route->k2t_ht = NULL;
}

int skt_route_add(skt_route_t *route, skt_route_entity_t *entity) {
    if (!route || !entity) {
        return -1;
    }
    skt_route_entity_t *entity_copy = malloc(sizeof(skt_route_entity_t));
    memcpy(entity_copy, entity, sizeof(skt_route_entity_t));

    HASH_ADD_INT(route->t2k_ht, tcp_fd, entity);

    int len = strlen(entity_copy->htkey);
    len = len > SKCP_HTKEY_LEN ? SKCP_HTKEY_LEN : len;
    HASH_ADD_KEYPTR(hh, route->k2t_ht, entity_copy->htkey, len, entity_copy);
    return 0;
}

skt_route_entity_t *skt_route_switch(skt_route_t *route, skt_kcp_t **channels, int chan_cnt) {
    if (!route || !channels || chan_cnt <= 0) {
        return NULL;
    }
    skt_kcp_t *chan = channels[0];
    for (size_t i = 1; i < chan_cnt; i++) {
        if (channels[i]->stat->last_rtt < chan->stat->last_rtt) {
            chan = channels[i];
        }
    }
    skt_route_entity_t *entity = NULL;
    SKT_ROUTE_NEW_ENTITY(entity, 0, NULL, chan);
    // entity->skt_kcp = chan;

    return entity;
}

int skt_route_del(skt_route_t *route, skt_route_entity_t *entity) {
    if (!route || !entity) {
        return -1;
    }
    if (route->t2k_ht) {
        skt_route_entity_t *entity = find_t2k(route, entity->tcp_fd);
        if (entity) {
            HASH_DEL(route->t2k_ht, entity);
            FREE_IF(entity);
        }
    }
    if (route->k2t_ht) {
        skt_route_entity_t *entity = find_k2t(route, entity->htkey);
        if (entity) {
            HASH_DEL(route->k2t_ht, entity);
            FREE_IF(entity);
        }
    }

    return 0;
}

skt_route_entity_t *skt_route_t2k(skt_route_t *route, int tcp_fd) {
    if (!route || tcp_fd <= 0) {
        return NULL;
    }
    skt_route_entity_t *entity = NULL;
    if (route->t2k_ht) {
        entity = find_t2k(route, tcp_fd);
    }
    return entity;
}

skt_route_entity_t *skt_route_k2t(skt_route_t *route, char *htkey) {
    if (!route || !htkey) {
        return NULL;
    }
    skt_route_entity_t *entity = NULL;
    if (route->k2t_ht) {
        entity = find_k2t(route, htkey);
    }
    return entity;
}