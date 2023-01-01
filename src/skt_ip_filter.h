#ifndef _SKT_IP_FILTER_H
#define _SKT_IP_FILTER_H

#include <arpa/inet.h>
#include <bitset.h>

typedef struct {
    bitset_t *bitset;
} skt_ip_filter_t;

skt_ip_filter_t *skt_load_ip_list(const char *file);
bool skt_ip_filter_is_in(skt_ip_filter_t *filter, struct in_addr ip);
void skt_ip_filter_free(skt_ip_filter_t *filter);

#endif