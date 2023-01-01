#include "skt_ip_filter.h"

#include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
#include <assert.h>

#include "skt_utils.h"

typedef struct {
    char ip_from[20];
    char ip_to[20];
} ip_mask_tuple_t;

// line format: 192.208.1.1 255.255.255.0
static int read_line(FILE *fp, ip_mask_tuple_t *tuple) {
    // char ip[20] = {0};
    // char mask[20] = {0};

    int i = 0, field = 0, ip_from_idx = 0, ip_to_idx = 0, ch;
    while ((ch = fgetc(fp)) != '\n') {
        if (!(ch >= '0' && ch <= '9') && ch != '.' && ch != ' ' && ch != '\r') {
            // invalid char
            return -1;
        }

        if (ch == ' ') {
            field++;
            i++;
            continue;
        }

        if (0 == field) {
            // ip field
            if (ip_from_idx >= sizeof(tuple->ip_from) - 1) {
                // invalid ip len
                return -2;
            }
            tuple->ip_from[ip_from_idx++] = ch;
        } else if (1 == field) {
            // mask field
            if (ip_to_idx >= sizeof(tuple->ip_to) - 1) {
                // invalid mask len
                return -3;
            }
            tuple->ip_to[ip_to_idx++] = ch;
        } else {
            // more than two fields error
            return -4;
        }
    }
    return 0;
}

bool skt_ip_filter_is_in(skt_ip_filter_t *filter, struct in_addr ip) {
    return bitset_get(filter->bitset, ntohl(ip.s_addr));
}

skt_ip_filter_t *skt_load_ip_list(const char *file) {
    LOG_I("loading ip list file: %s", file);
    FILE *fp;
    if ((fp = fopen(file, "r")) == NULL) {
        LOG_E("can't open file %s", file);
        return NULL;
    }

    skt_ip_filter_t *filter = malloc(sizeof(skt_ip_filter_t));
    filter->bitset = bitset_create();

    while (!feof(fp)) {
        ip_mask_tuple_t tuple;
        bzero(&tuple, sizeof(tuple));
        int rt = read_line(fp, &tuple);
        if (rt != 0) {
            break;
        }

        // LOG_D("read ip_from %s mask_to %s", tuple.ip_from, tuple.ip_to);
        struct in_addr ip_from, ip_to;
        inet_pton(AF_INET, tuple.ip_from, &ip_from);
        inet_pton(AF_INET, tuple.ip_to, &ip_to);
        // LOG_D("222 ip_from %u mask_to %u", ntohl(ip_from.s_addr), ntohl(ip_to.s_addr));
        for (size_t i = ntohl(ip_from.s_addr); i <= ntohl(ip_to.s_addr); i++) {
            bitset_set(filter->bitset, i);
            // LOG_D("bitset_set %zu", i);
        }

        // char ip1[20] = {0};
        // char ip2[20] = {0};
        // inet_ntop(AF_INET, &ip_from, ip1, sizeof(ip1));
        // inet_ntop(AF_INET, &ip_to, ip2, sizeof(ip2));
        // LOG_D("333 ip_from %s mask_to %s", ip1, ip2);
    }

    fclose(fp);

    LOG_I("loaded ip list file: %s ok", file);
    return filter;
}

void skt_ip_filter_free(skt_ip_filter_t *filter) {
    if (!filter) {
        return;
    }
    if (filter->bitset) {
        bitset_free(filter->bitset);
        filter->bitset = NULL;
    }
    FREE_IF(filter);
}