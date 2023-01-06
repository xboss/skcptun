#include <arpa/inet.h>
#include <stdio.h>

#include "skt_ip_filter.h"
#include "skt_utils.h"

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Invalid parameter.\nUsage:\n    %s ip_list_file ip\n", argv[0]);
        return -1;
    }

    skt_ip_filter_t *filter = skt_load_ip_list(argv[1]);
    if (filter == NULL) {
        return -1;
    }

    // char ip[] = "104.193.88.77";
    char *ip = argv[2];
    struct in_addr ip_addr;
    inet_pton(AF_INET, ip, &ip_addr);
    printf("ip: %s %u %u\n", ip, ip_addr.s_addr, ntohl(ip_addr.s_addr));
    if (skt_ip_filter_is_in(filter, ip_addr)) {
        LOG_D("ip %s is in ip list", ip);
    } else {
        LOG_D("ip %s is not in ip list", ip);
    }

    skt_ip_filter_free(filter);

    return 0;
}