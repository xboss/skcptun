#ifndef _SKT_CONFIG_H
#define _SKT_CONFIG_H

#include <stdint.h>
#include <stdlib.h>

typedef struct etcp_serv_conf_s etcp_serv_conf_t;
typedef struct etcp_cli_conf_s etcp_cli_conf_t;
typedef struct skcp_conf_s skcp_conf_t;

struct skt_config_s {
    char *script_file;
    char *tun_ip;
    char *tun_mask;
    etcp_serv_conf_t **etcp_serv_conf_list;
    etcp_cli_conf_t **etcp_cli_conf_list;
    skcp_conf_t **skcp_serv_conf_list;
    skcp_conf_t **skcp_cli_conf_list;

    size_t etcp_serv_conf_list_size;
    size_t etcp_cli_conf_list_size;
    size_t skcp_serv_conf_list_size;
    size_t skcp_cli_conf_list_size;
};
typedef struct skt_config_s skt_config_t;

skt_config_t *skt_init_conf(const char *conf_file);
void skt_free_conf(skt_config_t *conf);

#endif