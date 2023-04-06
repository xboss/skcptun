#ifndef _SKT_CONFIG_H
#define _SKT_CONFIG_H

#include <stdint.h>
#include <stdlib.h>

typedef struct etcp_serv_conf_s etcp_serv_conf_t;
typedef struct etcp_cli_conf_s etcp_cli_conf_t;
typedef struct skcp_conf_s skcp_conf_t;

#define SKT_TUN_SERV_MODE "tun_server"
#define SKT_TUN_CLI_MODE "tun_client"
#define SKT_PROXY_SERV_MODE "proxy_server"
#define SKT_PROXY_CLI_MODE "proxy_client"

#define SKT_IF_TUN_SERV_MODE(_v_mode) if (strcmp((_v_mode), SKT_TUN_SERV_MODE) == 0)
#define SKT_IF_TUN_CLI_MODE(_v_mode) if (strcmp((_v_mode), SKT_TUN_CLI_MODE) == 0)
#define SKT_IF_PROXY_SERV_MODE(_v_mode) if (strcmp((_v_mode), SKT_PROXY_SERV_MODE) == 0)
#define SKT_IF_PROXY_CLI_MODE(_v_mode) if (strcmp((_v_mode), SKT_PROXY_CLI_MODE) == 0)

struct skt_config_s {
    char *mode;
    char *script_file;
    char *tun_ip;
    char *tun_mask;
    char *tcp_target_addr;
    uint16_t tcp_target_port;
    etcp_serv_conf_t *etcp_serv_conf;
    etcp_cli_conf_t *etcp_cli_conf;
    skcp_conf_t **skcp_conf_list;
    size_t skcp_conf_list_cnt;
};
typedef struct skt_config_s skt_config_t;

skt_config_t *skt_init_conf(const char *conf_file);
void skt_free_conf(skt_config_t *conf);

#endif