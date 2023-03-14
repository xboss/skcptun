#ifndef _SKT_CONFIG_H
#define _SKT_CONFIG_H

#include <stdint.h>

typedef struct etcp_serv_conf_s etcp_serv_conf_t;
typedef struct etcp_cli_conf_s etcp_cli_conf_t;
typedef struct skcp_conf_s skcp_conf_t;

#define SKT_TUN_SERV_MODE 1
#define SKT_TUN_CLI_MODE 2
#define SKT_PROXY_SERV_MODE 3
#define SKT_PROXY_CLI_MODE 4

typedef struct {
    int mode;  // 1:tunnel server; 2:tunnel client; 3:proxy server; 4:proxy client.
    char *tun_ip;
    char *tun_mask;
    char *tcp_target_addr;
    uint16_t tcp_target_port;
    etcp_serv_conf_t *etcp_serv_conf;
    etcp_cli_conf_t *etcp_cli_conf;
    skcp_conf_t *skcp_conf;
} skt_config_t;

skt_config_t *skt_init_conf(const char *conf_file);
void skt_free_conf(skt_config_t *conf);

#endif