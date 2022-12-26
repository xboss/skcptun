#ifndef _SKT_CONFIG_H
#define _SKT_CONFIG_H

typedef struct skt_serv_conf_s skt_serv_conf_t;
typedef struct skt_cli_conf_s skt_cli_conf_t;

skt_serv_conf_t *skt_init_server_tc_conf(const char *conf_file);
void skt_free_server_tc_conf(skt_serv_conf_t *serv_conf);
skt_cli_conf_t *skt_init_client_tc_conf(const char *conf_file);
void skt_free_client_tc_conf(skt_cli_conf_t *cli_conf);

#endif