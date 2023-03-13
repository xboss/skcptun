#include "skt_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "easy_tcp.h"
#include "skcp.h"
#include "skt_client.h"
#include "skt_server.h"
#include "skt_utils.h"

#define SKT_CONF_R_BUF_SIZE 1024
#define SKT_CONF_MAX_JSTR_LEN SKT_CONF_R_BUF_SIZE * 5

#define SKT_CONF_ERROR(_v_e_item)                    \
    LOG_E("invalid %s in %s", _v_e_item, conf_file); \
    skt_free_conf(conf);                             \
    cJSON_Delete(m_json);                            \
    return NULL

/* -------------------------------------------------------------------------- */
/*                                   common                                   */
/* -------------------------------------------------------------------------- */

static inline void get_str(cJSON *m_json, char *name, char **value) {
    cJSON *local_addr_js = cJSON_GetObjectItemCaseSensitive(m_json, name);
    if (cJSON_IsString(local_addr_js) && (local_addr_js->valuestring != NULL)) {
        int slen = strlen(local_addr_js->valuestring);
        *value = malloc(slen + 1);
        memset(*value, 0, slen + 1);
        memcpy(*value, local_addr_js->valuestring, slen);
    }
}

static inline void get_int(cJSON *m_json, char *name, int *value) {
    cJSON *local_port_js = cJSON_GetObjectItemCaseSensitive(m_json, name);
    if (cJSON_IsNumber(local_port_js)) {
        *value = local_port_js->valueint;
    }
}

/* -------------------------------------------------------------------------- */
/*                                   config                                   */
/* -------------------------------------------------------------------------- */

#define SKT_SET_TCP_CONF                                                 \
    get_int(m_json, "tcp_read_buf_size", (int *)&etcp_conf->r_buf_size); \
    if (etcp_conf->r_buf_size <= 0) {                                    \
        LOG_E("invalid tcp_read_buf_size in config");                    \
        return -1;                                                       \
    }                                                                    \
    int keepalive = 0;                                                   \
    get_int(m_json, "tcp_keepalive", &keepalive);                        \
    if (keepalive > 0) {                                                 \
        etcp_conf->r_keepalive = keepalive;                              \
        etcp_conf->w_keepalive = keepalive;                              \
    }                                                                    \
    int recv_timeout = 0;                                                \
    get_int(m_json, "tcp_recv_timeout", &recv_timeout);                  \
    if (recv_timeout > 0) {                                              \
        etcp_conf->recv_timeout = recv_timeout;                          \
    }                                                                    \
    int send_timeout = 0;                                                \
    get_int(m_json, "tcp_send_timeout", &send_timeout);                  \
    if (send_timeout > 0) {                                              \
        etcp_conf->send_timeout = send_timeout;                          \
    }

inline static int init_etcp_serv_conf(cJSON *m_json, skt_config_t *conf) {
    conf->etcp_serv_conf = (etcp_serv_conf_t *)calloc(1, sizeof(etcp_serv_conf_t));
    etcp_serv_conf_t *etcp_conf = conf->etcp_serv_conf;
    ETCP_SER_DEF_CONF(etcp_conf);

    SKT_SET_TCP_CONF

    int timeout_interval = 0;
    get_int(m_json, "tcp_timeout_interval", &timeout_interval);
    if (timeout_interval > 0) {
        etcp_conf->timeout_interval = timeout_interval;
    }

    get_str(m_json, "tcp_listen_addr", &etcp_conf->serv_addr);
    if (NULL == etcp_conf->serv_addr) {
        LOG_E("invalid tcp_listen_addr in config");
        return -1;
    }
    get_int(m_json, "tcp_listen_port", (int *)&etcp_conf->serv_port);
    if (etcp_conf->serv_port <= 0) {
        LOG_E("invalid tcp_listen_port in config");
        return -1;
    }

    return 0;
}

inline static int init_etcp_cli_conf(cJSON *m_json, skt_config_t *conf) {
    conf->etcp_cli_conf = (etcp_cli_conf_t *)calloc(1, sizeof(etcp_cli_conf_t));
    etcp_cli_conf_t *etcp_conf = conf->etcp_cli_conf;
    ETCP_CLI_DEF_CONF(conf->etcp_cli_conf);

    SKT_SET_TCP_CONF

    get_str(m_json, "tcp_target_addr", &conf->tcp_target_addr);
    if (NULL == conf->tcp_target_addr) {
        LOG_E("invalid tcp_target_addr in config");
        return -1;
    }
    get_int(m_json, "tcp_target_port", (int *)&conf->tcp_target_port);
    if (conf->tcp_target_port <= 0) {
        LOG_E("invalid tcp_target_port in config");
        return -1;
    }

    return 0;
}

skt_config_t *skt_init_conf(const char *conf_file) {
    FILE *fp;
    if ((fp = fopen(conf_file, "r")) == NULL) {
        LOG_E("can't open conf file %s", conf_file);
        return NULL;
    }

    char json_str[SKT_CONF_MAX_JSTR_LEN] = {0};
    char buf[SKT_CONF_R_BUF_SIZE] = {0};
    char *p = json_str;
    int js_len = 0;
    while (fgets(buf, SKT_CONF_R_BUF_SIZE, fp) != NULL) {
        int len = strlen(buf);
        memcpy(p, buf, len);
        p += len;
        js_len += len;
        if (js_len > SKT_CONF_MAX_JSTR_LEN) {
            LOG_E("conf file %s is too large", conf_file);
            fclose(fp);
            return NULL;
        }
    }
    fclose(fp);

    cJSON *m_json = cJSON_Parse(json_str);
    if (m_json == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            LOG_E("%s", error_ptr);
        } else {
            LOG_E("json parse error");
        }
        return NULL;
    }

    skt_config_t *conf = (skt_config_t *)calloc(1, sizeof(skt_config_t));

    get_int(m_json, "mode", (int *)&conf->mode);

    if (conf->mode < 1 || conf->mode > 4) {
        SKT_CONF_ERROR("mode");
    }

    int rt = -1;
    conf->skcp_conf = (skcp_conf_t *)malloc(sizeof(skcp_conf_t));
    SKCP_DEF_CONF(conf->skcp_conf);
    if (conf->mode == SKT_TUN_SERV_MODE || conf->mode == SKT_TUN_CLI_MODE) {
        get_str(m_json, "tun_ip", &conf->tun_ip);
        if (NULL == conf->tun_ip) {
            SKT_CONF_ERROR("tun_ip");
        }

        get_str(m_json, "tun_mask", &conf->tun_mask);
        if (NULL == conf->tun_mask) {
            SKT_CONF_ERROR("tun_mask");
        }
    }

    if (conf->mode == SKT_PROXY_SERV_MODE) {
        rt = init_etcp_cli_conf(m_json, conf);
        if (rt != 0) {
            SKT_CONF_ERROR("init easytcp client config");
        }
    }

    if (conf->mode == SKT_PROXY_CLI_MODE) {
        rt = init_etcp_serv_conf(m_json, conf);
        if (rt != 0) {
            SKT_CONF_ERROR("init easytcp server config");
        }
    }

    if (conf->mode == SKT_TUN_SERV_MODE || conf->mode == SKT_PROXY_SERV_MODE) {
        int max_conn_cnt = 0;
        get_int(m_json, "skcp_max_conn_cnt", &max_conn_cnt);
        if (max_conn_cnt > 0) {
            conf->skcp_conf->max_conn_cnt = max_conn_cnt;
        }
        get_str(m_json, "skcp_listen_addr", &conf->skcp_conf->addr);
        if (NULL == conf->skcp_conf->addr) {
            SKT_CONF_ERROR("skcp_listen_addr");
        }
        get_int(m_json, "skcp_listen_port", (int *)&conf->skcp_conf->port);
        if (conf->skcp_conf->port <= 0) {
            SKT_CONF_ERROR("skcp_listen_port");
        }
    }

    if (conf->mode == SKT_TUN_CLI_MODE || conf->mode == SKT_PROXY_CLI_MODE) {
        get_str(m_json, "skcp_remote_addr", &conf->skcp_conf->addr);
        if (NULL == conf->skcp_conf->addr) {
            SKT_CONF_ERROR("skcp_remote_addr");
        }
        get_int(m_json, "skcp_remote_port", (int *)&conf->skcp_conf->port);
        if (conf->skcp_conf->port <= 0) {
            SKT_CONF_ERROR("skcp_remote_port");
        }
        char *ticket = NULL;
        get_str(m_json, "ticket", &ticket);
        if (!ticket) {
            SKT_CONF_ERROR("ticket");
        }
        int ticket_len = strlen(ticket);
        ticket_len = ticket_len < SKCP_TICKET_LEN ? ticket_len : SKCP_TICKET_LEN;
        memcpy(conf->skcp_conf->ticket, ticket, ticket_len);
    }

    int speed_mode = 0;
    get_int(m_json, "skcp_speed_mode", &speed_mode);
    if (1 != speed_mode) {
        conf->skcp_conf->nodelay = 0;
        conf->skcp_conf->resend = 0;
        conf->skcp_conf->nc = 0;
    }

    int keepalive = 0;
    get_int(m_json, "skcp_keepalive", &keepalive);
    if (keepalive > 0) {
        conf->skcp_conf->r_keepalive = keepalive;
        conf->skcp_conf->w_keepalive = keepalive;
    }

    char *password = NULL;
    get_str(m_json, "password", &password);
    if (!password) {
        SKT_CONF_ERROR("password");
    }
    int pw_len = strlen(password);
    char padding[16] = {0};
    if (pw_len > 16) {
        pw_len = 16;
        memcpy(padding, password, pw_len);
    } else {
        memcpy(padding, password, pw_len);
        pw_len = 16;
    }
    FREE_IF(password);

    char_to_hex(padding, pw_len, conf->skcp_conf->key);

    cJSON_Delete(m_json);

    return conf;
}

void skt_free_conf(skt_config_t *conf) {
    // TODO:
    if (!conf) {
        return;
    }

    if (conf->tun_ip) {
        FREE_IF(conf->tun_ip);
    }

    if (conf->tun_mask) {
        FREE_IF(conf->tun_mask);
    }

    if (conf->tcp_target_addr) {
        FREE_IF(conf->tcp_target_addr);
    }

    if (conf->skcp_conf) {
        if (conf->skcp_conf->addr) {
            FREE_IF(conf->skcp_conf->addr);
        }
        FREE_IF(conf->skcp_conf);
    }

    if (conf->etcp_serv_conf) {
        if (conf->etcp_serv_conf->serv_addr) {
            FREE_IF(conf->etcp_serv_conf->serv_addr);
        }
        FREE_IF(conf->etcp_serv_conf);
    }

    if (conf->etcp_cli_conf) {
        FREE_IF(conf->etcp_cli_conf);
    }

    FREE_IF(conf);
}

/* ---------------------------------- test ---------------------------------- */

// int main(int argc, char const *argv[]) {
//     skt_config_t *conf = skt_init_conf("../skcptun_sample.conf");
//     assert(conf);
//     skt_free_conf(conf);
//     return 0;
// }
