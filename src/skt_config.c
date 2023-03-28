#include "skt_config.h"

#include <stdio.h>
#include <string.h>

#include "cJSON.h"
#include "easy_tcp.h"
#include "skcp.h"
#include "skt_client.h"
#include "skt_server.h"
#include "skt_utils.h"

#define SKT_CONF_R_BUF_SIZE 1024
#define SKT_CONF_MAX_JSTR_LEN SKT_CONF_R_BUF_SIZE * 5

inline static char *get_str(cJSON *m_json, char *name, char *def) {
    cJSON *str_js = cJSON_GetObjectItemCaseSensitive(m_json, name);
    char *s = NULL;
    int slen = 0;
    if (cJSON_IsString(str_js) && (str_js->valuestring != NULL)) {
        s = str_js->valuestring;
        slen = strlen(str_js->valuestring);
    } else if (def) {
        s = def;
        slen = strlen(def);
    }
    char *value = NULL;
    if (s) {
        value = (char *)calloc(1, slen + 1);
        memcpy(value, s, slen);
    }
    return value;
}

inline static int get_int(cJSON *m_json, char *name, int def) {
    cJSON *int_js = cJSON_GetObjectItemCaseSensitive(m_json, name);
    if (cJSON_IsNumber(int_js)) {
        return int_js->valueint;
    }
    return def;
}

inline static cJSON *get_obj(cJSON *m_json, char *name) {
    cJSON *obj = cJSON_GetObjectItemCaseSensitive(m_json, name);
    if (!obj || !cJSON_IsObject(obj)) {
        return NULL;
    }
    return obj;
}

inline static int get_obj_array(cJSON *m_json, char *name, cJSON **obj_arr) {
    *obj_arr = cJSON_GetObjectItemCaseSensitive(m_json, name);
    if (!cJSON_IsArray(*obj_arr)) {
        return 0;
    }
    int sz = cJSON_GetArraySize(*obj_arr);
    if (sz <= 0) {
        return 0;
    }
    return sz;
}

static cJSON *read_file(const char *conf_file) {
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

    return m_json;
}

#define SKT_CONF_SET_INT_DEF(_v_name, _v_value) (_v_value) = get_int(m_json, _v_name, (_v_value));

inline static int init_skcp_conf(cJSON *m_json, skcp_conf_t *skcp_conf) {
    SKCP_DEF_CONF(skcp_conf);
    SKT_CONF_SET_INT_DEF("skcp_keepalive", skcp_conf->r_keepalive);
    skcp_conf->w_keepalive = skcp_conf->r_keepalive;
    SKT_CONF_SET_INT_DEF("port", skcp_conf->port);
    SKT_CONF_SET_INT_DEF("skcp_max_conn_cnt", skcp_conf->max_conn_cnt);
    int speed_mode = get_int(m_json, "skcp_speed_mode", 0);
    if (1 != speed_mode) {
        skcp_conf->nodelay = 0;
        skcp_conf->resend = 0;
        skcp_conf->nc = 0;
    }
    char *password = get_str(m_json, "password", NULL);
    if (password) {
        int pw_len = strlen(password);
        char padding[16] = {0};
        pw_len = pw_len > 16 ? 16 : pw_len;
        memcpy(padding, password, pw_len);
        FREE_IF(password);
        char_to_hex(padding, pw_len, skcp_conf->key);
    }

    char *ticket = get_str(m_json, "ticket", NULL);
    if (ticket) {
        int ticket_len = strlen(ticket);
        ticket_len = ticket_len < SKCP_TICKET_LEN ? ticket_len : SKCP_TICKET_LEN;
        memcpy(skcp_conf->ticket, ticket, ticket_len);
    }

    skcp_conf->addr = get_str(m_json, "address", "127.0.0.1");
    return 0;
}

inline static int init_skcp_conf_array(cJSON *m_json, skt_config_t *conf, char *skcp_serv_name) {
    cJSON *obj_arr = NULL;
    int oa_sz = get_obj_array(m_json, skcp_serv_name, &obj_arr);
    if (oa_sz <= 0) {
        LOG_E("invalid %s in config file", skcp_serv_name);
        return -1;
    }
    conf->skcp_conf_cnt = oa_sz;
    conf->skcp_conf = (skcp_conf_t **)calloc(oa_sz, sizeof(skcp_conf_t *));
    size_t i = 0;
    for (; i < oa_sz; i++) {
        conf->skcp_conf[i] = (skcp_conf_t *)calloc(1, sizeof(skcp_conf_t));
        cJSON *o_json = cJSON_GetArrayItem(obj_arr, i);
        init_skcp_conf(o_json, conf->skcp_conf[i]);
        // SKCP_DEF_CONF(conf->skcp_conf[i]);
        // SKT_CONF_SET_INT_DEF("skcp_keepalive", conf->skcp_conf[i]->r_keepalive);
        // conf->skcp_conf[i]->w_keepalive = conf->skcp_conf[i]->r_keepalive;
        // SKT_CONF_SET_INT_DEF("port", conf->skcp_conf[i]->port);
        // SKT_CONF_SET_INT_DEF("skcp_max_conn_cnt", conf->skcp_conf[i]->max_conn_cnt);
        // int speed_mode = get_int(m_json, "skcp_speed_mode", 0);
        // if (1 != speed_mode) {
        //     conf->skcp_conf[i]->nodelay = 0;
        //     conf->skcp_conf[i]->resend = 0;
        //     conf->skcp_conf[i]->nc = 0;
        // }
        // char *password = get_str(m_json, "password", NULL);
        // if (password) {
        //     int pw_len = strlen(password);
        //     char padding[16] = {0};
        //     pw_len = pw_len > 16 ? 16 : pw_len;
        //     memcpy(padding, password, pw_len);
        //     FREE_IF(password);
        //     char_to_hex(padding, pw_len, conf->skcp_conf[i]->key);
        // }

        // char *ticket = get_str(m_json, "ticket", NULL);
        // if (ticket) {
        //     int ticket_len = strlen(ticket);
        //     ticket_len = ticket_len < SKCP_TICKET_LEN ? ticket_len : SKCP_TICKET_LEN;
        //     memcpy(conf->skcp_conf[i]->ticket, ticket, ticket_len);
        // }

        // conf->skcp_conf[i]->addr = get_str(m_json, "address", "127.0.0.1");
    }

    return 0;
}

static int init_proxy_cli(cJSON *m_json, skt_config_t *conf) {
    conf->etcp_serv_conf = (etcp_serv_conf_t *)calloc(1, sizeof(etcp_serv_conf_t));
    etcp_serv_conf_t *etcp_conf = conf->etcp_serv_conf;
    ETCP_SER_DEF_CONF(etcp_conf);
    SKT_CONF_SET_INT_DEF("tcp_read_buf_size", etcp_conf->r_buf_size);
    SKT_CONF_SET_INT_DEF("tcp_keepalive", etcp_conf->r_keepalive);
    etcp_conf->w_keepalive = etcp_conf->r_keepalive;
    SKT_CONF_SET_INT_DEF("tcp_recv_timeout", etcp_conf->recv_timeout);
    SKT_CONF_SET_INT_DEF("tcp_send_timeout", etcp_conf->send_timeout);
    SKT_CONF_SET_INT_DEF("tcp_timeout_interval", etcp_conf->timeout_interval);
    SKT_CONF_SET_INT_DEF("tcp_listen_port", etcp_conf->serv_port);
    etcp_conf->serv_addr = get_str(m_json, "tcp_listen_addr", "127.0.0.1");
    return init_skcp_conf_array(m_json, conf, "skcp_remote_servers");
}

static int init_proxy_serv(cJSON *m_json, skt_config_t *conf) {
    conf->etcp_cli_conf = (etcp_cli_conf_t *)calloc(1, sizeof(etcp_cli_conf_t));
    etcp_cli_conf_t *etcp_conf = conf->etcp_cli_conf;
    ETCP_CLI_DEF_CONF(etcp_conf);
    SKT_CONF_SET_INT_DEF("tcp_read_buf_size", etcp_conf->r_buf_size);
    SKT_CONF_SET_INT_DEF("tcp_keepalive", etcp_conf->r_keepalive);
    etcp_conf->w_keepalive = etcp_conf->r_keepalive;
    SKT_CONF_SET_INT_DEF("tcp_recv_timeout", etcp_conf->recv_timeout);
    SKT_CONF_SET_INT_DEF("tcp_send_timeout", etcp_conf->send_timeout);
    SKT_CONF_SET_INT_DEF("tcp_target_port", conf->tcp_target_port);
    conf->tcp_target_addr = get_str(m_json, "tcp_target_addr", "127.0.0.1");

    conf->skcp_conf = (skcp_conf_t **)calloc(1, sizeof(skcp_conf_t *));
    conf->skcp_conf[0] = (skcp_conf_t *)calloc(1, sizeof(skcp_conf_t));
    cJSON *obj = get_obj(m_json, "skcp_server");
    return init_skcp_conf(obj, conf->skcp_conf[0]);
}

static int init_tun_cli(cJSON *m_json, skt_config_t *conf) {
    conf->tun_ip = get_str(m_json, "tun_ip", NULL);
    if (!conf->tun_ip) {
        LOG_E("invalid tun_client.tun_ip in config file");
        return -1;
    }

    conf->tun_mask = get_str(m_json, "tun_mask", NULL);
    if (!conf->tun_mask) {
        LOG_E("invalid tun_client.tun_mask in config file");
        return -1;
    }
    return init_skcp_conf_array(m_json, conf, "skcp_remote_servers");
}

static int init_tun_serv(cJSON *m_json, skt_config_t *conf) {
    conf->tun_ip = get_str(m_json, "tun_ip", NULL);
    if (!conf->tun_ip) {
        LOG_E("invalid tun_server.tun_ip in config file");
        return -1;
    }

    conf->tun_mask = get_str(m_json, "tun_mask", NULL);
    if (!conf->tun_mask) {
        LOG_E("invalid tun_server.tun_mask in config file");
        return -1;
    }
    conf->skcp_conf = (skcp_conf_t **)calloc(1, sizeof(skcp_conf_t *));
    conf->skcp_conf[0] = (skcp_conf_t *)calloc(1, sizeof(skcp_conf_t));
    cJSON *obj = get_obj(m_json, "skcp_server");
    return init_skcp_conf(obj, conf->skcp_conf[0]);
}

skt_config_t *skt_init_conf(const char *conf_file) {
    cJSON *m_json = read_file(conf_file);
    if (!m_json) {
        return NULL;
    }

    skt_config_t *conf = (skt_config_t *)calloc(1, sizeof(skt_config_t));
    conf->mode = get_str(m_json, "mode", NULL);
    if (!conf->mode) {
        FREE_IF(conf);
        return NULL;
    }

    int rt = -1;
    cJSON *o_json = NULL;
    SKT_IF_TUN_SERV_MODE(conf->mode) {
        o_json = get_obj(m_json, SKT_TUN_SERV_MODE);
        if (o_json) {
            rt = init_tun_serv(o_json, conf);
        }
    }
    else SKT_IF_TUN_CLI_MODE(conf->mode) {
        o_json = get_obj(m_json, SKT_TUN_CLI_MODE);
        if (o_json) {
            rt = init_tun_cli(o_json, conf);
        }
    }
    else SKT_IF_PROXY_SERV_MODE(conf->mode) {
        o_json = get_obj(m_json, SKT_PROXY_SERV_MODE);
        if (o_json) {
            rt = init_proxy_serv(o_json, conf);
        }
    }
    else SKT_IF_PROXY_CLI_MODE(conf->mode) {
        o_json = get_obj(m_json, SKT_PROXY_CLI_MODE);
        if (o_json) {
            rt = init_proxy_cli(o_json, conf);
        }
    }

    cJSON_Delete(m_json);
    if (rt != 0) {
        skt_free_conf(conf);
        return NULL;
    }
    return conf;
}

void skt_free_conf(skt_config_t *conf) {
    if (!conf) {
        return;
    }

    if (conf->mode) {
        FREE_IF(conf->mode);
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

    if (conf->skcp_conf && conf->skcp_conf_cnt > 0) {
        for (size_t i = 0; i < conf->skcp_conf_cnt; i++) {
            if (conf->skcp_conf[i]) {
                if (conf->skcp_conf[i]->addr) {
                    FREE_IF(conf->skcp_conf[i]->addr);
                }
                FREE_IF(conf->skcp_conf[i]);
            }
        }
        FREE_IF(conf->skcp_conf);
        conf->skcp_conf_cnt = 0;
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
//     skt_config_t *conf = skt_init_conf("../skcptun_sample_config.json");
//     assert(conf);
//     skt_free_conf(conf);
//     return 0;
// }
