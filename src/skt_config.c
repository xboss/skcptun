#include "skt_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// #include "3rd/cJSON/cJSON.h"
#include "cJSON.h"
#include "skt_client.h"
#include "skt_server.h"
#include "skt_utils.h"

#define SKT_CONF_R_BUF_SIZE 1024
#define SKT_CONF_MAX_JSTR_LEN SKT_CONF_R_BUF_SIZE * 5

/**********  common **********/

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

static skt_kcp_conf_t *init_def_kcp_conf() {
    skt_kcp_conf_t *kcp_conf = malloc(sizeof(skt_kcp_conf_t));
    skcp_conf_t *skcp_conf = malloc(sizeof(skcp_conf_t));
    skcp_conf->interval = 10;
    skcp_conf->mtu = 1400;
    skcp_conf->rcvwnd = 128;
    skcp_conf->sndwnd = 128;
    skcp_conf->nodelay = 1;
    skcp_conf->resend = 2;
    skcp_conf->nc = 1;
    skcp_conf->r_keepalive = 600;
    skcp_conf->w_keepalive = 600;
    skcp_conf->estab_timeout = 100;

    kcp_conf->skcp_conf = skcp_conf;
    kcp_conf->addr = NULL;  //"127.0.0.1";
    kcp_conf->port = 1111;
    kcp_conf->key = NULL;
    kcp_conf->r_buf_size = 1500;
    kcp_conf->kcp_buf_size = 2048;
    kcp_conf->timeout_interval = 1;

    return kcp_conf;
}

/**********  client config **********/

static skt_cli_conf_t *init_def_cli_conf() {
    skt_cli_conf_t *cli_conf = malloc(sizeof(skt_cli_conf_t));

    cli_conf->kcp_conf = init_def_kcp_conf();
    cli_conf->tun_ip = NULL;
    cli_conf->tun_mask = NULL;

    return cli_conf;
}

void skt_free_client_conf(skt_cli_conf_t *cli_conf) {
    if (cli_conf) {
        if (cli_conf->kcp_conf) {
            FREE_IF(cli_conf->kcp_conf->skcp_conf);
            FREE_IF(cli_conf->kcp_conf->key);
            FREE_IF(cli_conf->kcp_conf->addr);
            FREE_IF(cli_conf->kcp_conf);
        }

        FREE_IF(cli_conf->tun_ip);
        FREE_IF(cli_conf->tun_mask);

        FREE_IF(cli_conf);
    }
}

skt_cli_conf_t *skt_init_client_conf(const char *conf_file) {
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

    skt_cli_conf_t *conf = init_def_cli_conf();
    // TODO: check ip format
    // TODO: check port format

    get_str(m_json, "tun_ip", &conf->tun_ip);
    if (NULL == conf->tun_ip) {
        LOG_E("invalid tun_ip in %s", conf_file);
        skt_free_client_conf(conf);
        cJSON_Delete(m_json);
        return NULL;
    }

    get_str(m_json, "tun_mask", &conf->tun_mask);
    if (NULL == conf->tun_mask) {
        LOG_E("invalid tun_mask in %s", conf_file);
        skt_free_client_conf(conf);
        cJSON_Delete(m_json);
        return NULL;
    }

    get_str(m_json, "remote_addr", &conf->kcp_conf->addr);
    if (NULL == conf->kcp_conf->addr) {
        LOG_E("invalid remote_addr in %s", conf_file);
        skt_free_client_conf(conf);
        cJSON_Delete(m_json);
        return NULL;
    }

    get_int(m_json, "remote_port", (int *)&conf->kcp_conf->port);

    int speed_mode = 0;
    get_int(m_json, "speed_mode", &speed_mode);
    if (1 != speed_mode) {
        conf->kcp_conf->skcp_conf->nodelay = 0;
        conf->kcp_conf->skcp_conf->resend = 0;
        conf->kcp_conf->skcp_conf->nc = 0;
    }

    int keepalive = 0;
    get_int(m_json, "keepalive", &keepalive);
    if (keepalive > 0) {
        conf->kcp_conf->skcp_conf->r_keepalive = keepalive;
        conf->kcp_conf->skcp_conf->w_keepalive = keepalive;
    }

    char *password = NULL;
    get_str(m_json, "password", &password);
    if (NULL != password) {
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

        int k_len = 33;
        conf->kcp_conf->key = malloc(k_len);
        memset(conf->kcp_conf->key, 0, k_len);
        char_to_hex(padding, pw_len, conf->kcp_conf->key);
    }

    cJSON_Delete(m_json);

    return conf;
}

/********** server config **********/

static skt_serv_conf_t *init_def_serv_conf() {
    skt_serv_conf_t *serv_conf = malloc(sizeof(skt_serv_conf_t));
    serv_conf->tun_ip = NULL;
    serv_conf->tun_mask = NULL;

    serv_conf->kcp_conf = init_def_kcp_conf();

    return serv_conf;
}

void skt_free_server_conf(skt_serv_conf_t *serv_conf) {
    if (serv_conf) {
        if (serv_conf->kcp_conf) {
            FREE_IF(serv_conf->kcp_conf->skcp_conf);
            FREE_IF(serv_conf->kcp_conf->key);
            FREE_IF(serv_conf->kcp_conf->addr);
            FREE_IF(serv_conf->kcp_conf);
        }

        FREE_IF(serv_conf->tun_ip);
        FREE_IF(serv_conf->tun_mask);

        FREE_IF(serv_conf);
    }
}

skt_serv_conf_t *skt_init_server_conf(const char *conf_file) {
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

    skt_serv_conf_t *conf = init_def_serv_conf();

    // TODO: check ip format
    // TODO: check port format

    get_str(m_json, "tun_ip", &conf->tun_ip);
    if (NULL == conf->tun_ip) {
        LOG_E("invalid tun_ip in %s", conf_file);
        skt_free_server_conf(conf);
        cJSON_Delete(m_json);
        return NULL;
    }

    get_str(m_json, "tun_mask", &conf->tun_mask);
    if (NULL == conf->tun_mask) {
        LOG_E("invalid tun_mask in %s", conf_file);
        skt_free_server_conf(conf);
        cJSON_Delete(m_json);
        return NULL;
    }

    get_str(m_json, "listen_addr", &conf->kcp_conf->addr);
    if (NULL == conf->kcp_conf->addr) {
        LOG_E("invalid listen_addr in %s", conf_file);
        skt_free_server_conf(conf);
        cJSON_Delete(m_json);
        return NULL;
    }
    get_int(m_json, "listen_port", (int *)&conf->kcp_conf->port);

    int speed_mode = 0;
    get_int(m_json, "speed_mode", &speed_mode);
    if (1 != speed_mode) {
        conf->kcp_conf->skcp_conf->nodelay = 0;
        conf->kcp_conf->skcp_conf->resend = 0;
        conf->kcp_conf->skcp_conf->nc = 0;
    }

    int keepalive = 0;
    get_int(m_json, "keepalive", &keepalive);
    if (keepalive > 0) {
        conf->kcp_conf->skcp_conf->r_keepalive = keepalive;
        conf->kcp_conf->skcp_conf->w_keepalive = keepalive;
    }

    char *password = NULL;
    get_str(m_json, "password", &password);
    if (NULL != password) {
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

        int k_len = 33;
        conf->kcp_conf->key = malloc(k_len);
        memset(conf->kcp_conf->key, 0, k_len);
        char_to_hex(padding, pw_len, conf->kcp_conf->key);
    }

    cJSON_Delete(m_json);

    return conf;
}