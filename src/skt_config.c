#include "skt_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "3rd/cJSON/cJSON.h"
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

/**********  client config **********/

static skt_cli_conf_t *init_def_cli_conf() {  // TODO:
    skt_cli_conf_t *cli_conf = malloc(sizeof(skt_cli_conf_t));
    skt_kcp_cli_conf_t *kcp_cli_conf = malloc(sizeof(skt_kcp_cli_conf_t));
    kcp_cli_conf->addr = NULL;  //"127.0.0.1";
    kcp_cli_conf->port = 2222;
    kcp_cli_conf->key = NULL;
    kcp_cli_conf->interval = 10;
    kcp_cli_conf->mtu = 1024;
    kcp_cli_conf->rcvwnd = 128;
    kcp_cli_conf->sndwnd = 128;
    kcp_cli_conf->nodelay = 1;
    kcp_cli_conf->resend = 2;
    kcp_cli_conf->nc = 1;
    kcp_cli_conf->r_buf_size = kcp_cli_conf->mtu;
    kcp_cli_conf->kcp_buf_size = 2048;
    kcp_cli_conf->r_keepalive = 600;
    kcp_cli_conf->w_keepalive = 600;
    kcp_cli_conf->timeout_interval = 1;
    kcp_cli_conf->estab_timeout = 100;
    cli_conf->kcp_cli_conf = kcp_cli_conf;

    skt_tcp_serv_conf_t *tcp_serv_conf = malloc(sizeof(skt_tcp_serv_conf_t));
    tcp_serv_conf->serv_addr = NULL;
    tcp_serv_conf->serv_port = 1111;
    tcp_serv_conf->backlog = 1024;
    tcp_serv_conf->tcp_r_buf_size = 900;
    tcp_serv_conf->r_keepalive = 600;
    tcp_serv_conf->w_keepalive = 600;
    tcp_serv_conf->recv_timeout = 1000l;
    tcp_serv_conf->send_timeout = 1000l;
    cli_conf->tcp_serv_conf = tcp_serv_conf;

    return cli_conf;
}

void skt_free_client_conf(skt_cli_conf_t *cli_conf) {
    if (cli_conf) {
        if (cli_conf->kcp_cli_conf) {
            FREE_IF(cli_conf->kcp_cli_conf->key);
            FREE_IF(cli_conf->kcp_cli_conf->addr);
            FREE_IF(cli_conf->kcp_cli_conf);
        }
        if (cli_conf->tcp_serv_conf) {
            FREE_IF(cli_conf->tcp_serv_conf->serv_addr);
            FREE_IF(cli_conf->tcp_serv_conf);
        }

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

    get_str(m_json, "local_addr", &conf->tcp_serv_conf->serv_addr);
    if (NULL == conf->tcp_serv_conf->serv_addr) {
        char *s = "0.0.0.0";
        int l = strlen(s);
        conf->tcp_serv_conf->serv_addr = malloc(l + 1);
        memset(conf->tcp_serv_conf->serv_addr, 0, l + 1);
        memcpy(conf->tcp_serv_conf->serv_addr, s, l);
    }

    get_int(m_json, "local_port", (int *)&conf->tcp_serv_conf->serv_port);

    get_str(m_json, "remote_addr", &conf->kcp_cli_conf->addr);
    if (NULL == conf->kcp_cli_conf->addr) {
        char *s = "127.0.0.1";
        int l = strlen(s);
        conf->kcp_cli_conf->addr = malloc(l + 1);
        memset(conf->kcp_cli_conf->addr, 0, l + 1);
        memcpy(conf->kcp_cli_conf->addr, s, l);
    }
    get_int(m_json, "remote_port", (int *)&conf->kcp_cli_conf->port);

    int speed_mode = 0;
    get_int(m_json, "speed_mode", &speed_mode);
    if (1 != speed_mode) {
        conf->kcp_cli_conf->nodelay = 0;
        conf->kcp_cli_conf->resend = 0;
        conf->kcp_cli_conf->nc = 0;
    }

    int keepalive = 0;
    get_int(m_json, "keepalive", &keepalive);
    if (keepalive > 0) {
        conf->kcp_cli_conf->r_keepalive = keepalive;
        conf->kcp_cli_conf->w_keepalive = keepalive;
        conf->tcp_serv_conf->r_keepalive = keepalive;
        conf->tcp_serv_conf->w_keepalive = keepalive;
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
        conf->kcp_cli_conf->key = malloc(k_len);
        memset(conf->kcp_cli_conf->key, 0, k_len);
        char_to_hex(padding, pw_len, conf->kcp_cli_conf->key);
    }

    cJSON_Delete(m_json);

    return conf;
}

/**********  server config **********/

skt_serv_conf_t *init_def_serv_conf() {
    skt_serv_conf_t *serv_conf = malloc(sizeof(skt_serv_conf_t));
    serv_conf->target_addr = NULL;
    serv_conf->target_port = 3333;
    skt_kcp_serv_conf_t *kcp_serv_conf = malloc(sizeof(skt_kcp_serv_conf_t));
    kcp_serv_conf->addr = NULL;
    kcp_serv_conf->port = 2222;
    kcp_serv_conf->key = NULL;
    kcp_serv_conf->interval = 10;
    kcp_serv_conf->mtu = 1024;
    kcp_serv_conf->rcvwnd = 128;
    kcp_serv_conf->sndwnd = 128;
    kcp_serv_conf->nodelay = 1;
    kcp_serv_conf->resend = 2;
    kcp_serv_conf->nc = 1;
    kcp_serv_conf->r_buf_size = kcp_serv_conf->mtu;
    kcp_serv_conf->kcp_buf_size = 2048;
    kcp_serv_conf->r_keepalive = 600;
    kcp_serv_conf->w_keepalive = 600;
    kcp_serv_conf->timeout_interval = 1;
    kcp_serv_conf->estab_timeout = 100;
    serv_conf->kcp_serv_conf = kcp_serv_conf;

    skt_tcp_cli_conf_t *tcp_cli_conf = malloc(sizeof(skt_tcp_cli_conf_t));
    tcp_cli_conf->r_keepalive = 600;
    tcp_cli_conf->w_keepalive = 600;
    tcp_cli_conf->recv_timeout = 1000l;
    tcp_cli_conf->send_timeout = 1000l;
    tcp_cli_conf->r_buf_size = 900;
    serv_conf->tcp_cli_conf = tcp_cli_conf;

    return serv_conf;
}

void skt_free_server_conf(skt_serv_conf_t *serv_conf) {
    if (serv_conf) {
        FREE_IF(serv_conf->target_addr);
        if (serv_conf->kcp_serv_conf) {
            FREE_IF(serv_conf->kcp_serv_conf->key);
            FREE_IF(serv_conf->kcp_serv_conf->addr);
            FREE_IF(serv_conf->kcp_serv_conf);
        }
        if (serv_conf->tcp_cli_conf) {
            FREE_IF(serv_conf->tcp_cli_conf);
        }

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

    get_str(m_json, "local_addr", &conf->kcp_serv_conf->addr);
    if (NULL == conf->kcp_serv_conf->addr) {
        char *s = "0.0.0.0";
        int l = strlen(s);
        conf->kcp_serv_conf->addr = malloc(l + 1);
        memset(conf->kcp_serv_conf->addr, 0, l + 1);
        memcpy(conf->kcp_serv_conf->addr, s, l);
    }
    get_int(m_json, "local_port", (int *)&conf->kcp_serv_conf->port);

    get_str(m_json, "target_addr", &conf->target_addr);
    if (NULL == conf->target_addr) {
        char *s = "127.0.0.1";
        int l = strlen(s);
        conf->target_addr = malloc(l + 1);
        memset(conf->target_addr, 0, l + 1);
        memcpy(conf->target_addr, s, l);
    }
    get_int(m_json, "target_port", (int *)&conf->target_port);

    int speed_mode = 0;
    get_int(m_json, "speed_mode", &speed_mode);
    if (1 != speed_mode) {
        conf->kcp_serv_conf->nodelay = 0;
        conf->kcp_serv_conf->resend = 0;
        conf->kcp_serv_conf->nc = 0;
    }

    int keepalive = 0;
    get_int(m_json, "keepalive", &keepalive);
    if (keepalive > 0) {
        conf->kcp_serv_conf->r_keepalive = keepalive;
        conf->kcp_serv_conf->w_keepalive = keepalive;
        conf->tcp_cli_conf->r_keepalive = keepalive;
        conf->tcp_cli_conf->w_keepalive = keepalive;
    }

    char *password = NULL;
    get_str(m_json, "password", &password);
    if (NULL != password) {
        int pw_len = strlen(password);
        char padding[16] = {0};
        // memset(padding, 1, 16);
        if (pw_len > 16) {
            pw_len = 16;
            memcpy(padding, password, pw_len);
        } else {
            memcpy(padding, password, pw_len);
            pw_len = 16;
        }
        FREE_IF(password);

        int k_len = 33;
        conf->kcp_serv_conf->key = malloc(k_len);
        memset(conf->kcp_serv_conf->key, 0, k_len);
        char_to_hex(padding, pw_len, conf->kcp_serv_conf->key);
    }

    cJSON_Delete(m_json);

    return conf;
}

/**********  test **********/

// #define _DEBUG
// #if (defined(__linux__) || defined(__linux)) && defined(_DEBUG)
// #include <mcheck.h>
// #endif

// int main(int argc, char *argv[]) {
//     char *conf_file;

//     if (argc == 2) {
//         conf_file = argv[1];
//     } else {
//         printf("param error!!!\n");
//         return -1;
//     }

// #if (defined(__linux__) || defined(__linux)) && defined(_DEBUG)
//     setenv("MALLOC_TRACE", "/tmp/mtrace_config.log", 1);
//     mtrace();
// #endif

//     skt_cli_conf_t *cconf = skt_init_client_conf(conf_file);
//     if (NULL == cconf) {
//         return -1;
//     }

//     LOG_D("remote_addr:%s", cconf->kcp_cli_conf->addr);
//     LOG_D("remote_port:%d", cconf->kcp_cli_conf->port);
//     LOG_D("local_addr:%s", cconf->tcp_serv_conf->serv_addr);
//     LOG_D("local_port:%d", cconf->tcp_serv_conf->serv_port);
//     LOG_D("key:%s", cconf->kcp_cli_conf->key);
//     LOG_D("cconf->kcp_cli_conf->r_keepalive:%d", cconf->kcp_cli_conf->r_keepalive);
//     LOG_D("cconf->kcp_cli_conf->w_keepalive:%d", cconf->kcp_cli_conf->w_keepalive);
//     LOG_D("cconf->tcp_serv_conf->r_keepalive:%d", cconf->tcp_serv_conf->r_keepalive);
//     LOG_D("cconf->tcp_serv_conf->w_keepalive:%d", cconf->tcp_serv_conf->w_keepalive);
//     LOG_D("nodelay:%d", cconf->kcp_cli_conf->nodelay);
//     LOG_D("resend:%d", cconf->kcp_cli_conf->resend);
//     LOG_D("nc:%d", cconf->kcp_cli_conf->nc);
//     skt_free_client_conf(cconf);

//     LOG_D("---------");
//     skt_serv_conf_t *sconf = skt_init_server_conf(conf_file);
//     if (NULL == cconf) {
//         return -1;
//     }
//     LOG_D("target_addr:%s", sconf->target_addr);
//     LOG_D("target_port:%d", sconf->target_port);
//     LOG_D("local_addr:%s", sconf->kcp_serv_conf->addr);
//     LOG_D("local_port:%d", sconf->kcp_serv_conf->port);
//     LOG_D("key:%s", sconf->kcp_serv_conf->key);
//     LOG_D("sconf->kcp_serv_conf->r_keepalive:%d", sconf->kcp_serv_conf->r_keepalive);
//     LOG_D("sconf->kcp_serv_conf->w_keepalive:%d", sconf->kcp_serv_conf->w_keepalive);
//     LOG_D("sconf->tcp_cli_conf->r_keepalive:%d", sconf->tcp_cli_conf->r_keepalive);
//     LOG_D("sconf->tcp_cli_conf->w_keepalive:%d", sconf->tcp_cli_conf->w_keepalive);
//     LOG_D("nodelay:%d", sconf->kcp_serv_conf->nodelay);
//     LOG_D("resend:%d", sconf->kcp_serv_conf->resend);
//     LOG_D("nc:%d", sconf->kcp_serv_conf->nc);
//     skt_free_server_conf(sconf);

// #if (defined(__linux__) || defined(__linux)) && defined(_DEBUG)
//     muntrace();
// #endif

//     return 0;
// }