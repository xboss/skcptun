
#include <assert.h>
#include <ctype.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "skt_local.h"
#include "skt_remote.h"
#include "ssconf.h"

static skt_config_t g_conf;
static skcptun_t *g_skt = NULL;

static int load_conf(const char *conf_file, skt_config_t *conf) {
    char *keys[] = {"mode",   "local_ip",     "local_port", "remote_ip", "remote_port", "password",
                    "ticket", "log_file",     "log_level",  "timeout",   "tun_ip",      "tun_mask",
                    "mtu",    "kcp_interval", "speed_mode", "keepalive"};
    int keys_cnt = sizeof(keys) / sizeof(char *);
    ssconf_t *cf = ssconf_init(1024, 1024);
    if (!cf) return _ERR;
    int rt = ssconf_load(cf, conf_file);
    if (rt != 0) return _ERR;
    conf->log_level = SSLOG_LEVEL_ERROR;
    char *v = NULL;
    int i;
    for (i = 0; i < keys_cnt; i++) {
        v = ssconf_get_value(cf, keys[i]);
        if (!v) {
            printf("'%s' does not exists in config file '%s'.\n", keys[i], conf_file);
            continue;
        }
        int len = strlen(v);
        if (strcmp("mode", keys[i]) == 0) {
            if (strcmp(v, "local") == 0) {
                conf->mode = SKT_MODE_LOCAL;
            } else if (strcmp(v, "remote") == 0) {
                conf->mode = SKT_MODE_REMOTE;
            } else {
                conf->mode = -1;
            }
        } else if (strcmp("local_ip", keys[i]) == 0) {
            if (len <= INET_ADDRSTRLEN) {
                memcpy(conf->udp_local_ip, v, len);
            }
        } else if (strcmp("local_port", keys[i]) == 0) {
            conf->udp_local_port = (unsigned short)atoi(v);
        } else if (strcmp("remote_ip", keys[i]) == 0) {
            if (len <= INET_ADDRSTRLEN) {
                memcpy(conf->udp_remote_ip, v, len);
            }
        } else if (strcmp("remote_port", keys[i]) == 0) {
            conf->udp_remote_port = (unsigned short)atoi(v);
        } else if (strcmp("password", keys[i]) == 0) {
            memcpy(conf->key, v, strnlen(v, AES_128_KEY_SIZE));
        } else if (strcmp("ticket", keys[i]) == 0) {
            memcpy(conf->ticket, v, strnlen(v, SKT_TICKET_SIZE));
        } else if (strcmp("timeout", keys[i]) == 0) {
            conf->timeout = atoi(v);
        } else if (strcmp("keepalive", keys[i]) == 0) {
            conf->keepalive = atoi(v);
        } else if (strcmp("tun_ip", keys[i]) == 0) {
            if (len <= INET_ADDRSTRLEN) {
                memcpy(conf->tun_ip, v, len);
            }
        } else if (strcmp("tun_mask", keys[i]) == 0) {
            if (len <= INET_ADDRSTRLEN) {
                memcpy(conf->tun_mask, v, len);
            }
        } else if (strcmp("mtu", keys[i]) == 0) {
            conf->mtu = atoi(v);
        } else if (strcmp("kcp_interval", keys[i]) == 0) {
            conf->kcp_interval = atoi(v);
        } else if (strcmp("speed_mode", keys[i]) == 0) {
            conf->speed_mode = atoi(v);
        } else if (strcmp("log_file", keys[i]) == 0) {
            len = len > 255 ? 255 : len;
            memcpy(conf->log_file, v, len);
        } else if (strcmp("log_level", keys[i]) == 0) {
            if (strcmp(v, "DEBUG") == 0) {
                conf->log_level = SSLOG_LEVEL_DEBUG;
            } else if (strcmp(v, "INFO") == 0) {
                conf->log_level = SSLOG_LEVEL_INFO;
            } else if (strcmp(v, "NOTICE") == 0) {
                conf->log_level = SSLOG_LEVEL_NOTICE;
            } else if (strcmp(v, "WARN") == 0) {
                conf->log_level = SSLOG_LEVEL_WARN;
            } else if (strcmp(v, "ERROR") == 0) {
                conf->log_level = SSLOG_LEVEL_ERROR;
            } else {
                conf->log_level = SSLOG_LEVEL_FATAL;
            }
        }
        // printf("%s:%s\n", keys[i], v);
    }
    ssconf_free(cf);
    // printf("------------\n");
    return _OK;
}

static int check_config(skt_config_t *conf) {
    /* TODO: check all config */
    if (conf->udp_local_port > 65535) {
        fprintf(stderr, "Invalid udp_local_port:%u in configfile.\n", conf->udp_local_port);
        return _ERR;
    }
    if (conf->udp_remote_port > 65535) {
        fprintf(stderr, "Invalid udp_remote_port:%u in configfile.\n", conf->udp_remote_port);
        return _ERR;
    }
    if (conf->mode != SKT_MODE_LOCAL && conf->mode != SKT_MODE_REMOTE) {
        fprintf(stderr, "Invalid mode:%d in configfile. local mode is 'local', remote mode is 'remote'.\n", conf->mode);
        return _ERR;
    }
    if (conf->keepalive <= 0) {
        conf->keepalive = SKT_KEEPALIVE;
    }

    conf->kcp_mtu = SKT_ASSIGN_KCP_MTU(conf->mtu);
    conf->tun_mtu = SKT_ASSIGN_TUN_MTU(conf->mtu);
    return _OK;
}

static void signal_handler(int sn) {
    _LOG("signal_handler sig:%d", sn);
    // skt_monitor(g_skt);
    switch (sn) {
        // case SIGQUIT:
        // case SIGTERM:
        case SIGINT:
            g_skt->running = 0;
            break;
        case SIGUSR1:
            skt_monitor(g_skt); /* TODO: */
            break;
        default:
            break;
    }
}

int main(int argc, char const *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <config file>\n", argv[0]);
        return 1;
    }

    memset(&g_conf, 0, sizeof(skt_config_t));
    /* TODO: default config */
    // g_conf.speed_mode = 1;
    // g_conf.mtu = SKT_MTU;

    int ret = load_conf(argv[1], &g_conf);
    if (ret != _OK) return 1;
    if (check_config(&g_conf) != _OK) return 1;

    sslog_init(g_conf.log_file, g_conf.log_level);
    strcpy((char *)g_conf.iv, "bewatermyfriend.");

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, signal_handler);
    signal(SIGUSR1, signal_handler);

    g_skt = skt_init(&g_conf);
    if (!g_skt) {
        _LOG_E("init skt error.");
        goto _finish_skcptun;
    }

    skt_setup_kcp(g_skt);

    ret = g_skt->conf->mode == SKT_MODE_REMOTE ? skt_remote_start(g_skt) : skt_local_start(g_skt);
    if (ret != _OK) {
        goto _finish_skcptun;
    }
    g_skt->conf->mode == SKT_MODE_REMOTE ? skt_remote_stop(g_skt) : skt_local_stop(g_skt);
    skt_free(g_skt);

_finish_skcptun:
    sslog_free();
    printf("Bye\n");
    return 0;
}
