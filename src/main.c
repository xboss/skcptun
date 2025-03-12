
#include <assert.h>
#include <ctype.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "skcptun.h"
#include "skt.h"
#include "skt_local.h"
#include "skt_remote.h"
#include "ssconf.h"

static skt_config_t g_conf;
static skcptun_t *g_skt = NULL;
struct ev_loop *g_loop = NULL;

static int load_conf(const char *conf_file, skt_config_t *conf) {
    char *keys[] = {"mode",    "local_ip", "local_port",   "remote_ip", "remote_port", "password",
                    "ticket",  "log_file", "log_level",    "timeout",   "tun_ip",      "tun_mask",
                    "tun_mtu", "kcp_mtu",  "kcp_interval", "speed_mode"};
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
        } else if (strcmp("tun_ip", keys[i]) == 0) {
            if (len <= INET_ADDRSTRLEN) {
                memcpy(conf->tun_ip, v, len);
            }
        } else if (strcmp("tun_mask", keys[i]) == 0) {
            if (len <= INET_ADDRSTRLEN) {
                memcpy(conf->tun_mask, v, len);
            }
        } else if (strcmp("tun_mtu", keys[i]) == 0) {
            conf->tun_mtu = atoi(v);
        } else if (strcmp("kcp_mtu", keys[i]) == 0) {
            conf->kcp_mtu = atoi(v);
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
        printf("%s:%s\n", keys[i], v);
    }
    ssconf_free(cf);
    printf("------------\n");
    return _OK;
}

static int check_config(skt_config_t *conf) {
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
    if (conf->tun_mtu + SKT_TICKET_SIZE + SKT_PKT_CMD_SZIE > conf->kcp_mtu || conf->kcp_mtu > SKT_MTU) {
        fprintf(stderr, "MTU error.\n");
        return _ERR;
    }
    return _OK;
}

static void signal_handler(int sn) {
    _LOG("signal_handler sig:%d", sn);
    switch (sn) {
        // case SIGQUIT:
        case SIGINT:
            // case SIGTERM:
            g_skt->running = 0;
            ev_break(g_loop, EVBREAK_ALL);
            exit(1); /* TODO: remove it */
            break;
        default:
            break;
    }
}

static void setup_kcp() {
    g_conf.kcp_rcvwnd = 32;
    g_conf.kcp_sndwnd = 32;
    if (g_conf.speed_mode != 0) {
        g_conf.kcp_nodelay = 1;
        g_conf.kcp_resend = 2;
        g_conf.kcp_nc = 1;
    } else {
        g_conf.kcp_nodelay = g_conf.kcp_resend = g_conf.kcp_nc = 0;
    }
}

int main(int argc, char const *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <config file>\n", argv[0]);
        return 1;
    }
    memset(&g_conf, 0, sizeof(skt_config_t));
    int ret = load_conf(argv[1], &g_conf);
    if (ret != _OK) return 1;
    if (check_config(&g_conf) != _OK) return 1;

    sslog_init(g_conf.log_file, g_conf.log_level);
    strcpy((char *)g_conf.iv, "bewatermyfriend.");

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, signal_handler);

    g_loop = EV_DEFAULT;

    setup_kcp();
    g_skt = skt_init(&g_conf, g_loop);
    if (!g_skt) {
        _LOG_E("init skt error.");
        return 1;
    }

    ret = g_skt->conf->mode == SKT_MODE_REMOTE ? skt_remote_start(g_skt) : skt_local_start(g_skt);
    if (ret != _OK) {
        return 1;
    }
    ev_run(g_loop, 0);
    g_skt->conf->mode == SKT_MODE_REMOTE ? skt_remote_stop(g_skt) : skt_local_stop(g_skt);
    skt_free(g_skt);
    sslog_free();
    printf("Bye\n");
    return 0;
}
