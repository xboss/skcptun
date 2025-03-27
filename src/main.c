
#include <assert.h>
#include <ctype.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "skt_local.h"
#include "skt_remote.h"
#include "ssconfig.h"

static skt_config_t g_conf;
static skcptun_t *g_skt = NULL;

static int check_config(skt_config_t *conf) {
    if (conf->mode != SKT_MODE_LOCAL && conf->mode != SKT_MODE_REMOTE) {
        fprintf(stderr, "Invalid mode:%d in configfile. local mode is 'local', remote mode is'remote'.\n", conf->mode);
        return _ERR;
    }
    if (conf->ticket[0] == '\0' || conf->ticket[SKT_TICKET_SIZE] != '\0') {
        fprintf(stderr, "Invalid ticket in configfile.\n");
        return _ERR;
    }
    if (conf->udp_local_port > 65535) {
        fprintf(stderr, "Invalid udp_local_port:%u in configfile.\n", conf->udp_local_port);
        return _ERR;
    }
    if (conf->udp_remote_port > 65535) {
        fprintf(stderr, "Invalid udp_remote_port:%u in configfile.\n", conf->udp_remote_port);
        return _ERR;
    }
    if (conf->mode == SKT_MODE_REMOTE && conf->udp_local_ip[0] == '\0') {
        fprintf(stderr, "Invalid udp_local_ip in configfile.\n");
        return _ERR;
    }
    if (conf->mode == SKT_MODE_LOCAL && conf->udp_remote_ip[0] == '\0') {
        fprintf(stderr, "Invalid udp_remote_ip in configfile.\n");
        return _ERR;
    }
    if (conf->tun_ip[0] == '\0') {
        fprintf(stderr, "Invalid tun_ip in configfile.\n");
        return _ERR;
    }
    if (conf->tun_mask[0] == '\0') {
        fprintf(stderr, "Invalid tun_mask in configfile.\n");
        return _ERR;
    }
    if (conf->kcp_sndwnd > 1024) {
        fprintf(stderr, "Invalid kcp_sndwnd:%d in configfile.\n", conf->kcp_sndwnd);
        return _ERR;
    }
    if (conf->kcp_rcvwnd > 1024) {
        fprintf(stderr, "Invalid kcp_rcvwnd:%d in configfile.\n", conf->kcp_rcvwnd);
        return _ERR;
    }
    // set default values
    if (conf->ping_interval <= 0) {
        conf->ping_interval = SKT_PING_INTERVAL;
    }
    if (conf->mtu <= 0) {
        conf->mtu = SKT_MTU;
    }
    if (conf->kcp_interval <= 0) {
        conf->kcp_interval = SKT_KCP_INTERVAL;
    }
    if (conf->speed_mode < 0 || conf->speed_mode > 2) {
        conf->speed_mode = 1;
    }
    if (conf->keepalive <= 0) {
        conf->keepalive = SKT_KEEPALIVE;
    }
    conf->kcp_mtu = SKT_ASSIGN_KCP_MTU(conf->mtu);
    conf->tun_mtu = SKT_ASSIGN_TUN_MTU(conf->mtu);
    return _OK;
}

int config_handler(const char *key, const char *value, size_t line_no, void *user) {
    skt_config_t *conf = (skt_config_t *)user;
    assert(conf);
    // {"mode",      "local_ip",      "local_port", "remote_ip", "remote_port", "password",     "ticket", "log_file",
    //  "log_level", "ping_interval", "tun_ip",     "tun_mask",  "mtu",         "kcp_interval", "speed_mode",
    //  "keepalive"};
    if (strcmp("mode", key) == 0) {
        if (strcmp(value, "local") == 0) {
            conf->mode = SKT_MODE_LOCAL;
        } else if (strcmp(value, "remote") == 0) {
            conf->mode = SKT_MODE_REMOTE;
        } else {
            conf->mode = -1;
        }
    } else if (strcmp("local_ip", key) == 0) {
        if (strlen(value) <= INET_ADDRSTRLEN) {
            memcpy(conf->udp_local_ip, value, strlen(value));
        }
    } else if (strcmp("local_port", key) == 0) {
        conf->udp_local_port = (unsigned short)atoi(value);
    } else if (strcmp("remote_ip", key) == 0) {
        if (strlen(value) <= INET_ADDRSTRLEN) {
            memcpy(conf->udp_remote_ip, value, strlen(value));
        }
    } else if (strcmp("remote_port", key) == 0) {
        conf->udp_remote_port = (unsigned short)atoi(value);
    } else if (strcmp("password", key) == 0) {
        memcpy(conf->key, value, strnlen(value, AES_128_KEY_SIZE));
    } else if (strcmp("ticket", key) == 0) {
        memcpy(conf->ticket, value, strnlen(value, SKT_TICKET_SIZE));
    } else if (strcmp("ping_interval", key) == 0) {
        conf->ping_interval = atoi(value);
    } else if (strcmp("keepalive", key) == 0) {
        conf->keepalive = atoi(value);
    } else if (strcmp("tun_ip", key) == 0) {
        if (strlen(value) <= INET_ADDRSTRLEN) {
            memcpy(conf->tun_ip, value, strlen(value));
        }
    } else if (strcmp("tun_mask", key) == 0) {
        if (strlen(value) <= INET_ADDRSTRLEN) {
            memcpy(conf->tun_mask, value, strlen(value));
        }
    } else if (strcmp("mtu", key) == 0) {
        conf->mtu = atoi(value);
    } else if (strcmp("kcp_interval", key) == 0) {
        conf->kcp_interval = atoi(value);
    } else if (strcmp("speed_mode", key) == 0) {
        conf->speed_mode = atoi(value);
    } else if (strcmp("log_file", key) == 0) {
        int len = strlen(value);
        len = len > 255 ? 255 : len;
        memcpy(conf->log_file, value, len);
    } else if (strcmp("log_level", key) == 0) {
        if (strcmp(value, "DEBUG") == 0) {
            conf->log_level = SSLOG_LEVEL_DEBUG;
        } else if (strcmp(value, "INFO") == 0) {
            conf->log_level = SSLOG_LEVEL_INFO;
        } else if (strcmp(value, "NOTICE") == 0) {
            conf->log_level = SSLOG_LEVEL_NOTICE;
        } else if (strcmp(value, "WARN") == 0) {
            conf->log_level = SSLOG_LEVEL_WARN;
        } else if (strcmp(value, "ERROR") == 0) {
            conf->log_level = SSLOG_LEVEL_ERROR;
        } else {
            conf->log_level = SSLOG_LEVEL_FATAL;
        }
    } else {
        fprintf(stderr, "Invalid key '%s' in configfile at line %zu.\n", key, line_no);
        return _ERR;
    }
    printf("%s=%s\n", key, value);
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
    int ret = sscf_parse(argv[1], config_handler, &g_conf);
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
