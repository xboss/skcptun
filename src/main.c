
#include <assert.h>
#include <ctype.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "skt.h"
#include "ssconf.h"


static skt_config_t g_conf;

static int load_conf(const char *conf_file, skt_config_t *conf) {
    char *keys[] = {"mode",    "listen_ip",     "listen_port", "target_ip", "target_port", "password",
                    "timeout", "read_buf_size", "log_file",    "log_level", "ticket"};
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
                conf->mode = SSPIPE_MODE_LOCAL;
            } else if (strcmp(v, "remote") == 0) {
                conf->mode = SSPIPE_MODE_REMOTE;
            } else {
                conf->mode = -1;
            }
        } else if (strcmp("listen_ip", keys[i]) == 0) {
            if (len <= INET_ADDRSTRLEN) {
                memcpy(conf->listen_ip, v, len);
            }
        } else if (strcmp("listen_port", keys[i]) == 0) {
            conf->listen_port = (unsigned short)atoi(v);
        } else if (strcmp("target_ip", keys[i]) == 0) {
            if (len <= INET_ADDRSTRLEN) {
                memcpy(conf->target_ip, v, len);
            }
        } else if (strcmp("target_port", keys[i]) == 0) {
            conf->target_port = (unsigned short)atoi(v);
        } else if (strcmp("password", keys[i]) == 0) {
            memcpy(conf->key, v, strnlen(v, AES_128_KEY_SIZE));
        } else if (strcmp("ticket", keys[i]) == 0) {
            memcpy(conf->ticket, v, strnlen(v, SSPIPE_TICKET_SIZE));
        }
        // else if (strcmp("timeout", keys[i]) == 0) {
        //     conf->timeout = atoi(v);
        // }
        else if (strcmp("read_buf_size", keys[i]) == 0) {
            conf->read_buf_size = atoi(v);
        } else if (strcmp("log_file", keys[i]) == 0) {
            conf->log_file = (char *)calloc(1, len + 1);
            if (!conf->log_file) {
                perror("alloc error");
                exit(1);
            }
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
    if (conf->listen_port > 65535) {
        fprintf(stderr, "Invalid listen_port:%u in configfile.\n", conf->listen_port);
        return _ERR;
    }
    if (conf->mode == SSPIPE_MODE_LOCAL || conf->mode == SSPIPE_MODE_REMOTE) {
        if (conf->target_port > 65535) {
            fprintf(stderr, "Invalid target_port:%u in configfile.\n", conf->target_port);
            return _ERR;
        }
    }
    if (conf->mode != SSPIPE_MODE_LOCAL && conf->mode != SSPIPE_MODE_REMOTE) {
        fprintf(stderr, "Invalid mode:%d in configfile. local mode is 'local', remote mode is 'remote'.\n", conf->mode);
        return _ERR;
    }
    return _OK;
}

static void handle_exit(int sig) {
    _LOG("exit by signal %d ... ", sig);
    sspipe_stop(g_pipe);
}

static void signal_handler(int sn) {
    _LOG("signal_handler sig:%d", sn);
    switch (sn) {
        // case SIGQUIT:
        case SIGINT:
            // case SIGTERM:
            handle_exit(sn);
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
    int rt = load_conf(argv[1], &g_conf);
    if (rt != _OK) return 1;
    if (check_config(&g_conf) != 0) return 1;
    sslog_init(g_conf.log_file, g_conf.log_level);
    if (g_conf.log_file) free(g_conf.log_file);
    strcpy((char *)g_conf.iv, "bewatermyfriend.");

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, signal_handler);

    g_pipe = sspipe_init(&g_conf);
    if (!g_pipe) {
        _LOG_E("init pipe error.");
        return 1;
    }

    rt = sspipe_start(g_pipe);
    if (rt != _OK) {
        _LOG_E("start server error.");
    }

    sspipe_free(g_pipe);
    sslog_free();
    printf("Bye\n");
    return 0;
}
