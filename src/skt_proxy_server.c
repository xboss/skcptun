#include "skt_proxy_server.h"

#include "skt_protocol.h"
#include "skt_utils.h"
#include "uthash.h"

typedef struct skt_fd_entry_s {
    int sfd;       // server fd
    int cfd;       // client fd
    uint32_t cid;  // connection id
    size_t ref_cnt;
    struct skt_fd_entry_s *next;
} skt_fd_entry_t;

typedef struct {
    skt_fd_entry_t **buckets;
    size_t bucket_cnt;
    size_t size;
} skt_fd_map_t;

typedef struct {
    struct ev_loop *loop;
    skcp_t *skcp;
    etcp_cli_t *etcp;
    skt_fd_map_t *sfd_map;
    char *target_addr;
    uint16_t target_port;
} skt_serv_t;

static skt_serv_t *g_ctx = NULL;

/* -------------------------------------------------------------------------- */
/*                                 Private API                                */
/* -------------------------------------------------------------------------- */

/* ------------------------------ fd map start ------------------------------ */

static skt_fd_map_t *fd_map_init(size_t bucket_cnt) {
    if (bucket_cnt <= 0) {
        bucket_cnt = 1000;
    }

    skt_fd_map_t *fd_map = (skt_fd_map_t *)calloc(1, sizeof(skt_fd_map_t));
    fd_map->bucket_cnt = bucket_cnt;
    fd_map->buckets = (skt_fd_entry_t **)calloc(bucket_cnt, sizeof(skt_fd_entry_t *));
    fd_map->size = 0;
    return fd_map;
}
static skt_fd_entry_t *fd_map_find(skt_fd_map_t *fd_map, int sfd, int cfd) {
    if ((sfd != 0 && cfd != 0) || (sfd == 0 && cfd == 0) || sfd < 0 || cfd < 0) {
        return NULL;
    }
    int fd = sfd;
    if (cfd > 0) {
        fd = cfd;
    }

    size_t key = fd % fd_map->bucket_cnt;
    skt_fd_entry_t *tmp = fd_map->buckets[key];
    for (size_t i = 0; tmp && i < fd_map->size; i++) {
        if (cfd > 0) {
            if (fd == tmp->cfd) {
                return tmp;
            }
        } else {
            if (fd == tmp->sfd) {
                return tmp;
            }
        }
        tmp = tmp->next;
    }
    return NULL;
}

static int fd_map_add(skt_fd_map_t *fd_map, int fd, skt_fd_entry_t *entry) {
    if (fd < 0) {
        return -1;
    }

    size_t key = fd % fd_map->bucket_cnt;
    skt_fd_entry_t *tmp = fd_map->buckets[key];
    if (!tmp) {
        fd_map->buckets[key] = entry;
        goto fd_map_add_end;
    }

    for (size_t i = 0; tmp; i++) {
        if (!tmp->next) {
            break;
        }
        tmp = tmp->next;
        if (i >= fd_map->size) {
            return -1;
        }
    }
    tmp->next = entry;

fd_map_add_end:
    entry->next = NULL;
    entry->ref_cnt++;
    fd_map->size++;
    return 0;
}

static void fd_map_free_entry(skt_fd_entry_t *entry) {
    if (!entry) {
        return;
    }
    if (entry->ref_cnt > 0) {
        entry->ref_cnt--;
    }
    if (entry->ref_cnt == 0) {
        free(entry);
    }
}

static int fd_map_del(skt_fd_map_t *fd_map, int sfd, int cfd) {
    if ((sfd != 0 && cfd != 0) || (sfd == 0 && cfd == 0) || sfd < 0 || cfd < 0) {
        return -1;
    }
    int fd = sfd;
    if (cfd > 0) {
        fd = cfd;
    }

    size_t key = fd % fd_map->bucket_cnt;
    skt_fd_entry_t *tmp = fd_map->buckets[key];
    skt_fd_entry_t *last = NULL;
    for (size_t i = 0; tmp && i < fd_map->size; i++) {
        if (cfd > 0) {
            if (fd == tmp->cfd) {
                if (last == NULL) {
                    fd_map->buckets[key] = NULL;
                } else {
                    last->next = tmp->next;
                }
                fd_map->size--;
                fd_map_free_entry(tmp);
                return 0;
            }
        } else {
            if (fd == tmp->sfd) {
                if (last == NULL) {
                    fd_map->buckets[key] = NULL;
                } else {
                    last->next = tmp->next;
                }
                fd_map->size--;
                fd_map_free_entry(tmp);
                return 0;
            }
        }
        last = tmp;
        tmp = tmp->next;
    }
    return -1;
}

static void fd_map_free(skt_fd_map_t *fd_map) {
    if (!fd_map) {
        return;
    }
    if (fd_map->bucket_cnt <= 0 || fd_map->size <= 0 || !fd_map->buckets) {
        return;
    }

    for (size_t i = 0; i < fd_map->bucket_cnt; i++) {
        skt_fd_entry_t *en = fd_map->buckets[i];
        for (size_t j = 0; en && j < fd_map->size; j++) {
            skt_fd_entry_t *tmp = en;
            en = en->next;
            fd_map_free_entry(tmp);
        }
    }

    free(fd_map->buckets);
    free(fd_map);
}
/* ------------------------------- fd map end ------------------------------- */

static void on_recv_seg_data(uint32_t cid, skt_seg_t *seg) {
    if (seg->payload_len <= 0) {
        LOG_E("proxy server on_recv_seg_data payload error cid: %u type: %x", cid, seg->type);
        return;
    }

    char cmd = '\0';
    int cfd = 0;
    char *pdata = NULL;
    int pdata_len = 0;
    if (parse_skt_msg(seg->payload, seg->payload_len, &cmd, &cfd, &pdata, &pdata_len) != 0) {
        LOG_E("proxy server parse_skt_msg error cid: %u type: %x cmd: %c", cid, seg->type, cmd);
        return;
    }

    if (cmd != SKT_MSG_CMD_DATA && cmd != SKT_MSG_CMD_ACCEPT && cmd != SKT_MSG_CMD_CLOSE) {
        LOG_E("proxy server msg cmd error cid: %u type: %x cmd: %c", cid, seg->type, cmd);
        return;
    }

    skcp_conn_t *conn = skcp_get_conn(g_ctx->skcp, cid);
    if (cmd == SKT_MSG_CMD_ACCEPT) {
        int sfd = etcp_client_create_conn(g_ctx->etcp, g_ctx->target_addr, g_ctx->target_port, NULL);
        if (sfd <= 0) {
            LOG_E("proxy server etcp_client_create_conn error cid: %u type: %x cmd: %c", cid, seg->type, cmd);
            return;
        }

        // skcp_conn_t *skcp_conn = skcp_get_conn(g_ctx->skcp, cid);
        // if (!skcp_conn) {
        //     LOG_E("proxy server skcp_get_conn error cid: %u type: %x cmd: %c", cid, seg->type, cmd);
        //     return;
        // }

        skt_fd_entry_t *en = (skt_fd_entry_t *)calloc(1, sizeof(skt_fd_entry_t));
        en->ref_cnt = 0;
        en->sfd = sfd;
        en->cfd = cfd;
        en->cid = cid;
        fd_map_add(g_ctx->sfd_map, sfd, en);
        skt_fd_map_t *cfd_map = (skt_fd_map_t *)conn->user_data;
        if (!cfd_map) {
            cfd_map = fd_map_init(0);
            conn->user_data = cfd_map;
        }
        fd_map_add(cfd_map, cfd, en);
        // LOG_I("skcp cmd accept sfd: %d cfd: %d", en->sfd, en->cfd);

        return;
    }

    skt_fd_map_t *cfd_map = (skt_fd_map_t *)conn->user_data;
    if (!cfd_map) {
        LOG_E("on_recv_seg_data cfd_map error cfd: %d", cfd);
        return;
    }
    skt_fd_entry_t *entry = fd_map_find(cfd_map, 0, cfd);
    if (!entry) {
        LOG_E("on_recv_seg_data find cfd_map error cfd: %d cid: %u type: %x cmd: %c", cfd, cid, seg->type, cmd);
        return;
    }

    if (cmd == SKT_MSG_CMD_CLOSE) {
        etcp_client_close_conn(g_ctx->etcp, entry->sfd, 1);
        // LOG_I("skcp cmd close sfd: %d cfd: %d", entry->sfd, cfd);
        fd_map_del(cfd_map, 0, cfd);
        fd_map_del(g_ctx->sfd_map, entry->sfd, 0);
        return;
    }

    if (cmd == SKT_MSG_CMD_DATA) {
        if (!pdata || pdata_len <= 0) {
            LOG_E("proxy server pdata error cid: %u type: %x cmd: %c", cid, seg->type, cmd);
            return;
        }

        int w_len = etcp_client_send(g_ctx->etcp, entry->sfd, pdata, pdata_len);
        if (w_len <= 0) {
            LOG_E("proxy server etcp_client_send error cid: %u type: %x cmd: %c", cid, seg->type, cmd);
            return;
        }
        return;
    }
}

/* ---------------------------- EasyTCP callback ---------------------------- */

static void on_tcp_recv(int fd, char *buf, int len) {
    skt_fd_entry_t *entry = fd_map_find(g_ctx->sfd_map, fd, 0);
    if (!entry) {
        LOG_E("on_tcp_recv find sfd_map error sfd: %d", fd);
        return;
    }

    char header[SKT_MSG_HEADER_MAX] = {};
    snprintf(header, SKT_MSG_HEADER_MAX, "%c\n%d\n", SKT_MSG_CMD_DATA, entry->cfd);
    int header_len = strlen(header);
    int msg_len = header_len + len;
    char *msg = (char *)calloc(1, msg_len);  // format: "cmd(1B)\nfd\ndata"
    memcpy(msg, header, header_len);
    memcpy(msg + header_len, buf, len);

    char *seg_raw = NULL;
    int seg_raw_len = 0;
    SKT_ENCODE_SEG(seg_raw, 0, SKT_SEG_DATA, msg, msg_len, seg_raw_len);
    FREE_IF(msg);
    int rt = skcp_send(g_ctx->skcp, entry->cid, seg_raw, seg_raw_len);
    FREE_IF(seg_raw);
    if (rt < 0) {
        LOG_E("skcp_send error cid: %u", entry->cid);
        return;
    }
}

static void on_tcp_close(int fd) {
    LOG_D("tcp client on_close fd: %d", fd);
    skt_fd_entry_t *entry = fd_map_find(g_ctx->sfd_map, fd, 0);
    if (!entry) {
        LOG_E("on_tcp_close find sfd_map error sfd: %d", fd);
        return;
    }

    char msg[SKT_MSG_HEADER_MAX] = {};  // format: "cmd(1B)\nfd"
    snprintf(msg, SKT_MSG_HEADER_MAX, "%c\n%d", SKT_MSG_CMD_CLOSE, fd);
    char *seg_raw = NULL;
    int seg_raw_len = 0;
    SKT_ENCODE_SEG(seg_raw, 0, SKT_SEG_DATA, msg, strlen(msg), seg_raw_len);
    int rt = skcp_send(g_ctx->skcp, entry->cid, seg_raw, seg_raw_len);
    FREE_IF(seg_raw);
    if (rt < 0) {
        LOG_E("skcp_send error cid: %u", entry->cid);
        return;
    }

    // LOG_I("on_tcp_close sfd: %d cfd: %d", entry->sfd, entry->cfd);
    fd_map_del(g_ctx->sfd_map, fd, 0);
    skcp_conn_t *conn = skcp_get_conn(g_ctx->skcp, entry->cid);
    if (!conn) {
        LOG_E("on_tcp_close skcp_get_conn error sfd: %u", entry->cid);
        return;
    }
    skt_fd_map_t *cfd_map = (skt_fd_map_t *)conn->user_data;
    if (!cfd_map) {
        LOG_E("on_tcp_close cfd_map error cfd: %d", entry->cfd);
        return;
    }
    fd_map_del(cfd_map, 0, entry->cfd);
}

/* ------------------------------ skcp callback ----------------------------- */

// static void skcp_on_accept(uint32_t cid) {
//     LOG_I("skcp_on_accept cid: %u", cid);
//     return;
// }

static void skcp_on_recv_data(uint32_t cid, char *buf, int len) {
    LOG_D("server on_recv cid: %u len: %d", cid, len);

    if (!buf || len < SKT_SEG_HEADER_LEN) {
        LOG_E("server on_recv error cid: %u len: %d", cid, len);
        return;
    }

    skt_seg_t *seg = NULL;
    SKT_DECODE_SEG(seg, buf, len);
    if (!SKT_CHECK_SEG_HEADER(seg)) {
        LOG_E("server on_recv decode seg error cid: %u len: %d", cid, len);
        FREE_IF(seg);
        return;
    }

    LOG_D("server on_recv seg type: %x", seg->type);

    if ((seg->flg & SKT_SEG_FLG_AUTH) == SKT_SEG_FLG_AUTH) {
        // TODO: auth ticket
    }

    if (seg->type == SKT_SEG_PING) {
        char *pong_seg_raw = NULL;
        int pong_seg_raw_len = 0;
        SKT_ENCODE_SEG(pong_seg_raw, 0, SKT_SEG_PONG, NULL, 0, pong_seg_raw_len);
        int rt = skcp_send(g_ctx->skcp, cid, pong_seg_raw, pong_seg_raw_len);
        FREE_IF(seg);
        FREE_IF(pong_seg_raw);
        if (rt < 0) {
            LOG_E("server on_recv send pong error cid: %u", cid);
            return;
        }
        return;
    }

    if (seg->type == SKT_SEG_DATA) {
        on_recv_seg_data(cid, seg);
        FREE_IF(seg);
        return;
    }

    FREE_IF(seg);
    return;
}

static void skcp_on_close(uint32_t cid) {
    LOG_D("skcp_on_close cid: %u", cid);
    skcp_conn_t *conn = skcp_get_conn(g_ctx->skcp, cid);
    if (conn && conn->user_data) {
        skt_fd_map_t *cfd_map = (skt_fd_map_t *)conn->user_data;
        fd_map_free(cfd_map);
        conn->user_data = NULL;
    }
    return;
}

static int skcp_on_check_ticket(char *ticket, int len) {
    // TODO: auth ticket
    return 0;
}

/* -------------------------------------------------------------------------- */
/*                                 Public API                                 */
/* -------------------------------------------------------------------------- */

int skt_proxy_server_init(skcp_conf_t *skcp_conf, etcp_cli_conf_t *etcp_conf, struct ev_loop *loop, char *target_addr,
                          uint16_t target_port) {
    g_ctx = (skt_serv_t *)calloc(1, sizeof(skt_serv_t));
    g_ctx->loop = loop;
    g_ctx->target_addr = target_addr;
    g_ctx->target_port = target_port;
    g_ctx->sfd_map = fd_map_init(0);

    // g_ctx->ip_cid_ht = NULL;

    g_ctx->skcp = skcp_init(skcp_conf, loop, g_ctx, SKCP_MODE_SERV);
    if (NULL == g_ctx->skcp) {
        skt_proxy_server_free();
        return -1;
    };

    // g_ctx->skcp->conf->on_accept = skcp_on_accept;
    g_ctx->skcp->conf->on_check_ticket = skcp_on_check_ticket;
    g_ctx->skcp->conf->on_close = skcp_on_close;
    g_ctx->skcp->conf->on_recv_data = skcp_on_recv_data;

    g_ctx->etcp = etcp_init_client(etcp_conf, loop, NULL);
    if (NULL == g_ctx->etcp) {
        skt_proxy_server_free();
        return -1;
    }
    g_ctx->etcp->conf->on_recv = on_tcp_recv;
    g_ctx->etcp->conf->on_close = on_tcp_close;

    return 0;
}

void skt_proxy_server_free() {
    if (g_ctx->skcp) {
        skcp_free(g_ctx->skcp);
    }

    if (g_ctx->etcp) {
        etcp_free_client(g_ctx->etcp);
    }

    if (g_ctx->sfd_map) {
        fd_map_free(g_ctx->sfd_map);
        g_ctx->sfd_map = NULL;
    }

    FREE_IF(g_ctx);
}