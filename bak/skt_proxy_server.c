#include "skt_proxy_server.h"

#include "skt_protocol.h"
#include "skt_utils.h"
#include "uthash.h"

typedef struct {
    int sfd;       // server fd
    int cfd;       // client fd
    uint32_t cid;  // connection id
    UT_hash_handle hh;
} skt_fd_entry_t;

typedef struct {
    struct ev_loop *loop;
    skcp_t *skcp;
    etcp_cli_t *etcp;
    skt_fd_entry_t *smap;
    char *target_addr;
    uint16_t target_port;
} skt_serv_t;

static skt_serv_t *g_ctx = NULL;

/* -------------------------------------------------------------------------- */
/*                                 Private API                                */
/* -------------------------------------------------------------------------- */

/* ------------------------------ fd map start ------------------------------ */
inline static skt_fd_entry_t *find_fd_entry(skt_fd_entry_t *smap, skt_fd_entry_t *cmap, int sfd, int cfd) {
    skt_fd_entry_t *map = NULL;
    int fd = 0;
    if (smap) map = smap;
    if (cmap) map = cmap;
    if (sfd) fd = sfd;
    if (cfd) fd = cfd;

    skt_fd_entry_t *en = NULL;
    HASH_FIND_INT(map, &fd, en);
    return en;
}

inline static void add_fd_entry(skt_fd_entry_t **smap, skt_fd_entry_t **cmap, int sfd, int cfd, uint32_t cid) {
    skt_fd_entry_t *en = NULL;

    skt_fd_entry_t *tmp = find_fd_entry(*smap, NULL, sfd, 0);
    if (!tmp) {
        en = (skt_fd_entry_t *)calloc(1, sizeof(skt_fd_entry_t));
        en->sfd = sfd;
        en->cfd = cfd;
        en->cid = cid;
        HASH_ADD_INT(*smap, sfd, en);
    }

    tmp = find_fd_entry(*cmap, NULL, 0, cfd);
    if (!tmp) {
        en = (skt_fd_entry_t *)calloc(1, sizeof(skt_fd_entry_t));
        en->sfd = sfd;
        en->cfd = cfd;
        en->cid = cid;
        HASH_ADD_INT(*cmap, cfd, en);
    }
}

inline static void del_fd_entry(skt_fd_entry_t **smap, skt_fd_entry_t **cmap, int sfd, int cfd) {
    skt_fd_entry_t *en = NULL;
    if (smap && *smap) {
        HASH_FIND_INT(*smap, &sfd, en);
        if (en) {
            HASH_DEL(*smap, en);
            free(en);
        }
    }

    en = NULL;
    if (cmap && *cmap) {
        HASH_FIND_INT(*cmap, &cfd, en);
        if (en) {
            HASH_DEL(*cmap, en);
            free(en);
        }
    }
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
    skt_fd_entry_t *cmap = (skt_fd_entry_t *)conn->user_data;

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

        add_fd_entry(&g_ctx->smap, &cmap, sfd, cfd, cid);
        conn->user_data = cmap;
        // TODO: test
        int smap_cnt = HASH_COUNT(g_ctx->smap);
        int cmap_cnt = HASH_COUNT(cmap);
        LOG_I("skcp cmd accept sfd: %d cfd: %d smap_cnt: %d cmap_cnt: %d", sfd, cfd, smap_cnt, cmap_cnt);

        return;
    }

    skt_fd_entry_t *entry = find_fd_entry(NULL, cmap, 0, cfd);
    if (!entry) {
        LOG_E("on_recv_seg_data find cfd_map error cfd: %d cid: %u type: %x cmd: %c", cfd, cid, seg->type, cmd);
        return;
    }

    if (cmd == SKT_MSG_CMD_CLOSE) {
        etcp_client_close_conn(g_ctx->etcp, entry->sfd, 1);
        // LOG_I("skcp cmd close sfd: %d cfd: %d", entry->sfd, cfd);
        del_fd_entry(&g_ctx->smap, &cmap, entry->sfd, entry->cfd);
        conn->user_data = cmap;
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
    skt_fd_entry_t *entry = find_fd_entry(g_ctx->smap, NULL, fd, 0);
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
    skt_fd_entry_t *entry = find_fd_entry(g_ctx->smap, NULL, fd, 0);
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

    skcp_conn_t *conn = skcp_get_conn(g_ctx->skcp, entry->cid);
    if (!conn) {
        LOG_E("on_tcp_close skcp_get_conn error sfd: %u", entry->cid);
        return;
    }

    skt_fd_entry_t *cmap = (skt_fd_entry_t *)conn->user_data;
    del_fd_entry(&g_ctx->smap, &cmap, entry->sfd, entry->cfd);
    conn->user_data = cmap;
}

/* ------------------------------ skcp callback ----------------------------- */

static void skcp_on_accept(uint32_t cid) {
    LOG_I("skcp_on_accept cid: %u", cid);
    return;
}

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
        skt_fd_entry_t *cmap = (skt_fd_entry_t *)conn->user_data;
        skt_fd_entry_t *en, *tmp;
        HASH_ITER(hh, cmap, en, tmp) {
            HASH_DEL(cmap, en);
            free(en);
        }
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
    g_ctx->smap = NULL;

    // g_ctx->ip_cid_ht = NULL;

    g_ctx->skcp = skcp_init(skcp_conf, loop, g_ctx, SKCP_MODE_SERV);
    if (NULL == g_ctx->skcp) {
        skt_proxy_server_free();
        return -1;
    };

    g_ctx->skcp->conf->on_accept = skcp_on_accept;
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

    if (g_ctx->smap) {
        skt_fd_entry_t *en, *tmp;
        HASH_ITER(hh, g_ctx->smap, en, tmp) {
            HASH_DEL(g_ctx->smap, en);
            free(en);
        }
        g_ctx->smap = NULL;
    }

    FREE_IF(g_ctx);
}