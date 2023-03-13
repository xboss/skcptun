#include "skt_proxy_server.h"

#include "skt_protocol.h"
#include "skt_utils.h"
#include "uthash.h"

typedef struct {
    int sfd;  // server fd
    int cfd;  // client fd
    uint32_t cid;
    UT_hash_handle hh;
} skt_cp_ht_t;

typedef struct {
    struct ev_loop *loop;
    skcp_t *skcp;
    etcp_cli_t *etcp;
    skt_cp_ht_t *s2c_ht;
    skt_cp_ht_t *c2s_ht;
    char *target_addr;
    uint16_t target_port;
} skt_serv_t;

static skt_serv_t *g_ctx = NULL;

/* -------------------------------------------------------------------------- */
/*                                 Private API                                */
/* -------------------------------------------------------------------------- */

inline static void add_cp_ht(int sfd, uint32_t cid, int cfd) {
    skt_cp_ht_t *cp = NULL;
    HASH_FIND_INT(g_ctx->s2c_ht, &sfd, cp);
    if (cp == NULL) {
        cp = (skt_cp_ht_t *)malloc(sizeof(skt_cp_ht_t));
        cp->sfd = sfd;
        HASH_ADD_INT(g_ctx->s2c_ht, sfd, cp);
    }
    cp->cfd = cfd;
    cp->cid = cid;

    cp = NULL;
    HASH_FIND_INT(g_ctx->c2s_ht, &cfd, cp);
    if (cp == NULL) {
        cp = (skt_cp_ht_t *)malloc(sizeof(skt_cp_ht_t));
        cp->cfd = cfd;
        HASH_ADD_INT(g_ctx->c2s_ht, cfd, cp);
    }
    cp->sfd = sfd;
    cp->cid = cid;
}

inline static void del_cp_ht(int sfd, int cfd) {
    skt_cp_ht_t *cp = NULL;

    if (sfd > 0) {
        HASH_FIND_INT(g_ctx->s2c_ht, &sfd, cp);
        if (cp) {
            HASH_DEL(g_ctx->s2c_ht, cp);
            FREE_IF(cp);
        }
    }

    if (cfd > 0) {
        cp = NULL;
        HASH_FIND_INT(g_ctx->c2s_ht, &cfd, cp);
        if (cp) {
            HASH_DEL(g_ctx->c2s_ht, cp);
            FREE_IF(cp);
        }
    }
}

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

    // skcp_conn_t *conn = skcp_get_conn(g_ctx->skcp, cid);
    skt_cp_ht_t *cp = NULL;
    if (cmd == SKT_MSG_CMD_ACCEPT) {
        int sfd = etcp_client_create_conn(g_ctx->etcp, g_ctx->target_addr, g_ctx->target_port, NULL);
        if (sfd <= 0) {
            LOG_E("proxy server etcp_client_create_conn error cid: %u type: %x cmd: %c", cid, seg->type, cmd);
            return;
        }

        add_cp_ht(sfd, cid, cfd);
        LOG_I("proxy server etcp_client_create_conn ok fd: %d cid: %u type: %x cmd: %c", sfd, cid, seg->type, cmd);
        return;
    }

    if (cmd == SKT_MSG_CMD_CLOSE) {
        HASH_FIND_INT(g_ctx->c2s_ht, &cfd, cp);
        if (!cp) {
            LOG_E("proxy server find c2s_ht error cfd: %d cid: %u type: %x cmd: %c", cfd, cid, seg->type, cmd);
            return;
        }

        etcp_client_close_conn(g_ctx->etcp, cp->sfd, 1);
        del_cp_ht(cp->sfd, 0);
    }

    if (cmd == SKT_MSG_CMD_DATA) {
        if (!pdata || pdata_len <= 0) {
            LOG_E("proxy server pdata error cid: %u type: %x cmd: %c", cid, seg->type, cmd);
            return;
        }

        HASH_FIND_INT(g_ctx->c2s_ht, &cfd, cp);
        if (!cp) {
            LOG_E("proxy server find c2s_ht error cfd: %d cid: %u type: %x cmd: %c", cfd, cid, seg->type, cmd);
            return;
        }

        int w_len = etcp_client_send(g_ctx->etcp, cp->sfd, pdata, pdata_len);
        if (w_len <= 0) {
            LOG_E("proxy server etcp_client_send error cid: %u type: %x cmd: %c", cid, seg->type, cmd);
            return;
        }
        return;
    }
}

/* ---------------------------- EasyTCP callback ---------------------------- */

static void on_tcp_recv(int fd, char *buf, int len) {
    skt_cp_ht_t *cp = NULL;
    HASH_FIND_INT(g_ctx->s2c_ht, &fd, cp);
    if (!cp) {
        LOG_E("on_tcp_recv find s2c error sfd: %d", fd);
        return;
    }

    char header[SKT_MSG_HEADER_MAX] = {};
    snprintf(header, SKT_MSG_HEADER_MAX, "%c\n%d\n", SKT_MSG_CMD_DATA, cp->cfd);
    int header_len = strlen(header);
    int msg_len = header_len + len;
    char *msg = (char *)calloc(1, msg_len);  // format: "cmd(1B)\nfd\ndata"
    memcpy(msg, header, header_len);
    memcpy(msg + header_len, buf, len);

    char *seg_raw = NULL;
    int seg_raw_len = 0;
    SKT_ENCODE_SEG(seg_raw, 0, SKT_SEG_DATA, msg, msg_len, seg_raw_len);
    int rt = skcp_send(g_ctx->skcp, cp->cid, seg_raw, seg_raw_len);
    FREE_IF(seg_raw);
    if (rt < 0) {
        LOG_E("skcp_send error cid: %u", cp->cid);
        return;
    }
}

static void on_tcp_close(int fd) {
    LOG_D("tcp client on_close fd: %d", fd);

    skt_cp_ht_t *cp = NULL;
    HASH_FIND_INT(g_ctx->s2c_ht, &fd, cp);
    if (!cp) {
        LOG_E("on_tcp_close find s2c error sfd: %d", fd);
        return;
    }

    char msg[SKT_MSG_HEADER_MAX] = {};  // format: "cmd(1B)\nfd"
    snprintf(msg, SKT_MSG_HEADER_MAX, "%c\n%d", SKT_MSG_CMD_CLOSE, fd);
    char *seg_raw = NULL;
    int seg_raw_len = 0;
    SKT_ENCODE_SEG(seg_raw, 0, SKT_SEG_DATA, msg, strlen(msg), seg_raw_len);
    int rt = skcp_send(g_ctx->skcp, cp->cid, seg_raw, seg_raw_len);
    FREE_IF(seg_raw);
    if (rt < 0) {
        LOG_E("skcp_send error cid: %u", cp->cid);
        return;
    }
    LOG_I("on_tcp_close msg: %s", msg);

    del_cp_ht(fd, 0);
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
    // skcp_conn_t *conn = skcp_get_conn(g_ctx->skcp, cid);
    // if (conn && conn->user_data) {
    //     skt_fd_cid_ht_t *fc = (skt_fd_cid_ht_t *)conn->user_data;
    //     del_fd_cid_ht(fc);
    // }
    return;
}

static int skcp_on_check_ticket(char *ticket, int len) {
    // TODO:
    return 0;
}

/* -------------------------------------------------------------------------- */
/*                                 Public API                                 */
/* -------------------------------------------------------------------------- */

int skt_proxy_server_init(skcp_conf_t *skcp_conf, etcp_cli_conf_t *etcp_conf, struct ev_loop *loop, char *target_addr,
                          uint16_t target_port) {
    // TODO:
    g_ctx = (skt_serv_t *)calloc(1, sizeof(skt_serv_t));
    g_ctx->loop = loop;
    g_ctx->target_addr = target_addr;
    g_ctx->target_port = target_port;
    g_ctx->c2s_ht = NULL;
    g_ctx->s2c_ht = NULL;

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

    skt_cp_ht_t *cp = NULL, *tmp = NULL;
    if (g_ctx->s2c_ht) {
        HASH_ITER(hh, g_ctx->s2c_ht, cp, tmp) {
            HASH_DEL(g_ctx->s2c_ht, cp);
            FREE_IF(cp);
        }
    }

    cp = NULL;
    tmp = NULL;
    if (g_ctx->c2s_ht) {
        HASH_ITER(hh, g_ctx->c2s_ht, cp, tmp) {
            HASH_DEL(g_ctx->c2s_ht, cp);
            FREE_IF(cp);
        }
    }

    FREE_IF(g_ctx);
}