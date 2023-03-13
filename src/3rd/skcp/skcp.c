#include "skcp.h"

#include <assert.h>
#include <fcntl.h>
#include <openssl/aes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define _ALLOC(element_size) calloc(1, element_size)

#define _FREEIF(p)    \
    do {              \
        if (p) {      \
            free(p);  \
            p = NULL; \
        }             \
    } while (0)

#define _LOG(fmt, args...)   \
    do {                     \
        printf(fmt, ##args); \
        printf("\n");        \
    } while (0)

/* -------------------------------------------------------------------------- */
/*                               common function                              */
/* -------------------------------------------------------------------------- */
inline static uint64_t getmillisecond() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t millisecond = (tv.tv_sec * 1000000l + tv.tv_usec) / 1000l;
    return millisecond;
}

/* -------------------------------------------------------------------------- */
/*                                   cipher                                   */
/* -------------------------------------------------------------------------- */

inline static unsigned char *str2hex(const char *str) {
    unsigned char *ret = NULL;
    int str_len = strlen(str);
    int i = 0;
    assert((str_len % 2) == 0);
    ret = malloc(str_len / 2);
    for (i = 0; i < str_len; i = i + 2) {
        sscanf(str + i, "%2hhx", &ret[i / 2]);
    }
    return ret;
}

inline static char *cipher_padding(const char *buf, int size, int *final_size) {
    char *ret = NULL;
    int pidding_size = AES_BLOCK_SIZE - (size % AES_BLOCK_SIZE);
    int i;
    *final_size = size + pidding_size;
    ret = (char *)malloc(size + pidding_size);
    memcpy(ret, buf, size);
    if (pidding_size != 0) {
        for (i = size; i < (size + pidding_size); i++) {
            ret[i] = 0;
        }
    }
    return ret;
}

inline static void aes_cbc_encrpyt(const char *raw_buf, char **encrpy_buf, int len, const char *key, const char *iv) {
    AES_KEY aes_key;
    unsigned char *skey = str2hex(key);
    unsigned char *siv = str2hex(iv);
    AES_set_encrypt_key(skey, 128, &aes_key);
    AES_cbc_encrypt((unsigned char *)raw_buf, (unsigned char *)*encrpy_buf, len, &aes_key, siv, AES_ENCRYPT);
    _FREEIF(skey);
    _FREEIF(siv);
}
inline static void aes_cbc_decrypt(const char *raw_buf, char **encrpy_buf, int len, const char *key, const char *iv) {
    AES_KEY aes_key;
    unsigned char *skey = str2hex(key);
    unsigned char *siv = str2hex(iv);
    AES_set_decrypt_key(skey, 128, &aes_key);
    AES_cbc_encrypt((unsigned char *)raw_buf, (unsigned char *)*encrpy_buf, len, &aes_key, siv, AES_DECRYPT);
    _FREEIF(skey);
    _FREEIF(siv);
}
inline static char *aes_encrypt(const char *key, const char *iv, const char *in, int in_len, int *out_len) {
    int padding_size = in_len;
    char *after_padding_buf = (char *)in;
    if (in_len % 16 != 0) {
        after_padding_buf = cipher_padding(in, in_len, &padding_size);
    }
    *out_len = padding_size;

    char *out_buf = malloc(padding_size);
    memset(out_buf, 0, padding_size);
    aes_cbc_encrpyt(after_padding_buf, &out_buf, padding_size, key, iv);
    if (in_len % 16 != 0) {
        _FREEIF(after_padding_buf);
    }
    return out_buf;
}

static char *aes_decrypt(const char *key, const char *iv, const char *in, int in_len, int *out_len) {
    int padding_size = in_len;
    char *after_padding_buf = (char *)in;
    if (in_len % 16 != 0) {
        after_padding_buf = cipher_padding(in, in_len, &padding_size);
    }
    *out_len = padding_size;

    char *out_buf = malloc(padding_size);
    memset(out_buf, 0, padding_size);
    aes_cbc_decrypt(after_padding_buf, &out_buf, padding_size, key, iv);
    if (in_len % 16 != 0) {
        _FREEIF(after_padding_buf);
    }
    return out_buf;
}

/* -------------------------------------------------------------------------- */
/*                                  protocol                                  */
/* -------------------------------------------------------------------------- */

#define SKCP_CMD_REQ_CID 0x01
#define SKCP_CMD_REQ_CID_ACK 0x02
// #define SKCP_CMD_REQ_CID_COMP 0x02
#define SKCP_CMD_DATA 0x03
// #define SKCP_CMD_PING 0x04
// #define SKCP_CMD_PONG 0x05
// #define SKCP_CMD_CLOSE 0x06
// #define SKCP_CMD_CLOSE_ACK 0x07

#define SKCP_CMD_HEADER_LEN 9

typedef struct {
    uint32_t id;
    char type;
    uint32_t payload_len;
    char payload[0];
} skcp_cmd_t;

inline static char *encode_cmd(uint32_t id, char type, const char *buf, int len, int *out_len) {
    char *raw = (char *)_ALLOC(SKCP_CMD_HEADER_LEN + len);
    uint32_t nid = htonl(id);
    memcpy(raw, &nid, 4);
    *(raw + 4) = type;
    uint32_t payload_len = htonl(len);
    memcpy(raw + 5, &payload_len, 4);
    if (len > 0) {
        memcpy(raw + SKCP_CMD_HEADER_LEN, buf, len);
    }
    *out_len = len + SKCP_CMD_HEADER_LEN;

    return raw;
}

inline static skcp_cmd_t *decode_cmd(const char *buf, int len) {
    skcp_cmd_t *cmd = (skcp_cmd_t *)_ALLOC(sizeof(skcp_cmd_t) + (len - SKCP_CMD_HEADER_LEN));
    // _LOG("decode_cmd len: %d", len);
    cmd->id = ntohl(*(uint32_t *)buf);
    cmd->type = *(buf + 4);
    cmd->payload_len = ntohl(*(uint32_t *)(buf + 5));
    if (len > SKCP_CMD_HEADER_LEN) {
        memcpy(cmd->payload, buf + SKCP_CMD_HEADER_LEN, cmd->payload_len);
    }
    // _LOG("decode_cmd len: %d %lu", len, sizeof(*cmd));

    return cmd;
}

/* -------------------------------------------------------------------------- */
/*                              connection slots                              */
/* -------------------------------------------------------------------------- */

static skcp_conn_slots_t *init_conn_slots(uint32_t max_conns) {
    skcp_conn_slots_t *slots = (skcp_conn_slots_t *)_ALLOC(sizeof(skcp_conn_slots_t));
    slots->max_cnt = max_conns > 0 ? max_conns : SKCP_MAX_CONNS;
    slots->remain_cnt = slots->max_cnt;
    slots->conns = (skcp_conn_t **)_ALLOC(slots->max_cnt * sizeof(skcp_conn_t));
    slots->remain_id_stack = (uint32_t *)_ALLOC(slots->max_cnt * sizeof(uint32_t));
    for (uint32_t i = 0; i < slots->max_cnt; i++) {
        slots->remain_id_stack[i] = i + 1;
    }
    slots->remain_idx = 0;
    return slots;
}

static void free_conn_slots(skcp_conn_slots_t *slots) {
    if (!slots) {
        return;
    }
    _FREEIF(slots->conns);
    _FREEIF(slots->remain_id_stack);
    _FREEIF(slots);
}

inline static skcp_conn_t *get_conn_from_slots(skcp_conn_slots_t *slots, uint32_t cid) {
    if (slots == NULL || cid <= 0 || cid > slots->max_cnt) {
        return NULL;
    }
    return slots->conns[cid - 1];
}

// 借一个连接id，仅供slots内部使用，失败返回0，成功返回cid
inline static uint32_t borrow_cid(skcp_conn_slots_t *slots) {
    if (!slots || !slots->remain_id_stack || slots->remain_cnt <= 0 || slots->remain_cnt > slots->max_cnt ||
        slots->remain_idx > (slots->max_cnt - 1) || slots->remain_idx < 0) {
        return 0;
    }
    uint32_t cid = slots->remain_id_stack[slots->remain_idx];
    slots->remain_idx++;
    slots->remain_cnt--;
    return cid;
}

// 归还一个连接id，仅供slots内部使用，失败返回-1，成功返回0
inline static int return_cid(skcp_conn_slots_t *slots, uint32_t cid) {
    if (!slots || !slots->remain_id_stack || slots->remain_cnt < 0 || slots->remain_cnt >= slots->max_cnt ||
        slots->remain_idx > slots->max_cnt || slots->remain_idx <= 0 || cid <= 0) {
        return -1;
    }
    slots->remain_idx--;
    slots->remain_id_stack[slots->remain_idx] = cid;
    slots->remain_cnt++;
    return 0;
}

// 添加一个新连接到slots，注意此时传进来的conn中的cid并没有生成，失败返回0，成功返回cid
static uint32_t add_new_conn_to_slots(skcp_conn_slots_t *slots, skcp_conn_t *conn) {
    if (!slots || !conn) {
        return 0;
    }
    conn->id = borrow_cid(slots);
    if (conn->id <= 0) {
        return 0;
    }

    uint32_t i = conn->id - 1;
    if (slots->conns[i] != NULL) {
        return_cid(slots, conn->id);
        return 0;
    }
    slots->conns[i] = conn;
    return conn->id;
}

// 覆盖一个连接到slots，失败返回0，成功返回cid
static uint32_t replace_conn_to_slots(skcp_conn_slots_t *slots, skcp_conn_t *conn) {
    if (!slots || !conn || conn->id <= 0) {
        return 0;
    }

    slots->conns[conn->id - 1] = conn;
    return conn->id;
}

// 从slots中删除一个连接，并且归还cid，失败返回-1，成功返回0
static int del_conn_from_slots(skcp_conn_slots_t *slots, uint32_t cid) {
    if (!slots || cid <= 0) {
        return -1;
    }
    // int rt = return_cid(slots, cid);
    // if (rt != 0) {
    //     return -1;
    // }
    return_cid(slots, cid);
    slots->conns[cid - 1] = NULL;

    return 0;
}

/* -------------------------------------------------------------------------- */
/*                                    skcp                                    */
/* -------------------------------------------------------------------------- */

/* ------------------------------- definitions ------------------------------- */
static char *def_iv = "9586cda28238ab24c8a484df6e355f90";

/* ------------------------------- private api ------------------------------ */

// TODO: 可优化，有可能生成一样的iv
inline static void rand_iv(char *iv) {
    if (!iv) {
        return;
    }

    char s[] = "0123456789abcdef";
    srand((unsigned)time(NULL));
    for (size_t i = 0; i < SKCP_IV_LEN; i++) {
        int j = rand() % 16;
        if (i == 0 && j == 0) {
            j = rand() % 15 + 1;
        }
        iv[i] = s[j];
    }
}

static int init_cli_network(skcp_t *skcp) {
    // 设置客户端
    // 创建socket对象
    skcp->fd = socket(AF_INET, SOCK_DGRAM, 0);
    // 设置为非阻塞
    if (-1 == fcntl(skcp->fd, F_SETFL, fcntl(skcp->fd, F_GETFL) | O_NONBLOCK)) {
        _LOG("error fcntl");
        close(skcp->fd);
        return -1;
    }

    skcp->servaddr.sin_family = AF_INET;
    skcp->servaddr.sin_port = htons(skcp->conf->port);
    skcp->servaddr.sin_addr.s_addr = inet_addr(skcp->conf->addr);

    _LOG("kcp client start ok. fd: %d addr: %s port: %u", skcp->fd, skcp->conf->addr, skcp->conf->port);

    return 0;
}

static int init_serv_network(skcp_t *skcp) {
    // 设置服务端
    skcp->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (-1 == skcp->fd) {
        _LOG("start kcp server socket error");
        return -1;
    }
    // 设置为非阻塞
    if (-1 == fcntl(skcp->fd, F_SETFL, fcntl(skcp->fd, F_GETFL) | O_NONBLOCK)) {
        perror("setnonblock error");
    }

    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    if (NULL == skcp->conf->addr) {
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        servaddr.sin_addr.s_addr = inet_addr(skcp->conf->addr);
    }
    servaddr.sin_port = htons(skcp->conf->port);

    if (-1 == bind(skcp->fd, (struct sockaddr *)&servaddr, sizeof(servaddr))) {
        _LOG("bind error when start kcp server");
        close(skcp->fd);
        return -1;
    }

    _LOG("kcp server start ok. fd: %d addr: %s port: %u", skcp->fd, skcp->conf->addr, skcp->conf->port);

    return 0;
}

inline static int udp_send(skcp_t *skcp, const char *buf, int len, struct sockaddr_in dest_addr) {
    if (!buf || len <= 0) {
        return -1;
    }

    // 加密
    char *cipher_buf = NULL;
    int cipher_buf_len = 0;
    if (strlen(skcp->conf->key) > 0) {
        cipher_buf = aes_encrypt(skcp->conf->key, def_iv, buf, len, &cipher_buf_len);
    }

    int rt = sendto(skcp->fd, cipher_buf, cipher_buf_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    _FREEIF(cipher_buf);
    if (rt < 0) {
        perror("udp send error");
    }

    return rt;
}

static int kcp_output(const char *buf, int len, struct IKCPCB *kcp, void *user) {
    skcp_conn_t *conn = (skcp_conn_t *)user;

    int rt = udp_send(conn->skcp, buf, len, conn->dest_addr);
    if (rt > 0) {
        conn->last_w_tm = getmillisecond();
    }

    return rt;
}

static void free_conn(skcp_t *skcp, skcp_conn_t *conn) {
    if (!skcp || !conn) {
        return;
    }

    if (skcp->conn_slots) {
        int rt = del_conn_from_slots(skcp->conn_slots, conn->id);
        if (rt != 0) {
            _LOG("del_conn_from_slots error cid: %u", conn->id);
        }
    }

    if (conn->kcp) {
        ikcp_release(conn->kcp);
        conn->kcp = NULL;
    }

    if (conn->timeout_watcher) {
        ev_timer_stop(skcp->loop, conn->timeout_watcher);
        _FREEIF(conn->timeout_watcher);
    }

    if (conn->kcp_update_watcher) {
        ev_timer_stop(skcp->loop, conn->kcp_update_watcher);
        _FREEIF(conn->kcp_update_watcher);
    }

    conn->status = SKCP_CONN_ST_OFF;
    conn->id = 0;
    conn->user_data = NULL;

    _FREEIF(conn);
}

static void kcp_update_cb(struct ev_loop *loop, ev_timer *watcher, int revents) {
    if (EV_ERROR & revents) {
        _LOG("kcp update got invalid event");
        return;
    }
    skcp_conn_t *conn = (skcp_conn_t *)(watcher->data);
    ikcp_update(conn->kcp, clock());
}

static void conn_timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents) {
    if (EV_ERROR & revents) {
        _LOG("timeout_cb got invalid event");
        return;
    }
    skcp_conn_t *conn = (skcp_conn_t *)(watcher->data);
    uint64_t now = getmillisecond();
    // TODO:
    if (now - conn->last_r_tm > conn->skcp->conf->r_keepalive * 1000) {
        _LOG("timeout cid: %u", conn->id);
        skcp_close_conn(conn->skcp, conn->id);
        return;
    }
    // if (conn->status == SKCP_CONN_ST_READY && conn->estab_tm - now > conn->skcp->conf->estab_timeout) {
    //     skcp_close_conn(conn->skcp, conn->id);
    //     return;
    // }
}

static skcp_conn_t *init_conn(skcp_t *skcp, int32_t cid) {
    assert(skcp);
    skcp_conn_t *conn = (skcp_conn_t *)_ALLOC(sizeof(skcp_conn_t));
    conn->last_r_tm = conn->last_w_tm = conn->estab_tm = getmillisecond();
    conn->status = SKCP_CONN_ST_ON;  // SKCP_CONN_ST_READY;
    conn->skcp = skcp;
    conn->user_data = NULL;  // 在accept阶段初始化
    if (skcp->mode == SKCP_MODE_CLI) {
        conn->dest_addr = skcp->servaddr;
    }

    // conn->waiting_buf_q = NULL;

    if (cid <= 0) {
        cid = add_new_conn_to_slots(skcp->conn_slots, conn);
        if (cid == 0) {
            free_conn(skcp, conn);
            return NULL;
        }
    } else {
        conn->id = cid;
        if (replace_conn_to_slots(skcp->conn_slots, conn) == 0) {
            free_conn(skcp, conn);
            return NULL;
        }
    }

    ikcpcb *kcp = ikcp_create(cid, conn);
    skcp_conf_t *conf = skcp->conf;
    kcp->output = kcp_output;
    ikcp_wndsize(kcp, conf->sndwnd, conf->rcvwnd);
    ikcp_nodelay(kcp, conf->nodelay, conf->interval, conf->nodelay, conf->nc);
    ikcp_setmtu(kcp, conf->mtu);
    conn->kcp = kcp;

    // 设置kcp定时循环
    conn->kcp_update_watcher = malloc(sizeof(ev_timer));
    double kcp_interval = conf->interval / 1000.0;
    conn->kcp_update_watcher->data = conn;
    ev_init(conn->kcp_update_watcher, kcp_update_cb);
    ev_timer_set(conn->kcp_update_watcher, kcp_interval, kcp_interval);
    ev_timer_start(skcp->loop, conn->kcp_update_watcher);

    // 设置超时定时循环
    conn->timeout_watcher = malloc(sizeof(ev_timer));
    conn->timeout_watcher->data = conn;
    ev_init(conn->timeout_watcher, conn_timeout_cb);
    ev_timer_set(conn->timeout_watcher, skcp->conf->timeout_interval, skcp->conf->timeout_interval);
    ev_timer_start(skcp->loop, conn->timeout_watcher);

    return conn;
}

static int kcp_send_raw(skcp_conn_t *conn, const char *buf, int len) {
    if (!conn || !buf || len <= 0 || conn->status != SKCP_CONN_ST_ON) {
        return -1;
    }

    int rt = ikcp_send(conn->kcp, buf, len);
    if (rt < 0) {
        // 发送失败
        return -1;
    }
    ikcp_update(conn->kcp, clock());
    return rt;
}

static void on_req_cid_cmd(skcp_t *skcp, skcp_cmd_t *cmd, struct sockaddr_in dest_addr) {
    const uint ack_len = 1 + 1 + SKCP_TICKET_LEN + 1 + SKCP_IV_LEN + 1;
    // char ack[ack_len] = {0};
    char *ack = (char *)_ALLOC(ack_len);  // split by "\n", format:"code\ncid\niv"
    int out_len = 0;
    char *buf = NULL;
    if (cmd->payload_len != SKCP_TICKET_LEN) {
        snprintf(ack, ack_len, "%d", 1);
        goto send_req_cid_ack;
    }

    int rt = skcp->conf->on_check_ticket(cmd->payload, cmd->payload_len);
    if (rt != 0) {
        // fail
        snprintf(ack, ack_len, "%d", 1);
        goto send_req_cid_ack;
    }
    // create connection
    skcp_conn_t *conn = init_conn(skcp, 0);
    if (!conn) {
        // fail
        snprintf(ack, ack_len, "%d", 1);
        goto send_req_cid_ack;
    }

    conn->dest_addr = dest_addr;
    memcpy(conn->ticket, cmd->payload, SKCP_TICKET_LEN);

    // reset iv
    rand_iv(conn->iv);
    // send result ok
    snprintf(ack, ack_len, "%d\n%u\n%s", 0, conn->id, conn->iv);
    _LOG("on_req_cid_cmd ack: %s", ack);

send_req_cid_ack:
    buf = encode_cmd(0, SKCP_CMD_REQ_CID_ACK, ack, strlen(ack), &out_len);
    _FREEIF(ack);
    rt = udp_send(skcp, buf, out_len, dest_addr);
    _FREEIF(buf);
    if (rt < 0) {
        skcp_close_conn(skcp, conn->id);
    }
}

static void on_req_cid_ack_cmd(skcp_t *skcp, skcp_cmd_t *cmd) {
    if (cmd->payload_len <= 0 || cmd->payload[1] != '\n' || cmd->payload[0] != '0' ||
        cmd->payload_len < 4 + SKCP_IV_LEN) {
        // error
        return;
    }

    // success
    char *p = cmd->payload + 2;
    int i = 0;
    for (; i < cmd->payload_len - 2; i++) {
        if (*p == '\n') {
            break;
        }
        p++;
    }
    int scid_len = p - (cmd->payload + 2);
    char *scid = (char *)_ALLOC(scid_len + 1);
    memcpy(scid, cmd->payload + 2, scid_len);

    uint32_t cid = atoi(scid);
    _FREEIF(scid);
    if (cid <= 0) {
        // error
        return;
    }

    // create connection
    skcp_conn_t *conn = init_conn(skcp, cid);
    if (!conn) {
        // error
        return;
    }
    memcpy(conn->iv, p + 1, cmd->payload_len - i - 2);
    conn->status = SKCP_CONN_ST_ON;
    // TODO: set ticket, to the user to resolv

    _LOG("on_req_cid_ack_cmd cid: %d iv: %s", conn->id, conn->iv);

    skcp->conf->on_recv_cid(conn->id);
}

static void read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    if (EV_ERROR & revents) {
        _LOG("read_cb got invalid event");
        return;
    }
    skcp_t *skcp = (skcp_t *)(watcher->data);

    char *raw_buf = (char *)_ALLOC(skcp->conf->r_buf_size);
    struct sockaddr_in cliaddr;
    socklen_t cliaddr_len = sizeof(cliaddr);
    int32_t bytes = recvfrom(skcp->fd, raw_buf, skcp->conf->r_buf_size, 0, (struct sockaddr *)&cliaddr, &cliaddr_len);
    if (-1 == bytes) {
        perror("read_cb recvfrom error");
        _FREEIF(raw_buf);
        return;
    }

    // 解密
    char *plain_buf = raw_buf;
    int plain_len = bytes;
    if (strlen(skcp->conf->key) > 0) {
        plain_buf = aes_decrypt(skcp->conf->key, def_iv, raw_buf, bytes, &plain_len);
        _FREEIF(raw_buf);
    }

    uint32_t cid = ikcp_getconv(plain_buf);
    if (cid == 0) {
        // pure udp
        if (plain_len < SKCP_CMD_HEADER_LEN) {
            _FREEIF(plain_buf);
            return;
        }
        skcp_cmd_t *cmd = decode_cmd(plain_buf, plain_len);
        _FREEIF(plain_buf);
        if (!cmd) {
            _LOG("decode_cmd error");
            return;
        }
        if (cmd->type == SKCP_CMD_REQ_CID && skcp->mode == SKCP_MODE_SERV) {
            on_req_cid_cmd(skcp, cmd, cliaddr);
            _FREEIF(cmd);
            return;
        }
        if (cmd->type == SKCP_CMD_REQ_CID_ACK && skcp->mode == SKCP_MODE_CLI) {
            on_req_cid_ack_cmd(skcp, cmd);
            _FREEIF(cmd);
            return;
        }
        _FREEIF(cmd);
        return;
    }

    // kcp protocol
    if (plain_len < 24) {
        _FREEIF(plain_buf);
        return;
    }

    skcp_conn_t *conn = skcp_get_conn(skcp, cid);
    if (!conn) {
        _FREEIF(plain_buf);
        return;
    }
    if (skcp->mode == SKCP_MODE_SERV) {
        conn->dest_addr = cliaddr;
    }

    ikcp_input(conn->kcp, plain_buf, plain_len);
    ikcp_update(conn->kcp, clock());
    _FREEIF(plain_buf);

    int recv_len = 0;
    char *kcp_recv_buf = NULL;
    int kcp_recv_buf_len = 0;
    for (size_t try_cnt = 0; try_cnt < 10; try_cnt++) {
        kcp_recv_buf_len = skcp->conf->kcp_buf_size * (try_cnt + 1);
        kcp_recv_buf = (char *)_ALLOC(kcp_recv_buf_len);
        if (!kcp_recv_buf) {
            perror("alloc kcp_recv_buf error");
            return;
        }

        // 返回-1表示数据还没有收完数据，-3表示接受buf太小
        recv_len = ikcp_recv(conn->kcp, kcp_recv_buf, kcp_recv_buf_len);
        ikcp_update(conn->kcp, clock());
        if (recv_len == -1 || recv_len == -2) {
            // EAGAIN
            _FREEIF(kcp_recv_buf);
            return;
        }

        if (recv_len == -3) {
            _FREEIF(kcp_recv_buf);
            continue;
        }

        break;  // 有数据
    }

    // char *kcp_recv_buf = (char *)_ALLOC(skcp->conf->kcp_buf_size);
    // // 返回-1表示数据还没有收满，-3表示接受buf大小<实际收到的数据大小
    // int recv_len = ikcp_recv(conn->kcp, kcp_recv_buf, skcp->conf->kcp_buf_size);
    // ikcp_update(conn->kcp, clock());
    // if (recv_len < 0) {
    //     _FREEIF(kcp_recv_buf);
    //     return;
    // }

    conn->last_r_tm = getmillisecond();
    skcp->conf->on_recv_data(conn->id, kcp_recv_buf, recv_len);
    _FREEIF(kcp_recv_buf);
}

// static void write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
//     if (EV_ERROR & revents) {
//         _LOG("write_cb got invalid event");
//         return;
//     }
//     skcp_t *skcp = (skcp_t *)(watcher->data);
//     // TODO:
// }

/* ------------------------------- public api ------------------------------- */

int skcp_req_cid(skcp_t *skcp, const char *ticket, int len) {
    if (skcp->mode != SKCP_MODE_CLI) {
        return -1;
    }

    int out_len = 0;
    char *buf = encode_cmd(0, SKCP_CMD_REQ_CID, ticket, len, &out_len);
    int rt = udp_send(skcp, buf, out_len, skcp->servaddr);
    _FREEIF(buf);
    return rt;
}

int skcp_send(skcp_t *skcp, uint32_t cid, const char *buf, int len) {
    skcp_conn_t *conn = skcp_get_conn(skcp, cid);
    if (!conn || conn->status != SKCP_CONN_ST_ON) {
        return -1;
    }
    int rt = kcp_send_raw(conn, buf, len);
    return rt;
}

skcp_conn_t *skcp_get_conn(skcp_t *skcp, uint32_t cid) {
    if (!skcp || !skcp->conn_slots || cid <= 0) {
        return NULL;
    }
    return get_conn_from_slots(skcp->conn_slots, cid);
}

void skcp_close_conn(skcp_t *skcp, uint32_t cid) {
    skcp_conn_t *conn = skcp_get_conn(skcp, cid);
    if (!conn) {
        return;
    }
    // _LOG("skcp_close_conn cid: %u", cid);
    skcp->conf->on_close(cid);

    free_conn(skcp, conn);
}

skcp_t *skcp_init(skcp_conf_t *conf, struct ev_loop *loop, void *user_data, SKCP_MODE mode) {
    if (!conf || !loop) {
        return NULL;
    }

    skcp_t *skcp = (skcp_t *)_ALLOC(sizeof(skcp_t));
    skcp->conf = conf;
    skcp->mode = mode;
    skcp->user_data = user_data;
    skcp->loop = loop;

    skcp->conn_slots = init_conn_slots(conf->max_conn_cnt);
    if (!skcp->conn_slots) {
        _FREEIF(skcp);
        return NULL;
    }
    // if (mode == SKCP_MODE_SERV) {
    // }

    // setup network
    if (mode == SKCP_MODE_CLI) {
        if (init_cli_network(skcp) != 0) {
            _FREEIF(skcp);
            return NULL;
        }
    } else {
        if (init_serv_network(skcp) != 0) {
            _FREEIF(skcp);
            return NULL;
        }
    }

    // setup libev
    // 设置读事件循环
    skcp->r_watcher = malloc(sizeof(struct ev_io));
    skcp->r_watcher->data = skcp;
    ev_io_init(skcp->r_watcher, read_cb, skcp->fd, EV_READ);
    ev_io_start(skcp->loop, skcp->r_watcher);

    // // 设置写事件循环
    // skcp->w_watcher = malloc(sizeof(struct ev_io));
    // skcp->w_watcher->data = skcp;
    // ev_io_init(skcp->w_watcher, write_cb, skcp->fd, EV_WRITE);
    // ev_io_start(skcp->loop, skcp->w_watcher);

    return skcp;
}

void skcp_free(skcp_t *skcp) {
    if (!skcp) {
        return;
    }

    if (skcp->r_watcher) {
        ev_io_stop(skcp->loop, skcp->r_watcher);
        _FREEIF(skcp->r_watcher);
    }

    // if (skcp->timeout_watcher) {
    //     ev_timer_stop(skcp->loop, skcp->timeout_watcher);
    //     _FREEIF(skcp->timeout_watcher);
    // }

    // if (skcp->kcp_update_watcher) {
    //     ev_timer_stop(skcp->loop, skcp->kcp_update_watcher);
    //     _FREEIF(skcp->kcp_update_watcher);
    // }

    if (skcp->w_watcher) {
        ev_io_stop(skcp->loop, skcp->w_watcher);
        _FREEIF(skcp->w_watcher);
    }

    if (skcp->fd) {
        close(skcp->fd);
        skcp->fd = 0;
    }

    if (skcp->conn_slots) {
        for (uint32_t i = 0; i < skcp->conn_slots->remain_idx; i++) {
            uint32_t cid = skcp->conn_slots->remain_id_stack[i];
            skcp_close_conn(skcp, cid);
        }
        free_conn_slots(skcp->conn_slots);
    }

    skcp->conf = NULL;
    skcp->user_data = NULL;

    _FREEIF(skcp);
}
