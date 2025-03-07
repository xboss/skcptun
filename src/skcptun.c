
#define _XOPEN_SOURCE 700

#include "skcptun.h"

#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "tun.h"
#include "uthash.h"

#define SKT_PKT_HEADER_SZIE 4
#define MAX_DATA_PAYLOAD_SZIE (1024 * 2)
#define RECV_DATA_BUF_SIZE ((MAX_DATA_PAYLOAD_SZIE + SKT_PKT_HEADER_SZIE) * 5)
#define MAX_CTRL_PAYLOAD_SZIE (128)
// #define RECV_CTRL_BUF_SIZE (MAX_CTRL_PAYLOAD_SZIE + SKT_PKT_HEADER_SZIE)
#define RECV_TIMEOUT 1000 * 60 * 5
#define SEND_TIMEOUT 1000 * 60 * 5
#define POLL_TIMEOUT 1000 * 10

#define _IS_SECRET (strlen((const char*)skt->conf->key) > 0 && strlen((const char*)skt->conf->iv) > 0)

typedef struct {
    skcptun_t* skt;
} data_channel_args_t;

typedef struct {
    skcptun_t* skt;
} ctrl_channel_args_t;

////////////////////////////////
// tools
////////////////////////////////

inline static uint64_t mstime() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t millisecond = (tv.tv_sec * 1000000l + tv.tv_usec) / 1000l;
    return millisecond;
}

static void print_hex(const char* label, const unsigned char* data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

////////////////////////////////
// conv id manager
////////////////////////////////

#define SKT_CONV_MIN (10000)

typedef struct {
    uint32_t id;
    UT_hash_handle hh;
} skt_conv_t;
static pthread_rwlock_t g_conv_lock;
static skt_conv_t* g_conv_table = NULL;
static uint32_t g_conv_id = SKT_CONV_MIN;

static int skt_conv_init() {
    if (pthread_rwlock_init(&g_conv_lock, NULL) != 0) {
        perror("init conv lock failed");
        return _ERR;
    }
    g_conv_table = NULL;
    g_conv_id = SKT_CONV_MIN;
    return _OK;
}

static int skt_conv_add(uint32_t id) {
    pthread_rwlock_wrlock(&g_conv_lock);
    int ret = _OK;
    do {
        skt_conv_t* conv;
        HASH_FIND_INT(g_conv_table, &id, conv);
        if (conv == NULL) {
            conv = (skt_conv_t*)malloc(sizeof(skt_conv_t));
            if (!conv) {
                perror("alloc skt_conv_add");
                ret = _ERR;
                break;
            }
            conv->id = id;
            HASH_ADD_INT(g_conv_table, id, conv);
        }
    } while (0);
    pthread_rwlock_unlock(&g_conv_lock);
    return ret;
}

static skt_conv_t* skt_conv_find(int id) {
    pthread_rwlock_rdlock(&g_conv_lock);
    skt_conv_t* conv;
    HASH_FIND_INT(g_conv_table, &id, conv);
    pthread_rwlock_unlock(&g_conv_lock);
    return conv;
}
static void skt_conv_del(int id) {
    pthread_rwlock_wrlock(&g_conv_lock);
    skt_conv_t* conv;
    HASH_FIND_INT(g_conv_table, &id, conv);
    if (conv != NULL) {
        HASH_DEL(g_conv_table, conv);
        free(conv);
    }
    pthread_rwlock_unlock(&g_conv_lock);
}

static uint32_t skt_conv_gen() {
    g_conv_id++;
    if (g_conv_id < SKT_CONV_MIN) {
        _LOG_W("conv id overflow\n");
    }
    if (skt_conv_add(g_conv_id) == _ERR) {
        return 0;
    }
    return g_conv_id;
}

////////////////////////////////
// protocol
////////////////////////////////

inline static int pack(skcptun_t* skt, char* payload, int payload_len, char* pkt, int* pkt_len) {
    int cipher_len = 0;
    int payload_len_net = htonl(payload_len);
    memcpy(pkt, &payload_len_net, SKT_PKT_HEADER_SZIE);
    *pkt_len += SKT_PKT_HEADER_SZIE;
    if (_IS_SECRET) {
        if (crypto_encrypt(skt->conf->key, skt->conf->iv, (const unsigned char*)&payload, (size_t)payload_len,
                           (unsigned char*)pkt + SKT_PKT_HEADER_SZIE, (size_t*)&cipher_len)) {
            _LOG_E("crypto encrypt failed");
            return _ERR;
        }
        assert(cipher_len == payload_len && cipher_len > 0);
        *pkt_len += cipher_len;
    } else {
        memcpy(pkt + SKT_PKT_HEADER_SZIE, payload, payload_len);
        *pkt_len += payload_len;
    }
    return _OK;
}

inline static int unpack(skcptun_t* skt, char* pkt, int pkt_len, char* payload, int* payload_len) {
    if (_IS_SECRET) {
        int cipher_len = 0;
        if (crypto_decrypt(skt->conf->key, skt->conf->iv, (const unsigned char*)pkt + SKT_PKT_HEADER_SZIE,
                           pkt_len - SKT_PKT_HEADER_SZIE, (unsigned char*)payload, (size_t*)&cipher_len)) {
            _LOG_E("crypto decrypt failed when do_auth");
            assert(cipher_len == pkt_len - SKT_PKT_HEADER_SZIE);
            *payload_len += cipher_len;
            return _ERR;
        } else {
            memcpy(payload, pkt + SKT_PKT_HEADER_SZIE, pkt_len - SKT_PKT_HEADER_SZIE);
            *payload_len += pkt_len - SKT_PKT_HEADER_SZIE;
        }
    }
    return _OK;
}

////////////////////////////////
// controller channel
////////////////////////////////

static inline int tcp_send_totally(int fd, const char* buf, int len) {
    int sent = 0, s = len;
    while (sent < len) {
        s = sstcp_send(fd, buf + sent, s - sent);
        if (s < 0) {
            return _ERR;
        }
        sent += s;
    }
    assert(sent == len);
    // printf("<<< send_fd: %d ", fd);
    // print_hex("send", (const unsigned char*)buf, len);
    return _OK;
}

static int recv_ctrl_pkt(skcptun_t* skt, int fd, char* pkt, char* payload, int* payload_len) {
    int pkt_len = 0, r = 0, plen = 0;
    char buf[SKT_PKT_HEADER_SZIE + SKT_TICKET_SIZE] = {0};
    while (pkt_len < SKT_PKT_HEADER_SZIE + SKT_TICKET_SIZE) {
        r = sstcp_receive(fd, buf, SKT_PKT_HEADER_SZIE + SKT_TICKET_SIZE - pkt_len);
        if (r <= 0) {
            _LOG_W("recv ctrl failed");
            return _ERR;
        }
        // printf(">>> recv_fd: %d ", fd);
        // print_hex("recv", (const unsigned char*)buf, r);
        memcpy(pkt + pkt_len, buf, r);
        pkt_len += r;
        // double check
        if (pkt_len < SKT_PKT_HEADER_SZIE) {
            _LOG_W("recv ctrl failed. head_len: %d", pkt_len);
            return _ERR;
        }
        if (pkt_len >= SKT_PKT_HEADER_SZIE) {
            plen = ntohl(*(uint32_t*)pkt);
            if (plen > MAX_CTRL_PAYLOAD_SZIE) {
                _LOG_W("recv ctrl failed. payload_len: %d", plen);
                return _ERR;
            }
        }
    }
    assert(pkt_len == SKT_PKT_HEADER_SZIE + SKT_TICKET_SIZE);
    if (unpack(skt, pkt, pkt_len, payload, payload_len) == _ERR) return _ERR;
    return _OK;
}

static void handle_ctrl_server(int fd, sstcp_server_t* server) {
    if (sstcp_set_nodelay(fd) == _ERR) return;
    if (sstcp_set_recv_timeout(fd, RECV_TIMEOUT) == _ERR) return;
    if (sstcp_set_send_timeout(fd, SEND_TIMEOUT) == _ERR) return;

    skcptun_t* skt = (skcptun_t*)server->user_data;
    assert(skt);

    int payload_len = 0;
    char pkt[SKT_PKT_HEADER_SZIE + SKT_TICKET_SIZE] = {0};
    char payload[SKT_PKT_HEADER_SZIE + SKT_TICKET_SIZE] = {0};

    // recv ctrl packet
    if (recv_ctrl_pkt(skt, fd, pkt, payload, &payload_len) == _ERR) return;
    assert(payload_len > 0);

    // auth
    if (payload_len != SKT_TICKET_SIZE || memcmp(payload, skt->conf->ticket, SKT_TICKET_SIZE) != 0) {
        _LOG_W("auth failed");
        return;
    }

    // gen conv
    uint32_t cid = skt_conv_gen();
    if (cid == 0) return;

    // send kcp conv
    int pkt_len = 0;
    uint32_t cid_net = htonl(cid);
    // reuse pkt
    if (pack(skt, (char*)&cid_net, sizeof(uint32_t), pkt, &pkt_len) == _ERR) return;
    tcp_send_totally(fd, pkt, pkt_len);
}

static int req_conv(skcptun_t* skt, int* cid) {
    // auth and send conv req
    char pkt[SKT_PKT_HEADER_SZIE + SKT_TICKET_SIZE] = {0};
    int pkt_len = 0;
    int payload_len = SKT_TICKET_SIZE;
    uint32_t payload_len_net = htonl(payload_len);
    memcpy(pkt, &payload_len_net, SKT_PKT_HEADER_SZIE);
    pkt_len += SKT_PKT_HEADER_SZIE;
    if (pack(skt, skt->conf->ticket, SKT_TICKET_SIZE, pkt, &pkt_len)) return _ERR;
    assert(pkt_len == SKT_PKT_HEADER_SZIE + SKT_TICKET_SIZE);
    if (tcp_send_totally(skt->tcp_client->client_fd, pkt, pkt_len)) {
        _LOG_E("send conv req failed");
        return _ERR;
    }
    _LOG("send conv req ok.");

    char recv_buf[SKT_PKT_HEADER_SZIE + sizeof(uint32_t)] = {0};
    int recv_len = sstcp_receive(skt->tcp_client->client_fd, recv_buf, SKT_PKT_HEADER_SZIE + sizeof(uint32_t));
    if (recv_len <= 0 || recv_len != SKT_PKT_HEADER_SZIE + sizeof(uint32_t)) {
        _LOG_W("recv conv failed");
        return _ERR;
    }
    uint32_t cid_net = 0;
    payload_len = 0;
    if (unpack(skt, recv_buf, SKT_PKT_HEADER_SZIE + sizeof(uint32_t), (char*)&cid_net, &payload_len) == _ERR)
        return _ERR;
    *cid = ntohl(cid_net);

    return _OK;
}

////////////////////////////////
// data channel
////////////////////////////////

static void trans_data(skcptun_t* skt) { /* TODO: */ }

static void* handle_data_channel(void* args) {
    _LOG("handle_data_channel start.");
    assert(args);
    data_channel_args_t* dc_args = (data_channel_args_t*)args;
    skcptun_t* skt = (skcptun_t*)dc_args->skt;
    assert(skt);

    trans_data(skt);
    /* TODO: */

    free(args);
    _LOG("handle_data_channel end.");
    return NULL;
}

static int start_remote(skcptun_t* skt) {
    if (!skt->tcp_server) return _ERR;
    if (!skt_conv_init()) return _ERR;
    skt->running = 1;
    // start data channel
    data_channel_args_t* args = (data_channel_args_t*)calloc(1, sizeof(data_channel_args_t));
    if (!args) {
        perror("calloc");
        return _ERR;
    }
    args->skt = skt;
    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, handle_data_channel, args) != 0) {
        perror("Thread creation failed");
        free(args);
        return _ERR;
    }
    pthread_detach(thread_id);

    return sstcp_start_server(skt->tcp_server);
}

static int start_local(skcptun_t* skt) {
    if (!skt->tcp_client) return _ERR;
    skt->running = 1;

    // connect to ctrl server
    int ret = sstcp_connect(skt->tcp_client, skt->conf->ctrl_server_ip, skt->conf->ctrl_server_port);
    if (ret != _OK) {
        _LOG_E("connect to controller server failed. %d %s:%d", skt->tcp_client->client_fd, skt->conf->ctrl_server_ip,
               skt->conf->ctrl_server_port);
        return _ERR;
    }
    if (sstcp_set_nodelay(skt->tcp_client->client_fd) == _ERR) {
        close(skt->tcp_client->client_fd);
        return _ERR;
    }
    _LOG("connect to controller server ok. %d %s:%d", skt->tcp_client->client_fd, skt->conf->ctrl_server_ip,
         skt->conf->ctrl_server_port);

    // request conv
    int cid = 0;
    if (req_conv(skt, &cid) == _ERR) {
        close(skt->tcp_client->client_fd);
        return _ERR;
    }

    // ctrl_channel_args_t* args = (ctrl_channel_args_t*)calloc(1, sizeof(ctrl_channel_args_t));
    // if (!args) {
    //     perror("calloc");
    //     return _ERR;
    // }
    // args->skt = skt;
    // pthread_t thread_id;
    // if (pthread_create(&thread_id, NULL, handle_ctrl_client, args) != 0) {
    //     perror("Thread creation failed");
    //     free(args);
    //     return _ERR;
    // }
    // pthread_detach(thread_id);

    /* TODO: handle_ctrl_client */
    return _OK;
}

////////////////////////////////
// API
////////////////////////////////

skcptun_t* skt_init(skt_config_t* conf) {
    skcptun_t* skt = (skcptun_t*)calloc(1, sizeof(skcptun_t));
    if (skt == NULL) {
        perror("calloc");
        return NULL;
    }
    skt->conf = conf;
    skt->running = 0;

    // Allocate TUN device
    skt->tun_fd = tun_alloc(conf->tun_dev, IFNAMSIZ);
    if (skt->tun_fd < 0) {
        perror("tun_alloc");
        free(skt);
        return NULL;
    }

    // Set TUN device IP
    if (tun_set_ip(conf->tun_dev, conf->tun_ip) < 0) {
        perror("tun_set_ip");
        close(skt->tun_fd);
        free(skt);
        return NULL;
    }

    // Set TUN device netmask
    if (tun_set_netmask(conf->tun_dev, conf->tun_netmask) < 0) {
        perror("tun_set_netmask");
        close(skt->tun_fd);
        free(skt);
        return NULL;
    }

    // Set TUN device MTU
    if (tun_set_mtu(conf->tun_dev, conf->mtu) < 0) {
        perror("tun_set_mtu");
        close(skt->tun_fd);
        free(skt);
        return NULL;
    }

    // Bring up TUN device
    if (tun_up(conf->tun_dev) < 0) {
        perror("tun_up");
        close(skt->tun_fd);
        free(skt);
        return NULL;
    }

    // init udp data channel
    skt->udp = ssudp_init(conf->udp_local_ip, conf->udp_local_port, conf->udp_remote_ip, conf->udp_remote_port);
    if (skt->udp == NULL) {
        close(skt->tun_fd);
        free(skt);
        return NULL;
    }

    if (skt->conf->mode == SKT_MODE_REMOTE) {
        // init tcp server controller channel
        skt->tcp_server = sstcp_create_server(conf->ctrl_server_ip, conf->ctrl_server_port, handle_ctrl_server, skt);
        if (skt->tcp_server == NULL) {
            close(skt->tun_fd);
            ssudp_free(skt->udp);
            free(skt);
            return NULL;
        }
    } else {
        // init tcp client
        skt->tcp_client = sstcp_create_client();
        /* TODO: */
    }

    return NULL;
}

int skt_start(skcptun_t* skt) {
    if (!skt || !skt->conf) return _ERR;
    if (skt->conf->mode == SKT_MODE_LOCAL) {
        return start_local(skt);
    } else if (skt->conf->mode == SKT_MODE_REMOTE) {
        return start_remote(skt);
    }
    return _ERR;
}

void skt_stop(skcptun_t* skt) {
    /* TODO: */
    return;
}

void skt_free(skcptun_t* skt) {
    /* TODO: */
    return;
}
