#include "skt_conv.h"

#define SKT_CONV_MIN (10000)

typedef struct {
    uint32_t cid;
    skt_conv_t* conv;
    UT_hash_handle hh;
} cid_index_t;

typedef struct {
    char ip[INET_ADDRSTRLEN + 1];
    skt_conv_t* conv;
    UT_hash_handle hh;
} ip_index_t;

static cid_index_t* g_cid_idx_tb = NULL;
static ip_index_t* g_ip_idx_tb = NULL;
static uint32_t g_conv_id = SKT_CONV_MIN;

 skt_conv_t* skt_conv_get_by_cid(uint32_t cid) {
    cid_index_t* cid_idx;
    HASH_FIND_INT(g_cid_idx_tb, &cid, cid_idx);
    if (!cid_idx) return NULL;
    assert(cid_idx->conv);
    return cid_idx->conv;
}

 skt_conv_t* skt_conv_get_by_ip(char* ip) {
    ip_index_t* ip_idx;
    HASH_FIND_STR(g_ip_idx_tb, ip, ip_idx);
    if (!ip_idx) return NULL;
    assert(ip_idx->conv);
    return ip_idx->conv;
}

 int skt_conv_add(uint32_t cid, const char* ip, const ikcpcb* kcp, struct sockaddr_in addr) {
    assert(cid > 0);
    assert(ip);
    assert(ip[INET_ADDRSTRLEN + 1] == '\0');
    if (skt_conv_get_by_cid(cid) == NULL) {
        return _ERR;
    }
    if (skt_conv_get_by_ip(ip) == NULL) {
        return _ERR;
    }
    skt_conv_t* conv = (skt_conv_t*)calloc(1, sizeof(skt_conv_t));
    if (!conv) {
        perror("alloc");
        return _ERR;
    }
    conv->cid = cid;
    conv->kcp = kcp;
    memcpy(conv->ip, ip, strnlen(ip, INET_ADDRSTRLEN));
    conv->addr = addr;

    cid_index_t* cid_idx = (cid_index_t*)calloc(1, sizeof(cid_index_t));
    if (!cid_idx) {
        perror("alloc");
        return _ERR;
    }
    cid_idx->cid = conv->cid;
    cid_idx->conv = conv;
    HASH_ADD_INT(g_cid_idx_tb, cid, cid_idx);

    ip_index_t* ip_idx = (ip_index_t*)calloc(1, sizeof(ip_index_t));
    if (!ip_idx) {
        perror("alloc");
        return _ERR;
    }
    memcpy(ip_idx->ip, ip, strnlen(ip, INET_ADDRSTRLEN));
    cid_idx->conv = conv;
    HASH_ADD_STR(g_ip_idx_tb, ip, ip_idx);
    return _OK;
}

 void skt_conv_del_by_cid(int cid) {
    cid_index_t* cid_idx;
    HASH_FIND_INT(g_cid_idx_tb, &cid, cid_idx);
    if (!cid_idx) return;
    assert(cid_idx->conv);
    ip_index_t* ip_idx;
    HASH_FIND_STR(g_ip_idx_tb, cid_idx->conv, ip_idx);
    assert(ip_idx);

    HASH_DEL(g_cid_idx_tb, cid_idx);
    free(cid_idx);
    HASH_DEL(g_ip_idx_tb, ip_idx);
    free(ip_idx);
    free(cid_idx->conv);
    

    
    // HASH_FIND_INT(g_conv_table, &id, conv);
    // if (conv != NULL) {
    //     HASH_DEL(g_conv_table, conv);
    //     free(conv);
    // }
}

 uint32_t skt_conv_gen_cid() {
    g_conv_id++;
    if (g_conv_id < SKT_CONV_MIN) {
        _LOG_W("conv id overflow\n");
    }
    
    // if (skt_conv_add(g_conv_id, NULL) == _ERR) {
    //     return 0;
    // }
    return g_conv_id;
}