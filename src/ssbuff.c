#include "ssbuff.h"

#include <stdlib.h>
#include <string.h>

#define _ERR -1
#define _OK 0
ssbuff_t* ssbuff_init(int cap) {
    ssbuff_t* ssb = (ssbuff_t*)calloc(1, sizeof(ssbuff_t));
    if (!ssb) {
        return NULL;
    }
    if (cap > 0) {
        ssb->buf = (char*)calloc(1, cap);
        if (!ssb->buf) {
            ssbuff_free(ssb);
            return NULL;
        }
        ssb->cap = cap;
    }
    return ssb;
}

void ssbuff_free(ssbuff_t* ssb) {
    if (ssb) {
        if (ssb->buf) {
            free(ssb->buf);
            ssb->buf = NULL;
        }
        free(ssb);
    }
}

int ssbuff_grow(ssbuff_t* ssb, int len) {
    if (ssb->len + len > ssb->cap) {
        int new_cap = ssb->cap * 3 / 2;
        if (new_cap < ssb->len + len) {
            new_cap = ssb->len + len;
        }
        char* new_buf = (char*)calloc(1, new_cap);
        if (!new_buf) {
            return _ERR;
        }
        if (ssb->buf) {
            memcpy(new_buf, ssb->buf, ssb->len);
            free(ssb->buf);
        }
        ssb->buf = new_buf;
        ssb->cap = new_cap;
    }
    return _OK;
}

int ssbuff_append(ssbuff_t* ssb, const char* data, int len) {
    if (ssbuff_grow(ssb, len) == _ERR) {
        return _ERR;
    }
    memcpy(ssb->buf + ssb->len, data, len);
    ssb->len += len;
    return _OK;
}

// int ssbuff_move(ssbuff_t* ssb, int offset, int len) {
//     if (offset <= 0 || len <= 0 || offset + len > ssb->len) {
//         return _ERR;
//     }
//     memmove(ssb->buf, ssb->buf + offset, len);
//     ssb->len = len;
//     return _OK;
// }