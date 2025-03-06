#ifndef _SSBUFF_H
#define _SSBUFF_H

typedef struct {
    char* buf;  // 动态缓冲区
    int len;    // 当前缓冲长度
    int cap;    // 缓冲区容量
} ssbuff_t;

ssbuff_t* ssbuff_init(int cap);
void ssbuff_free(ssbuff_t* ssb);
int ssbuff_grow(ssbuff_t* ssb, int len);
int ssbuff_append(ssbuff_t* ssb, const char* data, int len);
// int ssbuff_move(ssbuff_t* ssb, int offset, int len);

#endif /* _SSBUFF_H */