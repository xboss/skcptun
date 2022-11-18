#ifndef _SKT_UTILS_H
#define _SKT_UTILS_H

#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>

// #define _DEBUG_LOG
#define _INFO_LOG
#define _WARN_LOG

#define SKT_OK 0
#define SKT_ERROR -1

#define FREE_IF(p)    \
    do {              \
        if (p) {      \
            free(p);  \
            p = NULL; \
        }             \
    } while (0);

#define LOG_E(fmt, args...)  \
    do {                     \
        printf("ERROR ");    \
        print_now();         \
        printf(fmt, ##args); \
        printf("\n");        \
    } while (0);

#ifdef _WARN_LOG
#define LOG_W(fmt, args...)  \
    do {                     \
        printf("WARN ");     \
        print_now();         \
        printf(fmt, ##args); \
        printf("\n");        \
    } while (0);
#else
#define LOG_W(fmt, args...) \
    do {                    \
        ;                   \
    } while (0);
#endif

#ifdef _INFO_LOG
#define LOG_I(fmt, args...)  \
    do {                     \
        printf("INFO ");     \
        print_now();         \
        printf(fmt, ##args); \
        printf("\n");        \
    } while (0);
#else
#define LOG_I(fmt, args...) \
    do {                    \
        ;                   \
    } while (0);
#endif

#ifdef _DEBUG_LOG
#define LOG_D(fmt, args...)  \
    do {                     \
        printf("DEBUG ");    \
        print_now();         \
        printf(fmt, ##args); \
        printf("\n");        \
    } while (0);
#else
#define LOG_D(fmt, args...) \
    do {                    \
        ;                   \
    } while (0);
#endif

typedef struct waiting_buf_s waiting_buf_t;
struct waiting_buf_s {
    char buf[2048];
    int len;
    waiting_buf_t *next, *prev;
};

void char_to_hex(char* src, int len, char* des);
void* skt_mem_clone(void* src, size_t len);
void _PR(const void* buf, int len);
uint64_t getmillisecond();
void print_now();
void set_recv_timeout(int fd, time_t sec);
void set_send_timeout(int fd, time_t sec);
void setreuseaddr(int fd);
void setnonblock(int fd);
uint64_t oi_ntohll(uint64_t val);
uint64_t oi_htonll(uint64_t val);

#endif
