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
    } while (0)

#define LOG_E(fmt, args...)  \
    do {                     \
        printf("ERROR ");    \
        print_now();         \
        printf(fmt, ##args); \
        printf("\n");        \
    } while (0)

#ifdef _WARN_LOG
#define LOG_W(fmt, args...)  \
    do {                     \
        printf("WARN ");     \
        print_now();         \
        printf(fmt, ##args); \
        printf("\n");        \
    } while (0)
#else
#define LOG_W(fmt, args...) \
    do {                    \
        ;                   \
    } while (0)
#endif

#ifdef _INFO_LOG
#define LOG_I(fmt, args...)  \
    do {                     \
        printf("INFO ");     \
        print_now();         \
        printf(fmt, ##args); \
        printf("\n");        \
    } while (0)
#else
#define LOG_I(fmt, args...) \
    do {                    \
        ;                   \
    } while (0)
#endif

#ifdef _DEBUG_LOG
#define LOG_D(fmt, args...)  \
    do {                     \
        printf("DEBUG ");    \
        print_now();         \
        printf(fmt, ##args); \
        printf("\n");        \
    } while (0)
#else
#define LOG_D(fmt, args...) \
    do {                    \
        ;                   \
    } while (0)
#endif

#define SKT_MSG_HEADER_MAX 16
#define SKT_MSG_CMD_ACCEPT 'A'
#define SKT_MSG_CMD_DATA 'D'
#define SKT_MSG_CMD_CLOSE 'C'
#define SKT_MSG_SEPARATOR '\n'

unsigned short ip_checksum(unsigned short* buf, int nword);
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
int parse_skt_msg(char* buf, int len, char* cmd, int* fd, char** pdata, int* pdata_len);

#endif
