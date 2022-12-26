#include "skt_utils.h"

#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <netdb.h>
#include <openssl/aes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>

void* skt_mem_clone(void* src, size_t len) {
    void* new = malloc(len);
    memcpy(new, src, len);
    return new;
}

void _PR(const void* buf, int len) {
    const char* pb = buf;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = *pb;
        printf("%2X ", ((*pb) & 0xFF));
        pb++;
    }
    printf("\n");
}

uint64_t getmillisecond() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t millisecond = (tv.tv_sec * 1000000l + tv.tv_usec) / 1000l;
    return millisecond;
}

void char_to_hex(char* src, int len, char* des) {
    char hex_table[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    while (len--) {
        *(des++) = hex_table[(*src) >> 4];
        *(des++) = hex_table[*(src++) & 0x0f];
    }
}

void print_now() {
    time_t now;
    struct tm* tm_now;
    time(&now);
    tm_now = localtime(&now);
    printf("%d-%d-%d %d:%d:%d:%llu ", tm_now->tm_year + 1900, tm_now->tm_mon + 1, tm_now->tm_mday, tm_now->tm_hour,
           tm_now->tm_min, tm_now->tm_sec, (getmillisecond() % 1000l));
}

void setnonblock(int fd) {
    if (-1 == fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)) {
        LOG_E("error fcntl");
    }
}

void setreuseaddr(int fd) {
    int reuse = 1;
    if (-1 == setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))) {
        LOG_E("error setsockopt");
    }
}

void set_recv_timeout(int fd, time_t sec) {
    struct timeval timeout;
    timeout.tv_sec = sec;
    timeout.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        LOG_E("set_recv_timeout error");
    }
}

void set_send_timeout(int fd, time_t sec) {
    struct timeval timeout;
    timeout.tv_sec = sec;
    timeout.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        LOG_E("set_recv_timeout error");
    }
}

uint64_t oi_ntohll(uint64_t val) { return (((uint64_t)ntohl(val)) << 32) + ntohl(val >> 32); }

uint64_t oi_htonll(uint64_t val) { return (((uint64_t)htonl(val)) << 32) + htonl(val >> 32); }
