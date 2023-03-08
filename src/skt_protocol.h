#ifndef _SKT_PROTOCOL_H
#define _SKT_PROTOCOL_H

#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/*
protocol:
    protocol name(2B): "JJ"
    version(1B):0x01
    flg(1B):
    cmd(1B):
    payload length(4B):uint32
    palyload(nB):
*/

#define SKT_SEG_DATA 0x01
#define SKT_SEG_PING 0x02
#define SKT_SEG_PONG 0x03
// #define SKT_SEG_CLOSE 0x06
// #define SKT_SEG_CLOSE_ACK 0x07
// #define SKT_SEG_CTRL 0x08

#define SKT_SEG_HEADER_LEN 9
#define SKT_SEG_VER_1 0x01
#define SKT_SEG_FLG_AUTH 0x01

const static char SKT_SEG_NAME[] = "JJ";

typedef struct {
    char name[2];
    char ver;
    char flg;
    char type;
    uint32_t payload_len;
    char payload[0];
} skt_seg_t;

#define SKT_ENCODE_SEG(_v_raw, _v_flg, _v_type, _v_payload, _v_payload_len, _v_out_len) \
    do {                                                                                \
        (_v_raw) = (char *)calloc(1, SKT_SEG_HEADER_LEN + (_v_payload_len));            \
        memcpy((_v_raw), SKT_SEG_NAME, 2);                                              \
        *((_v_raw) + 2) = SKT_SEG_VER_1;                                                \
        *((_v_raw) + 3) = (_v_flg);                                                     \
        *((_v_raw) + 4) = (_v_type);                                                    \
        uint32_t _payload_len_tmp = htonl((_v_payload_len));                            \
        memcpy((_v_raw) + 5, &_payload_len_tmp, 4);                                     \
        if ((_v_payload) && (_v_payload_len) > 0) {                                     \
            memcpy((_v_raw) + SKT_SEG_HEADER_LEN, _v_payload, (_v_payload_len));        \
        }                                                                               \
        (_v_out_len) = (_v_payload_len) + SKT_SEG_HEADER_LEN;                           \
    } while (0)

#define SKT_DECODE_SEG(_v_seg, _v_buf, _v_buf_len)                                                    \
    do {                                                                                              \
        if (_v_buf && _v_buf_len >= SKT_SEG_HEADER_LEN) {                                             \
            (_v_seg) = (skt_seg_t *)calloc(1, sizeof(skt_seg_t) + ((_v_buf_len)-SKT_SEG_HEADER_LEN)); \
            memcpy((_v_seg)->name, (_v_buf), 2);                                                      \
            (_v_seg)->ver = *((_v_buf) + 2);                                                          \
            (_v_seg)->flg = *((_v_buf) + 3);                                                          \
            (_v_seg)->type = *((_v_buf) + 4);                                                         \
            (_v_seg)->payload_len = ntohl(*(uint32_t *)((_v_buf) + 5));                               \
            if ((_v_seg)->payload_len > 0) {                                                          \
                memcpy((_v_seg)->payload, (_v_buf) + SKT_SEG_HEADER_LEN, (_v_seg)->payload_len);      \
            }                                                                                         \
        }                                                                                             \
    } while (0)

#define SKT_CHECK_SEG_HEADER(_v_seg)                                                            \
    (_v_seg) && (_v_seg)->name[0] == SKT_SEG_NAME[0] && (_v_seg)->name[1] == SKT_SEG_NAME[1] && \
        (_v_seg)->ver == SKT_SEG_VER_1

#endif