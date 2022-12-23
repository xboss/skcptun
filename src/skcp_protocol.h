#ifndef _SKCP_PROTOCOL_H
#define _SKCP_PROTOCOL_H

// #include <stddef.h>
// #include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
header:
    protocol name(1B): 0xBB
    version(1B):0x01
    cmd(1B):
    flg(1B):
    payload length(4B):uint32

cmd:
connection:
    header(8B):
    palyload(nB):
*/

#define SKCP_CMD_CONN 0x01
#define SKCP_CMD_CONN_ACK 0x02
#define SKCP_CMD_DATA 0x03
#define SKCP_CMD_PING 0x04
#define SKCP_CMD_PONG 0x05
#define SKCP_CMD_CLOSE 0x06
#define SKCP_CMD_CLOSE_ACK 0x07
#define SKCP_CMD_CTRL 0x08

#define SKCP_CMD_HEADER_LEN 8
#define SKCP_PROTOCOL_NAME 0xBB
#define SKCP_PROTOCOL_VER_1 0x01
#define SKCP_CMD_CONN_NEED_AUTH 0x01

typedef struct {
    char name;
    char ver;
    char type;
    char flg;
    uint32_t payload_len;
} skcp_cmd_header_t;

typedef struct {
    skcp_cmd_header_t header;
    char payload[];
} skcp_cmd_t;

#define SKCP_ENCODE_CMD_HEADER(vbuf, vheader)                \
    do {                                                     \
        *(vbuf) = (vheader).name;                            \
        *((vbuf) + 1) = (vheader).ver;                       \
        *((vbuf) + 2) = (vheader).type;                      \
        *((vbuf) + 3) = (vheader).flg;                       \
        uint32_t payload_len = htonl((vheader).payload_len); \
        memcpy(buf + 4, &payload_len, 4);                    \
    } while (0)

#define SKCP_DECODE_CMD_HEADER(vheader, vbuf)                     \
    do {                                                          \
        (vheader).name = *(vbuf);                                 \
        (vheader).ver = *((vbuf) + 1);                            \
        (vheader).type = *((vbuf) + 2);                           \
        (vheader).flg = *((vbuf) + 3);                            \
        (vheader).payload_len = ntohl(*(uint32_t *)((vbuf) + 4)); \
    } while (0)

#define SKCP_BUILD_CMD_HEADER(vheader, vtype, vflg, vpayload_len) \
    do {                                                          \
        (vheader).name = SKCP_PROTOCOL_NAME;                      \
        (vheader).ver = SKCP_PROTOCOL_VER_1;                      \
        (vheader).type = (vtype);                                 \
        (vheader).flg = (vflg);                                   \
        (vheader).payload_len = (vpayload_len);                   \
    } while (0)

#define SKCP_BUILD_CMD(vcmd, vtype, vflg, vpayload_len, vpayload)         \
    do {                                                                  \
        (vcmd) = malloc(sizeof(skcp_cmd_t) + vpayload_len);               \
        SKCP_BUILD_CMD_HEADER((vcmd)->header, vtype, vflg, vpayload_len); \
        if (vpayload_len > 0) {                                           \
            memcpy((vcmd)->payload, (vpayload), (vpayload_len));          \
        }                                                                 \
    } while (0)

char *skcp_encode_cmd(skcp_cmd_t *cmd, int *len);
skcp_cmd_t *skcp_decode_cmd(char *buf, int len);

#endif  // SKCP_PROTOCOL_H