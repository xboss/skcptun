#ifndef _SKCP_PROTOCOL_H
#define _SKCP_PROTOCOL_H

// #include <stddef.h>
// #include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
define:
protocol name(8bit): 0xBB
version(8bit):0x01

cmd:
connection:
    protocol name(8bit): $name
    version(8bit): $ver
    cmd(8bit): 0x01
    flg(8bit):
                0x00:no encryption, no authentication, no payload
                0x01: require encryption, has payload
                0x02: require authentication, has payload
    payload length(uint32):
    palyload(n):
connection ack:
    protocol name(8bit): $name
    version(8bit): $ver
    cmd(8bit): 0x02
    code(8bit): 0x00:success; 0x01: unknow error; 0x02: encryption error; 0x03: authentication error;
    payload length(uint32):
    palyload(n):
data:
    protocol name(8bit): $name
    version(8bit): $ver
    cmd(8bit): 0x03
    payload length(uint32):
    palyload(n):
ping: TODO
    protocol name(8bit): $name
    version(8bit): $ver
    cmd(8bit): 0x04
pong: TODO
    protocol name(8bit): $name
    version(8bit): $ver
    cmd(8bit): 0x05
close:
    protocol name(8bit): $name
    version(8bit): $ver
    cmd(8bit): 0x06
close ack: TODO
    protocol name(8bit): $name
    version(8bit): $ver
    cmd(8bit): 0x07
control:
    protocol name(8bit): $name
    version(8bit): $ver
    cmd(8bit): 0x08
    payload length(uint32):
    palyload(n):

*/

#define SKCP_CMD_CONN 0x01
#define SKCP_CMD_CONN_ACK 0x02
#define SKCP_CMD_DATA 0x03
#define SKCP_CMD_PING 0x04
#define SKCP_CMD_PONG 0x05
#define SKCP_CMD_CLOSE 0x06
#define SKCP_CMD_CLOSE_ACK 0x07
#define SKCP_CMD_CTRL 0x08

#define SKCP_CMD_HEADER_LEN 3
#define SKCP_PROTOCOL_NAME 0xBB
#define SKCP_PROTOCOL_VER_1 0x01
#define SKCP_CMD_CONN_NEED_ENCRYPT 0x01
#define SKCP_CMD_CONN_NEED_AUTH 0x02

typedef struct {
    char name;
    char ver;
    char type;
} skcp_cmd_header_t;

typedef struct {
    skcp_cmd_header_t header;
    char flg;
    uint32_t payload_len;
    char payload[];
} skcp_cmd_conn_t;

typedef struct {
    skcp_cmd_header_t header;
    char code;
    uint32_t payload_len;
    char payload[];
} skcp_cmd_conn_ack_t;

typedef struct {
    skcp_cmd_header_t header;
    uint32_t payload_len;
    char payload[];
} skcp_cmd_data_t;

typedef struct {
    skcp_cmd_header_t header;
} skcp_cmd_close_t;

typedef struct {
    skcp_cmd_header_t header;
    uint32_t payload_len;
    char payload[];
} skcp_cmd_ctrl_t;

#define SKCP_ENCODE_CMD_HEADER(vbuf, vheader) \
    do {                                      \
        *(vbuf) = (vheader).name;             \
        *((vbuf) + 1) = (vheader).ver;        \
        *((vbuf) + 2) = (vheader).type;       \
    } while (0)

#define SKCP_DECODE_CMD_HEADER(vheader, vbuf) \
    do {                                      \
        (vheader).name = *(vbuf);             \
        (vheader).ver = *((vbuf) + 1);        \
        (vheader).type = *((vbuf) + 2);       \
    } while (0)

#define SKCP_BUILD_CMD_HEADER(vheader, vtype) \
    do {                                      \
        (vheader).name = SKCP_PROTOCOL_NAME;  \
        (vheader).ver = SKCP_PROTOCOL_VER_1;  \
        (vheader).type = (vtype);             \
    } while (0)

#define SKCP_BUILD_CMD_CONN(vcmd, vflg, vpayload_len, vpayload)  \
    do {                                                         \
        (vcmd) = malloc(sizeof(skcp_cmd_conn_t) + vpayload_len); \
        SKCP_BUILD_CMD_HEADER((vcmd)->header, SKCP_CMD_CONN);    \
        (vcmd)->flg = (vflg);                                    \
        (vcmd)->payload_len = (vpayload_len);                    \
        memcpy((vcmd)->payload, (vpayload), (vpayload_len));     \
    } while (0)

#define SKCP_BUILD_CMD_CONN_ACK(vcmd, vcode, vpayload_len, vpayload) \
    do {                                                             \
        (vcmd) = malloc(sizeof(skcp_cmd_conn_ack_t) + vpayload_len); \
        SKCP_BUILD_CMD_HEADER((vcmd)->header, SKCP_CMD_CONN);        \
        (vcmd)->code = (vcode);                                      \
        (vcmd)->payload_len = (vpayload_len);                        \
        memcpy((vcmd)->payload, (vpayload), (vpayload_len));         \
    } while (0)

#define SKCP_BUILD_CMD_CLOSE(vcmd)                             \
    do {                                                       \
        (vcmd) = malloc(sizeof(skcp_cmd_close_t));             \
        SKCP_BUILD_CMD_HEADER((vcmd)->header, SKCP_CMD_CLOSE); \
    } while (0)

#define SKCP_BUILD_CMD_DATA(vcmd, vpayload_len, vpayload)        \
    do {                                                         \
        (vcmd) = malloc(sizeof(skcp_cmd_data_t) + vpayload_len); \
        SKCP_BUILD_CMD_HEADER((vcmd)->header, SKCP_CMD_DATA);    \
        (vcmd)->payload_len = (vpayload_len);                    \
        memcpy((vcmd)->payload, (vpayload), (vpayload_len));     \
    } while (0)

#define SKCP_BUILD_CMD_CTRL(vcmd, vpayload_len, vpayload)        \
    do {                                                         \
        (vcmd) = malloc(sizeof(skcp_cmd_ctrl_t) + vpayload_len); \
        SKCP_BUILD_CMD_HEADER((vcmd)->header, SKCP_CMD_CTRL);    \
        (vcmd)->payload_len = (vpayload_len);                    \
        memcpy((vcmd)->payload, (vpayload), (vpayload_len));     \
    } while (0)

char *skcp_encode_cmd_conn(skcp_cmd_conn_t *cmd, int *len);
skcp_cmd_conn_t *skcp_decode_cmd_conn(char *buf, int len);
char *skcp_encode_cmd_conn_ack(skcp_cmd_conn_ack_t *cmd, int *len);
skcp_cmd_conn_ack_t *skcp_decode_cmd_conn_ack(char *buf, int len);
char *skcp_encode_cmd_data(skcp_cmd_data_t *cmd, int *len);
skcp_cmd_data_t *skcp_decode_cmd_data(char *buf, int len);
char *skcp_encode_cmd_close(skcp_cmd_close_t *cmd, int *len);
skcp_cmd_close_t *skcp_decode_cmd_close(char *buf, int len);
char *skcp_encode_cmd_ctrl(skcp_cmd_ctrl_t *cmd, int *len);
skcp_cmd_ctrl_t *skcp_decode_cmd_ctrl(char *buf, int len);

#endif  // SKCP_PROTOCOL_H