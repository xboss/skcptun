#include "skcp_protocol.h"

// #define SKCP_FREEIF(p) \
//     do {               \
//         if (p) {       \
//             free(p);   \
//             p = NULL;  \
//         }              \
//     } while (0)

/*********************skcp protocol start*********************/

char *skcp_encode_cmd(skcp_cmd_t *cmd, int *len) {
    if (!cmd || cmd->header.payload_len < 0) {
        return NULL;
    }
    *len = SKCP_CMD_HEADER_LEN + cmd->header.payload_len;
    char *buf = malloc(*len);
    SKCP_ENCODE_CMD_HEADER(buf, cmd->header);

    // memcpy(buf + 8, &payload_len, 4);
    if (cmd->header.payload_len > 0) {
        memcpy(buf + 8, cmd->payload, cmd->header.payload_len);
    }
    return buf;
}

skcp_cmd_t *skcp_decode_cmd(char *buf, int len) {
    if (!buf || len < SKCP_CMD_HEADER_LEN) {
        return NULL;
    }
    skcp_cmd_t *cmd = malloc(len);
    SKCP_DECODE_CMD_HEADER(cmd->header, buf);
    if (cmd->header.payload_len > 0) {
        // cmd->payload = malloc(cmd->payload_len);
        memcpy(cmd->payload, buf + 8, cmd->header.payload_len);
    }
    return cmd;
}

/*********************skcp protocol end*********************/
