#include "skcp_protocol.h"

#define SKCP_FREEIF(p) \
    do {               \
        if (p) {       \
            free(p);   \
            p = NULL;  \
        }              \
    } while (0)

/*********************skcp protocol start*********************/

char *skcp_encode_cmd_conn(skcp_cmd_conn_t *cmd, int *len) {
    if (!cmd || cmd->payload_len < 0) {
        return NULL;
    }
    *len = SKCP_CMD_HEADER_LEN + 5 + cmd->payload_len;
    char *buf = malloc(*len);
    SKCP_ENCODE_CMD_HEADER(buf, cmd->header);
    *(buf + 3) = cmd->flg;
    uint32_t payload_len = htonl(cmd->payload_len);
    memcpy(buf + 4, &payload_len, 4);
    if (cmd->payload_len > 0) {
        memcpy(buf + 8, cmd->payload, cmd->payload_len);
    }
    return buf;
}

skcp_cmd_conn_t *skcp_decode_cmd_conn(char *buf, int len) {
    if (!buf || len < SKCP_CMD_HEADER_LEN + 5) {
        return NULL;
    }
    skcp_cmd_conn_t *cmd = malloc(len);
    SKCP_DECODE_CMD_HEADER(cmd->header, buf);
    cmd->flg = *(buf + 3);
    cmd->payload_len = ntohl(*(uint32_t *)(buf + 4));
    if (cmd->payload_len > 0) {
        // cmd->payload = malloc(cmd->payload_len);
        memcpy(cmd->payload, buf + 8, cmd->payload_len);
    }
    return cmd;
}

char *skcp_encode_cmd_conn_ack(skcp_cmd_conn_ack_t *cmd, int *len) {
    if (!cmd || cmd->payload_len < 0) {
        return NULL;
    }
    *len = SKCP_CMD_HEADER_LEN + 5 + cmd->payload_len;
    char *buf = malloc(*len);
    SKCP_ENCODE_CMD_HEADER(buf, cmd->header);
    *(buf + 3) = cmd->code;
    uint32_t payload_len = htonl(cmd->payload_len);
    memcpy(buf + 4, &payload_len, 4);
    if (cmd->payload_len > 0) {
        memcpy(buf + 8, cmd->payload, cmd->payload_len);
    }
    return buf;
}

skcp_cmd_conn_ack_t *skcp_decode_cmd_conn_ack(char *buf, int len) {
    if (!buf || len < SKCP_CMD_HEADER_LEN + 5) {
        return NULL;
    }
    skcp_cmd_conn_ack_t *cmd = malloc(len);
    SKCP_DECODE_CMD_HEADER(cmd->header, buf);
    cmd->code = *(buf + 3);
    cmd->payload_len = ntohl(*(uint32_t *)(buf + 4));
    if (cmd->payload_len > 0) {
        // cmd->payload = malloc(cmd->payload_len);
        memcpy(cmd->payload, buf + 8, cmd->payload_len);
    }
    return cmd;
}

char *skcp_encode_cmd_data(skcp_cmd_data_t *cmd, int *len) {
    if (!cmd || cmd->payload_len < 0) {
        return NULL;
    }
    *len = SKCP_CMD_HEADER_LEN + 4 + cmd->payload_len;
    char *buf = malloc(*len);
    SKCP_ENCODE_CMD_HEADER(buf, cmd->header);
    uint32_t payload_len = htonl(cmd->payload_len);
    memcpy(buf + 3, &payload_len, 4);
    if (cmd->payload_len > 0) {
        memcpy(buf + 7, cmd->payload, cmd->payload_len);
    }
    return buf;
}

skcp_cmd_data_t *skcp_decode_cmd_data(char *buf, int len) {
    if (!buf || len < SKCP_CMD_HEADER_LEN + 4) {
        return NULL;
    }
    skcp_cmd_data_t *cmd = malloc(len);
    SKCP_DECODE_CMD_HEADER(cmd->header, buf);
    cmd->payload_len = ntohl(*(uint32_t *)(buf + 3));
    if (cmd->payload_len > 0) {
        // cmd->payload = malloc(cmd->payload_len);
        memcpy(cmd->payload, buf + 7, cmd->payload_len);
    }
    return cmd;
}

char *skcp_encode_cmd_close(skcp_cmd_close_t *cmd, int *len) {
    if (!cmd) {
        return NULL;
    }
    *len = SKCP_CMD_HEADER_LEN;
    char *buf = malloc(*len);
    SKCP_ENCODE_CMD_HEADER(buf, cmd->header);
    return buf;
}

skcp_cmd_close_t *skcp_decode_cmd_close(char *buf, int len) {
    if (!buf || len < SKCP_CMD_HEADER_LEN) {
        return NULL;
    }
    skcp_cmd_close_t *cmd = malloc(sizeof(skcp_cmd_close_t));
    SKCP_DECODE_CMD_HEADER(cmd->header, buf);
    return cmd;
}

char *skcp_encode_cmd_ctrl(skcp_cmd_ctrl_t *cmd, int *len) {
    if (!cmd || cmd->payload_len < 0) {
        return NULL;
    }
    *len = SKCP_CMD_HEADER_LEN + 4 + cmd->payload_len;
    char *buf = malloc(*len);
    SKCP_ENCODE_CMD_HEADER(buf, cmd->header);
    uint32_t payload_len = htonl(cmd->payload_len);
    memcpy(buf + 3, &payload_len, 4);
    if (cmd->payload_len > 0) {
        memcpy(buf + 7, cmd->payload, cmd->payload_len);
    }
    return buf;
}

skcp_cmd_ctrl_t *skcp_decode_cmd_ctrl(char *buf, int len) {
    if (!buf || len < SKCP_CMD_HEADER_LEN + 4) {
        return NULL;
    }
    skcp_cmd_ctrl_t *cmd = malloc(len);
    SKCP_DECODE_CMD_HEADER(cmd->header, buf);
    cmd->payload_len = ntohl(*(uint32_t *)(buf + 3));
    if (cmd->payload_len > 0) {
        // cmd->payload = malloc(cmd->payload_len);
        memcpy(cmd->payload, buf + 7, cmd->payload_len);
    }
    return cmd;
}

/*********************skcp protocol end*********************/
