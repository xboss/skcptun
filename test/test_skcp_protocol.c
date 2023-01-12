
#include <assert.h>
#include <stdio.h>

#include "skcp_protocol.h"

#define FREE_IF(p)    \
    do {              \
        if (p) {      \
            free(p);  \
            p = NULL; \
        }             \
    } while (0)

static void test_cmd() {
    // encode
    skcp_cmd_t *cmd1;
    char *str = "12345678123456781234567812345678";

    SKCP_BUILD_CMD(cmd1, SKCP_CMD_CONN, 0x00, strlen(str), str);
    int cmd_len1 = 0;
    char *cmd_buf1 = skcp_encode_cmd(cmd1, &cmd_len1);
    assert(cmd_buf1);
    assert(cmd_len1);
    assert(cmd_len1 == SKCP_CMD_HEADER_LEN + strlen(str));

    // decode
    skcp_cmd_t *cmd2 = skcp_decode_cmd(cmd_buf1, cmd_len1);
    FREE_IF(cmd_buf1);
    assert(cmd2);
    assert(cmd2->header.payload_len == strlen(str));
    assert(cmd1->header.name == cmd2->header.name);
    assert(cmd1->header.ver == cmd2->header.ver);
    assert(cmd1->header.type == cmd2->header.type);
    assert(cmd1->header.flg == cmd2->header.flg);
    assert(cmd1->header.payload_len == cmd2->header.payload_len);
    for (int i = 0; i < cmd1->header.payload_len; i++) {
        assert(cmd1->payload[i] == cmd2->payload[i]);
    }
    FREE_IF(cmd1);
    FREE_IF(cmd2);
    printf("cmd test ok!\n");
}

int main(int argc, char *argv[]) {
    test_cmd();

    return 0;
}