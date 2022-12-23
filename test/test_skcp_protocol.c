
#include <assert.h>
#include <stdio.h>

#include "../src/skcp_protocol.h"

#define FREE_IF(p)    \
    do {              \
        if (p) {      \
            free(p);  \
            p = NULL; \
        }             \
    } while (0)

static void test_cmd_conn() {
    // encode
    skcp_cmd_conn_t *cmd1;
    char *str = "12345678123456781234567812345678";
    SKCP_BUILD_CMD_CONN(cmd1, SKCP_CMD_CONN_NEED_ENCRYPT, strlen(str), str);
    int cmd_len1 = 0;
    char *cmd_buf1 = skcp_encode_cmd_conn(cmd1, &cmd_len1);
    assert(cmd_buf1);

    // decode
    skcp_cmd_conn_t *cmd2 = skcp_decode_cmd_conn(cmd_buf1, cmd_len1);
    FREE_IF(cmd_buf1);
    assert(cmd2);
    assert(cmd2->payload_len == strlen(str));
    assert(strcmp(cmd2->payload, str) == 0);
    assert(cmd1->header.name == cmd2->header.name);
    assert(cmd1->header.ver == cmd2->header.ver);
    assert(cmd1->header.type == cmd2->header.type);
    assert(cmd1->flg == cmd2->flg);
    assert(cmd1->payload_len == cmd2->payload_len);
    for (int i = 0; i < cmd1->payload_len; i++) {
        assert(cmd1->payload[i] == cmd2->payload[i]);
    }
    FREE_IF(cmd1);
    FREE_IF(cmd2);
    printf("cmd conn test ok!\n");
}

static void test_cmd_conn_ack() {
    // encode
    skcp_cmd_conn_ack_t *cmd1;
    char *str = "12345678123456781234567812345678";
    SKCP_BUILD_CMD_CONN_ACK(cmd1, 0x00, strlen(str), str);
    int cmd_len1 = 0;
    char *cmd_buf1 = skcp_encode_cmd_conn_ack(cmd1, &cmd_len1);
    assert(cmd_buf1);

    // decode
    skcp_cmd_conn_ack_t *cmd2 = skcp_decode_cmd_conn_ack(cmd_buf1, cmd_len1);
    FREE_IF(cmd_buf1);
    assert(cmd2);
    assert(cmd2->payload_len == strlen(str));
    assert(strcmp(cmd2->payload, str) == 0);
    assert(cmd1->header.name == cmd2->header.name);
    assert(cmd1->header.ver == cmd2->header.ver);
    assert(cmd1->header.type == cmd2->header.type);
    assert(cmd1->code == cmd2->code);
    assert(cmd1->payload_len == cmd2->payload_len);
    for (int i = 0; i < cmd1->payload_len; i++) {
        assert(cmd1->payload[i] == cmd2->payload[i]);
    }
    FREE_IF(cmd1);
    FREE_IF(cmd2);
    printf("cmd conn ack test ok!\n");
}

static void test_cmd_data() {
    // encode
    skcp_cmd_data_t *cmd1;
    char *str = "adsklfjasdflonqoaidfjouadjfnaosd";
    SKCP_BUILD_CMD_DATA(cmd1, strlen(str), str);
    int cmd_len1 = 0;
    char *cmd_buf1 = skcp_encode_cmd_data(cmd1, &cmd_len1);
    assert(cmd_buf1);

    // decode
    skcp_cmd_data_t *cmd2 = skcp_decode_cmd_data(cmd_buf1, cmd_len1);
    FREE_IF(cmd_buf1);
    assert(cmd2);
    assert(cmd2->payload_len == strlen(str));
    assert(strcmp(cmd2->payload, str) == 0);
    assert(cmd1->header.name == cmd2->header.name);
    assert(cmd1->header.ver == cmd2->header.ver);
    assert(cmd1->header.type == cmd2->header.type);
    assert(cmd1->payload_len == cmd2->payload_len);
    for (int i = 0; i < cmd1->payload_len; i++) {
        assert(cmd1->payload[i] == cmd2->payload[i]);
    }
    FREE_IF(cmd1);
    FREE_IF(cmd2);
    printf("cmd data test ok!\n");
}

static void test_cmd_ctrl() {
    // encode
    skcp_cmd_ctrl_t *cmd1;
    char *str = "sddff";
    SKCP_BUILD_CMD_CTRL(cmd1, strlen(str), str);
    int cmd_len1 = 0;
    char *cmd_buf1 = skcp_encode_cmd_ctrl(cmd1, &cmd_len1);
    assert(cmd_buf1);

    // decode
    skcp_cmd_ctrl_t *cmd2 = skcp_decode_cmd_ctrl(cmd_buf1, cmd_len1);
    FREE_IF(cmd_buf1);
    assert(cmd2);
    assert(cmd2->payload_len == strlen(str));
    assert(strcmp(cmd2->payload, str) == 0);
    assert(cmd1->header.name == cmd2->header.name);
    assert(cmd1->header.ver == cmd2->header.ver);
    assert(cmd1->header.type == cmd2->header.type);
    assert(cmd1->payload_len == cmd2->payload_len);
    for (int i = 0; i < cmd1->payload_len; i++) {
        assert(cmd1->payload[i] == cmd2->payload[i]);
    }
    FREE_IF(cmd1);
    FREE_IF(cmd2);
    printf("cmd ctrl test ok!\n");
}

static void test_cmd_close() {
    // encode
    skcp_cmd_close_t *cmd1;
    SKCP_BUILD_CMD_CLOSE(cmd1);
    int cmd_len1 = 0;
    char *cmd_buf1 = skcp_encode_cmd_close(cmd1, &cmd_len1);
    assert(cmd_buf1);

    // decode
    skcp_cmd_close_t *cmd2 = skcp_decode_cmd_close(cmd_buf1, cmd_len1);
    FREE_IF(cmd_buf1);
    assert(cmd2);
    assert(cmd1->header.name == cmd2->header.name);
    assert(cmd1->header.ver == cmd2->header.ver);
    assert(cmd1->header.type == cmd2->header.type);
    FREE_IF(cmd1);
    FREE_IF(cmd2);
    printf("cmd close test ok!\n");
}

int main(int argc, char *argv[]) {
    test_cmd_conn();
    test_cmd_conn_ack();
    test_cmd_data();
    test_cmd_ctrl();
    test_cmd_close();

    return 0;
}