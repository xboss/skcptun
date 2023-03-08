// #include "skt_protocol.h"

// #include <stdio.h>
// #include <string.h>

// char *skt_encode_seg(char flg, char type, const char *buf, int len, int *out_len) {
//     char *raw = (char *)calloc(1, SKT_SEG_HEADER_LEN + len);
//     memcpy(raw, SKT_SEG_NAME, 2);
//     *(raw + 2) = SKT_SEG_VER_1;
//     *(raw + 3) = flg;
//     *(raw + 4) = type;
//     uint32_t payload_len = htonl(len);
//     memcpy(raw + 5, &payload_len, 4);
//     if (len > 0) {
//         memcpy(raw + SKT_SEG_HEADER_LEN, buf, len);
//     }
//     *out_len = len + SKT_SEG_HEADER_LEN;

//     return raw;
// }

// skt_seg_t *skt_decode_seg(const char *buf, int len) {
//     skt_seg_t *seg = (skt_seg_t *)_ALLOC(sizeof(skt_seg_t) + (len - SKT_SEG_HEADER_LEN));

//     memcpy(seg->name, buf, 2);
//     seg->ver = *(buf + 2);
//     seg->flg = *(buf + 3);
//     seg->type = *(buf + 4);
//     seg->payload_len = ntohl(*(uint32_t *)(buf + 5));
//     if (len > SKT_SEG_HEADER_LEN) {
//         memcpy(seg->payload, buf + SKT_SEG_HEADER_LEN, seg->payload_len);
//     }
//     return seg;
// }
