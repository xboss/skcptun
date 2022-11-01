#include "skt_kcp.h"

int skt_kcp_recv(skt_kcp_conn_t *conn, char *buf, int len) {
    int recv_len = ikcp_recv(conn->kcp, buf, len);
    if (recv_len > 0) {
        ikcp_update(conn->kcp, clock());  // TODO: 可以性能优化
    }
    return recv_len;
}