#include <assert.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sstcp.h"

static char* target_ip = NULL;
static uint16_t target_port = 0;

static void handle_front(int front_fd, sstcp_server_t* server) {
    _LOG("handle_front accept: %d", front_fd);
    // printf("handle_front accept: %d\n", front_fd);
    sstcp_client_t* backend = sstcp_create_client();
    assert(backend);
    assert(target_ip);
    assert(target_port > 0);
    int ret = sstcp_connect(backend, target_ip, target_port);
    _LOG("sstcp_connect end. %d", backend->client_fd);
    assert(ret == _OK);

    char buf[1024 * 16] = {0};
    int infd = 0;
    int outfd = 0;
    ssize_t sent = 0, n = 0, m = 0;
    struct pollfd fds[2] = {{.fd = front_fd, .events = POLLIN}, {.fd = backend->client_fd, .events = POLLIN}};
    while (1) {
        _LOG("poll start");
        ret = poll(fds, 2, 1000 * 10);
        _LOG("poll end. %d", ret);
        if (ret < 0) {
            perror("poll failed");
            break;
        } else if (ret == 0) {
            _LOG("poll timeout.");
            // printf("poll timeout.\n");
            continue;
        }

        infd = (fds[0].revents & POLLIN) ? front_fd : backend->client_fd;
        outfd = infd == backend->client_fd ? front_fd : backend->client_fd;
        sent = 0;
        _LOG("read start. %d", infd);
        n = read(infd, buf, sizeof buf);
        _LOG("read end. %d", infd);
        if (n <= 0) break;
        while (sent < n) {
            _LOG("write start. %d", outfd);
            m = write(outfd, buf + sent, n - sent);
            _LOG("write end. %d", outfd);
            if (m < 0) break;
            sent += m;
        }
    }
    sstcp_close(backend->client_fd);
    sstcp_free_client(backend);
    _LOG("handle_front exit.");
    // printf("handle_front exit.\n");
}

int main(int argc, char const* argv[]) {
    assert(argc >= 4);
    assert(argv[1]);
    assert(argv[2]);
    target_ip = (char*)argv[1];
    target_port = atoi(argv[2]);
    assert(target_port > 0);
    sslog_init(NULL, SSLOG_LEVEL_DEBUG);
    char* listen_ip = "0.0.0.0";
    int listen_port = atoi(argv[3]);
    ;
    sstcp_server_t* server = sstcp_create_server(listen_ip, listen_port, handle_front, NULL);
    assert(server);
    sstcp_start_server(server);
    return 0;
}
