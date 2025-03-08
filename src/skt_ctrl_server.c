#include "skt_ctrl_server.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define BACKLOG 128

static int set_nonblocking(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl F_GETFL failed");
        return _ERR;
    }
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl F_SETFL failed");
        return _ERR;
    }
    return _OK;
}

static void accept_cb(EV_P_ ev_io* w, int revents) {
    int connfd;
    struct sockaddr_in cli;
    socklen_t len = sizeof(cli);

    connfd = accept(w->fd, (struct sockaddr*)&cli, &len);
    if (connfd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // 没有新的连接，继续等待
            return;
        } else {
            perror("server accept failed");
            return;
        }
    }

    // 设置客户端连接套接字为非阻塞
    set_nonblocking(connfd);

    // ev_io_init(&client->recv_watcher, read_cb, connfd, EV_READ);
    // client->recv_watcher.data = client;
    // ev_io_start(EV_A_ & client->recv_watcher);

}

skt_ctrl_server_t* skt_ctrl_server_init(struct ev_loop* loop, skt_config_t* conf, void* user_data) {
    skt_ctrl_server_t* server = (skt_ctrl_server_t*)calloc(1, sizeof(skt_ctrl_server_t));
    if (!server) {
        perror("alloc skt ctrl server");
        return NULL;
    }

    // 创建socket
    if ((server->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket creation failed");
        return NULL;
    }

    // 设置监听套接字为非阻塞
    set_nonblocking(server->fd);

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    if (strnlen(conf->ctrl_server_ip, INET_ADDRSTRLEN) == 0)
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    else
        servaddr.sin_addr.s_addr = inet_addr(conf->ctrl_server_ip);
    servaddr.sin_port = htons(conf->ctrl_server_port);

    // 绑定socket
    if (bind(server->fd, (const struct sockaddr*)&servaddr, sizeof(servaddr)) != 0) {
        perror("socket bind failed");
        close(server->fd);
        return NULL;
    }

    // 监听socket
    if (listen(server->fd, BACKLOG) != 0) {
        perror("socket listen failed");
        close(server->fd);
        return NULL;
    }

    ev_io accept_watcher;
    ev_io_init(&accept_watcher, accept_cb, server->fd, EV_READ);
    ev_io_start(loop, &accept_watcher);

    printf("Server is running on port %d\n", conf->ctrl_server_port);
    return server;
}

int skt_ctrl_server_start(skt_ctrl_server_t* server) {
    /* TODO: */
    return _OK;
}

void skt_ctrl_server_stop(skt_ctrl_server_t* server) {
    /* TODO: */
    return;
}

void skt_ctrl_server_free(skt_ctrl_server_t* server) {
    /* TODO: */
    return;
}
