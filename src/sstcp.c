#include "sstcp.h"

#include <assert.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void setreuseaddr(int fd) {
    int reuse = 1;
    if (-1 == setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))) {
        perror("set reuse addr error");
    }
}

// 客户端线程函数
static void* client_thread(void* arg) {
    int client_socket = *(int*)arg;
    sstcp_server_t* server = (sstcp_server_t*)(((void**)arg)[1]);
    assert(server);
    assert(server->handler);
    assert(client_socket >= 0);
    free(arg);

    // 调用客户端处理函数
    server->handler(client_socket, server);

    // 关闭客户端套接字
    sstcp_close(client_socket);
    _LOG("client_thread exit.");
    return 0;
}

// 创建服务器
sstcp_server_t* sstcp_create_server(const char* bind_ip, int port, sstcp_client_thread_cb_t handler, void* user_data) {
    if (!bind_ip || port <= 0 || !handler) 
        return NULL;
    
    sstcp_server_t* server = (sstcp_server_t*)calloc(1, sizeof(sstcp_server_t));
    if (!server) return NULL;

    server->port = port;
    server->server_fd = -1;
    server->running = 0;
    server->handler = handler;
    server->user_data = user_data;
    // server->threads = NULL;

    // 设置绑定IP
    if (bind_ip) {
        strncpy(server->bind_ip, bind_ip, INET_ADDRSTRLEN);
        if (strnlen(server->bind_ip, INET_ADDRSTRLEN) == 0) {
            free(server);
            return NULL;
        }
    }

    return server;
}

// 启动服务器
int sstcp_start_server(sstcp_server_t* server) {
    if (!server) {
        return _ERR;
    }

    struct sockaddr_in address;
    int addrlen = sizeof(address);

    // 创建套接字
    if ((server->server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        return _ERR;
    }

    setreuseaddr(server->server_fd);

    // 绑定套接字
    address.sin_family = AF_INET;
    address.sin_port = htons(server->port);
    if (strnlen(server->bind_ip, INET_ADDRSTRLEN) == 0)
        address.sin_addr.s_addr = INADDR_ANY;
    else
        address.sin_addr.s_addr = inet_addr(server->bind_ip);

    if (bind(server->server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        return _ERR;
    }

    // 监听
    if (listen(server->server_fd, 10) < 0) {
        perror("Listen failed");
        return _ERR;
    }

    _LOG("Server is listening on port %d server_fd %d", server->port, server->server_fd);
    server->running = 1;

    while (server->running) {
        // 接受连接
        int new_socket;
        if ((new_socket = accept(server->server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) < 0) {
            _LOG_E("Accept failed server_fd %d new_socket %d", server->server_fd, new_socket);
            perror("Accept failed");
            continue;
        }

        _LOG("New client connected fd:%d", new_socket);

        // 为每个客户端创建一个线程
        void** arg = (void**)malloc(2 * sizeof(void*));
        arg[0] = (void*)(intptr_t)new_socket;
        arg[1] = (void*)server;

        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, client_thread, arg) != 0) {
            perror("Thread creation failed");
            free(arg);
            continue;
        }
        pthread_detach(thread_id);  // 分离线程，避免资源泄漏
    }
    return _OK;
}

// 停止服务器
void sstcp_stop_server(sstcp_server_t* server) {
    server->running = 0;
    close(server->server_fd);
}

// 释放服务器资源
void sstcp_free_server(sstcp_server_t* server) {
    if (server) {
        free(server);
    }
}

// 创建客户端
sstcp_client_t* sstcp_create_client() {
    sstcp_client_t* client = (sstcp_client_t*)malloc(sizeof(sstcp_client_t));
    if (!client) return NULL;

    client->client_fd = -1;
    memset(&client->server_addr, 0, sizeof(client->server_addr));

    return client;
}

// 连接到服务器
int sstcp_connect(sstcp_client_t* client, const char* server_ip, int port) {
    // 创建套接字
    if ((client->client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        return _ERR;
    }

    // 设置服务器地址
    client->server_addr.sin_family = AF_INET;
    client->server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, server_ip, &client->server_addr.sin_addr) <= 0) {
        perror("Invalid address/Address not supported");
        return _ERR;
    }

    // 连接到服务器
    if (connect(client->client_fd, (struct sockaddr*)&client->server_addr, sizeof(client->server_addr)) < 0) {
        perror("Connection failed");
        return _ERR;
    }

    _LOG("Connected to server at %s:%d", server_ip, port);
    return _OK;
}

// 发送数据
int sstcp_send(int fd, const char* data, int length) {
    return send(fd, data, length, 0);
}

// 接收数据
int sstcp_receive(int fd, char* buffer, int length) {
    return recv(fd, buffer, length, 0);
}

// 释放客户端资源
void sstcp_free_client(sstcp_client_t* client) {
    if (client) {
        free(client);
    }
}

// 设置发送超时时间
int sstcp_set_send_timeout(int fd, int timeout_ms) {
    if (fd < 0 || timeout_ms < 0) {
        return _ERR;
    }
    // client->send_timeout = timeout_ms;
    struct timeval timeout;
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;

    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout)) < 0) {
        perror("Failed to set send timeout");
        return _ERR;
    }
    return _OK;
}

// 设置接收超时时间
int sstcp_set_recv_timeout(int fd, int timeout_ms) {
    if (fd < 0 || timeout_ms < 0) {
        return _ERR;
    }
    // client->recv_timeout = timeout_ms;
    struct timeval timeout;
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) < 0) {
        perror("Failed to set receive timeout");
        return _ERR;
    }
    return _OK;
}

int sstcp_set_nodelay(int fd) {
    int opt = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char*)&opt, sizeof(opt)) < 0) {
        perror("Failed to set TCP_NODELAY");
        return _ERR;
    }
    return _OK;
}

// 关闭连接
void sstcp_close(int fd) {
    close(fd);
    _LOG("close tcp connection fd:%d", fd);
}