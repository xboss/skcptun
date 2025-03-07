#ifndef _SSTCP_H
#define _SSTCP_H

#include <arpa/inet.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>

#include "skt.h"

// 定义服务器结构体
typedef struct sstcp_server_s sstcp_server_t;

// 回调函数类型定义
typedef void (*sstcp_client_thread_cb_t)(int client_socket, sstcp_server_t *server);

struct sstcp_server_s {
    int port;                           // 服务器端口
    int server_fd;                      // 服务器套接字描述符
    volatile int running;               // 服务器运行状态
    char bind_ip[INET_ADDRSTRLEN + 1];  // 绑定的IP地址
    sstcp_client_thread_cb_t handler;   // 客户端处理函数
    void *user_data;
    // pthread_t *threads;  // POSIX 线程数组
};

// 定义客户端结构体
typedef struct {
    int client_fd;                   // 客户端套接字描述符
    struct sockaddr_in server_addr;  // 服务器地址信息
    // int send_timeout;                // 发送超时时间（毫秒）
    // int recv_timeout;                // 接收超时时间（毫秒）
} sstcp_client_t;

// 初始化服务器
sstcp_server_t *sstcp_create_server(const char *bind_ip, int port, sstcp_client_thread_cb_t handler, void *user_data);

// 启动服务器
int sstcp_start_server(sstcp_server_t *server);

// 停止服务器
void sstcp_stop_server(sstcp_server_t *server);

// 释放服务器资源
void sstcp_free_server(sstcp_server_t *server);

// 创建客户端
sstcp_client_t *sstcp_create_client();

// 连接到服务器
int sstcp_connect(sstcp_client_t *client, const char *server_ip, int port);

// 释放客户端资源
void sstcp_free_client(sstcp_client_t *client);

// 发送数据
int sstcp_send(int fd, const char *data, int length);

// 接收数据
int sstcp_receive(int fd, char *buffer, int length);

// 设置发送超时时间
int sstcp_set_send_timeout(int fd, int timeout_ms);

// 设置接收超时时间
int sstcp_set_recv_timeout(int fd, int timeout_ms);

// 设置 TCP_NODELAY 选项
int sstcp_set_nodelay(int fd);

// 关闭连接
void sstcp_close(int fd);

#endif /* _SSTCP_H */