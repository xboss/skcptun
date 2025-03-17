#ifndef _PACKET_QUEUE_H
#define _PACKET_QUEUE_H

#include <stddef.h>

typedef struct packet_node_t {
    unsigned char* data;    // 数据包内容
    size_t length;          // 数据包长度(1-1500)
    struct packet_node_t* next;
} packet_node_t;

typedef struct {
    packet_node_t* head;       // 队列头部
    packet_node_t* tail;       // 队列尾部
    size_t count;           // 数据包计数
    size_t mem_usage;       // 总内存使用量
} packet_queue_t;

// 初始化队列
packet_queue_t* packet_queue_create();

// 销毁队列
void packet_queue_destroy(packet_queue_t* q);

// 入队操作（拷贝数据）
int packet_queue_enqueue(packet_queue_t* q, const unsigned char* data, size_t length);

// 出队操作（转移数据所有权）
int packet_queue_dequeue(packet_queue_t* q, unsigned char** out_data, size_t* out_length);

// 获取队列状态
size_t packet_queue_count(const packet_queue_t* q);
size_t packet_queue_mem_usage(const packet_queue_t* q);


#endif /* _PACKET_QUEUE_H */