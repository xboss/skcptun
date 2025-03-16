#include "packet_queue.h"
#include <stdlib.h>
#include <string.h>

#define _OK 0
#define _ERR -1

#define MAX_PACKET_SIZE 1500
#define MIN_PACKET_SIZE 1

packet_queue_t* packet_queue_create() {
    return (packet_queue_t*)calloc(1, sizeof(packet_queue_t));
}

void packet_queue_destroy(packet_queue_t* q) {
    if (q) {
        while (q->head) {
            packet_node_t* temp = q->head;
            q->head = q->head->next;
            free(temp->data);
            free(temp);
        }
        free(q);
    }
}

int packet_queue_enqueue(packet_queue_t* q, const unsigned char* data, size_t length) {
    if (!q || !data || length < MIN_PACKET_SIZE || length > MAX_PACKET_SIZE) {
        return _ERR;
    }

    // 创建新节点
    packet_node_t* node = (packet_node_t*)malloc(sizeof(packet_node_t));
    if (!node) return _ERR;

    // 拷贝数据
    node->data = (unsigned char*)malloc(length);
    if (!node->data) {
        free(node);
        return _ERR;
    }
    
    memcpy(node->data, data, length);
    node->length = length;
    node->next = NULL;

    // 更新队列状态
    if (q->tail) {
        q->tail->next = node;
    } else {
        q->head = node;
    }
    q->tail = node;
    q->count++;
    q->mem_usage += length + sizeof(packet_node_t);
    
    return _OK;
}

int packet_queue_dequeue(packet_queue_t* q, unsigned char** out_data, size_t* out_length) {
    if (!q || !q->head || !out_data || !out_length) return _ERR;

    // 转移数据所有权
    packet_node_t* temp = q->head;
    *out_data = temp->data;
    *out_length = temp->length;

    // 更新队列状态
    q->head = q->head->next;
    if (!q->head) q->tail = NULL;
    q->count--;
    q->mem_usage -= temp->length + sizeof(packet_node_t);
    
    free(temp);
    return _OK;
}

size_t packet_queue_count(const packet_queue_t* q) {
    return q ? q->count : 0;
}

size_t packet_queue_mem_usage(const packet_queue_t* q) {
    return q ? q->mem_usage : 0;
}
