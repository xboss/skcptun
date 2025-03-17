#include "packet_queue.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// 测试基础功能
void test_basic_operations() {
    packet_queue_t* q = packet_queue_create();
    assert(q != NULL);
    assert(packet_queue_count(q) == 0);

    // 合法数据包测试
    unsigned char test_data[1500];
    memset(test_data, 0xAA, sizeof(test_data));
    
    // 入队测试
    assert(packet_queue_enqueue(q, test_data, 1500) == 1);
    assert(packet_queue_count(q) == 1);
    assert(packet_queue_mem_usage(q) == 1500 + sizeof(packet_node_t));

    // 出队测试
    unsigned char* out_data;
    size_t out_len;
    assert(packet_queue_dequeue(q, &out_data, &out_len) == 1);
    assert(out_len == 1500);
    assert(memcmp(out_data, test_data, out_len) == 0);
    free(out_data);
    
    assert(packet_queue_count(q) == 0);
    packet_queue_destroy(q);
}

// 边界条件测试
void test_edge_cases() {
    packet_queue_t* q = packet_queue_create();
    
    // 最小数据包测试
    unsigned char min_data = 0xFF;
    assert(packet_queue_enqueue(q, &min_data, 1) == 1);
    
    // 非法长度测试
    assert(packet_queue_enqueue(q, NULL, 0) == 0);   // 长度过小
    assert(packet_queue_enqueue(q, NULL, 1501) == 0); // 长度过大
    
    // 空队列出队测试
    unsigned char* data;
    size_t len;
    assert(packet_queue_dequeue(q, &data, &len) == 1); // 取出最小包
    free(data);
    assert(packet_queue_dequeue(q, &data, &len) == 0); // 队列已空
    
    packet_queue_destroy(q);
}

// 压力测试
void test_high_performance() {
    packet_queue_t* q = packet_queue_create();
    const int TOTAL = 100000;
    unsigned char buf[100];

    // 批量入队
    for (int i = 0; i < TOTAL; i++) {
        memset(buf, i % 256, sizeof(buf));
        assert(packet_queue_enqueue(q, buf, sizeof(buf)));
    }

    // 批量出队
    for (int i = 0; i < TOTAL; i++) {
        unsigned char* data;
        size_t len;
        assert(packet_queue_dequeue(q, &data, &len));
        assert(len == sizeof(buf));
        assert(data[0] == (i % 256));
        free(data);
    }

    assert(packet_queue_count(q) == 0);
    packet_queue_destroy(q);
}

int main() {
    test_basic_operations();
    test_edge_cases();
    test_high_performance();
    
    printf("All tests passed!\n");
    return 0;
}
