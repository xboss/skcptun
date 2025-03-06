#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "ssudp.h"

int main() {
    const char* local_ip = "127.0.0.1";
    uint16_t local_port = 12345;
    const char* remote_ip = "127.0.0.1";
    uint16_t remote_port = 54321;

    ssudp_t* ssudp = ssudp_init(local_ip, local_port, remote_ip, remote_port);
    if (!ssudp) {
        fprintf(stderr, "Failed to initialize ssudp\n");
        return 1;
    }

    const char* message = "Hello, ssudp!";
    ssize_t sent_len = ssudp_send(ssudp, message, strlen(message));
    if (sent_len < 0) {
        perror("ssudp_send");
        ssudp_free(ssudp);
        return 1;
    }
    printf("Sent %zd bytes: %s\n", sent_len, message);

    char buffer[1024];
    ssize_t recv_len = ssudp_recv(ssudp, buffer, sizeof(buffer) - 1);
    if (recv_len < 0) {
        perror("ssudp_recv");
        ssudp_free(ssudp);
        return 1;
    }
    buffer[recv_len] = '\0';
    printf("Received %zd bytes: %s\n", recv_len, buffer);

    ssudp_free(ssudp);
    return 0;
}
