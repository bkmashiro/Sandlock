#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
int main() {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(80)};
    inet_pton(AF_INET, "93.184.216.34", &addr.sin_addr);
    connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    printf("connected\n");
    return 0;
}
