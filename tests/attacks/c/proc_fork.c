#include <unistd.h>
#include <stdio.h>
int main() {
    if (fork() == 0) printf("child\n");
    else printf("parent\n");
    return 0;
}
