#include <stdio.h>
int main() {
    FILE *f = fopen("/etc/passwd", "r");
    char buf[100];
    fread(buf, 1, 100, f);
    printf("%s", buf);
    return 0;
}
