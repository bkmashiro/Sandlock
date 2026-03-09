#include <sys/ptrace.h>
#include <stdio.h>
int main() {
    long ret = ptrace(PTRACE_TRACEME, 0, 0, 0);
    printf("ptrace returned %ld\n", ret);
    return 0;
}
