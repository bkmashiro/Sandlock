#include <stdio.h>
#include <math.h>
int main() {
    double sum = 0;
    for (int i = 0; i < 1000; i++) sum += sqrt(i);
    printf("%.2f\n", sum);
    return 0;
}
