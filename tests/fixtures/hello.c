#include <stdio.h>

static int sum(int a, int b) { return a + b; }

int main(void) {
    printf("Headless IDA smoke test: %d\n", sum(20, 22));
    return 0;
}
