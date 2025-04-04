#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
// 栈溢出漏洞,english
void vuln() {
    char buf[100];
    printf("Please enter a string: ");
    read(0,buf,0x200);
}

int main() {
    setvbuf(stdout, 0,2,0);
    setvbuf(stdin, 0,2,0);
    setvbuf(stderr, 0,2,0);
    vuln();
    return 0;
}
