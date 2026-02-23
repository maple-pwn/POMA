#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void win() { system("/bin/sh"); }

void vuln() {
    char buf[64];
    printf("Input: ");
    read(0, buf, 0x100);
    printf("You said: %s\n", buf);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    printf("Welcome to ret2win!\n");
    vuln();
    printf("Goodbye!\n");
    return 0;
}
