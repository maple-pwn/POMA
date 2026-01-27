// Decompiled from binary using IDA/Ghidra

void win(void) {
    system("/bin/sh");
    return;
}

void vuln(void) {
    char buf[64];
    
    printf("Input: ");
    gets(buf);
    printf("You said: %s\n", buf);
    return;
}

int main(void) {
    setvbuf(stdout, NULL, 2, 0);
    setvbuf(stdin, NULL, 2, 0);
    
    printf("Welcome to ret2win!\n");
    vuln();
    printf("Goodbye!\n");
    return 0;
}
