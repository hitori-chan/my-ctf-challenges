#include <stdio.h>

char flag[100];

int main() {
    freopen("/flag.txt", "r", stdin);
    scanf("%s", flag);
    puts(flag);
}
