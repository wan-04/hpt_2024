#include <stdio.h>
int hint()
{
    asm("pop %rdi\n");
    asm("ret");
}
int main()
{
    puts("hi there\n");

    char buffer[40];
    gets(buffer);


    return 0;
}