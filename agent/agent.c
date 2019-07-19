#include <stdio.h>


void on_load(void) __attribute__((constructor));

void on_load(void)
{
    printf("testtesttest");
}
