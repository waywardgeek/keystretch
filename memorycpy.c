// This file simply fills 2GB of RAM with no hashing.  It's a useful benchmark for
// keystretch, which hopefully should aproach this speed.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MEM_SIZE (1LL << 32)
#define MEM_LENGTH (MEM_SIZE/sizeof(unsigned long long))
#define BLOCK_SIZE (1LL << 14)
#define BLOCK_LENGTH (BLOCK_SIZE/sizeof(unsigned long long))
#define BLOCK_MASK ((BLOCK_LENGTH-1) & ~7)
#define KEY_SIZE 64
#define KEY_LENGTH (KEY_SIZE/sizeof(unsigned long long))
#define KEY_MASK (KEY_LENGTH-1)

int main() {
    unsigned long long *mem = (unsigned long long *)malloc(MEM_SIZE);
    memcpy(mem + (MEM_LENGTH >> 1), mem, (MEM_LENGTH >> 1)*sizeof(unsigned long long));
    printf("%u\n", ((unsigned int *)mem)[rand() % MEM_LENGTH]);
    return 0;
}
