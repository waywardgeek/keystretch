// This file simply fills 2GB of RAM with no hashing.  It's a useful benchmark for
// keystretch, which hopefully should aproach this speed.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MEM_SIZE (1LL << 31)
#define MEM_LENGTH (MEM_SIZE/sizeof(unsigned long long))
#define BLOCK_SIZE (1LL << 14)
#define BLOCK_LENGTH (BLOCK_SIZE/sizeof(unsigned long long))
#define BLOCK_MASK ((BLOCK_LENGTH-1) & ~7)
#define KEY_SIZE 64
#define KEY_LENGTH (KEY_SIZE/sizeof(unsigned long long))
#define KEY_MASK (KEY_LENGTH-1)

int main() {
    unsigned long long *mem = (unsigned long long *)malloc(MEM_SIZE);
    unsigned long long i, j, k;
    unsigned long long hash = 0x12345;
    unsigned long long *sourceBlock;
    unsigned long long *destBlock, *sourceLine, *destLine;
    unsigned long long keyData, pageData, lastPageData = 0;
    unsigned long long key[KEY_LENGTH] = {0,};
    printf("blockLen: %llu, memLen:%llu\n", BLOCK_LENGTH, MEM_LENGTH);
    // Initialize 1st page
    for(i = 0; i < BLOCK_LENGTH; i++) {
        mem[i] = 0;
    }
    for(i = 1; i < MEM_LENGTH/BLOCK_LENGTH; i++) {
        sourceBlock = mem + (hash % i)*BLOCK_LENGTH;
        destBlock = mem + i*BLOCK_LENGTH;
        for(j = 0; j < BLOCK_LENGTH; j += 8) {
            sourceLine = sourceBlock + (hash & BLOCK_MASK);
            destLine = destBlock + j;
            for(k = 0; k < 8; k++) {
                pageData = sourceLine[k];
                keyData = key[k];
                hash += (pageData*keyData) ^ lastPageData;
                key[k] = hash;
                destLine[k] = hash;
                lastPageData = pageData;
            }
        }
    }
    // Force the optimizer to keep the memory
    printf("%u\n", ((unsigned int *)mem)[rand() % MEM_LENGTH]);
    return 0;
}
