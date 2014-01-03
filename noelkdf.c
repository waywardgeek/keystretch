// This file simply fills 2GB of RAM with no hashing.  It's a useful benchmark for
// keystretch, which hopefully should aproach this speed.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "sha256.h"

typedef unsigned char uint8;
typedef unsigned long long uint64;

#define NUM_THREADS 1
#define TOTAL_MEM (1LL << 31) // 2GB
#define PAGE_LENGTH ((16*1024)/sizeof(uint64)) // 16KB
#define NUM_PAGES (TOTAL_MEM/(NUM_THREADS*sizeof(uint64)*PAGE_LENGTH))
#define MEM_LENGTH (NUM_PAGES*PAGE_LENGTH)

static char *salt = "this is a dummy salt";

struct ContextStruct {
    uint64 *mem;
    long threadId;
};

// Hash the next page.
static inline void hashPage(uint64 *toPage, uint64 *prevPage, uint64 *fromPage) {
    uint64 i;
    *toPage++ = *prevPage + ((*fromPage * *(prevPage + 1)) ^ *(fromPage - 1 + PAGE_LENGTH));
    prevPage++;
    fromPage++;
    for(i = 1; i < PAGE_LENGTH - 1; i++) {
        *toPage++ = *prevPage + ((*fromPage * *(prevPage + 1)) ^ *(fromPage - 1));
        prevPage++;
        fromPage++;
    }
    *toPage = *prevPage + ((*fromPage * *(prevPage + 1 - PAGE_LENGTH)) ^ *(fromPage - 1));
}

static void *hashMem(void *contextPtr) {
    struct ContextStruct *c = (struct ContextStruct *)contextPtr;
    uint64 *mem = c->mem;

    // Initialize first page
    PBKDF2_SHA256((uint8 *)&(c->threadId), sizeof(long), (uint8 *)salt, sizeof(salt), 1,
        (uint8 *)(void *)mem, PAGE_LENGTH*sizeof(uint64));

    // Create pages sequentially by hashing the previous page with a random page.
    uint64 i;
    uint64 *toPage = mem + PAGE_LENGTH, *fromPage, *prevPage = mem;
    for(i = 1; i < NUM_PAGES; i++) {
        // Select a random from page
        fromPage = mem + PAGE_LENGTH*(*prevPage % i);
        hashPage(toPage, prevPage, fromPage);
        prevPage = toPage;
        toPage += PAGE_LENGTH;
    }

/* For benchmark comparison: this is fast
    uint64 i, j;
    for(i = 0, j = 1; i < MEM_LENGTH - 1; i++, j++) {
        mem[i] = mem[j] + i;
    }
*/

    printf("%llu\n", mem[rand() % MEM_LENGTH]);
    pthread_exit(NULL);
}

int main() {
    uint64 *mem = (uint64 *)malloc(MEM_LENGTH*NUM_THREADS*sizeof(uint64));
    pthread_t threads[NUM_THREADS];
    struct ContextStruct c[NUM_THREADS];
    int rc;
    long t;
    for(t = 0; t < NUM_THREADS; t++) {
        c[t].mem = mem + t*MEM_LENGTH;
        c[t].threadId = t;
        rc = pthread_create(&threads[t], NULL, hashMem, (void *)(c + t));
        if (rc){
            fprintf(stderr, "Unable to start threads\n");
            return 1;
        }
    }
    // Wait for threads to finish
    for(t = 0; t < NUM_THREADS; t++) {
        (void)pthread_join(threads[t], NULL);
    }
    return 0;
}
