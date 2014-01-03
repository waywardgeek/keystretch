// This file simply fills 2GB of RAM with no hashing.  It's a useful benchmark for
// keystretch, which hopefully should aproach this speed.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define MEM_SIZE (1LL << 31)
#define MEM_LENGTH (MEM_SIZE/sizeof(unsigned long long))
#define NUM_THREADS 2

static void *moveMem(void *memPtr) {
    unsigned long long *mem = (unsigned long long *)memPtr;
    memmove(mem, mem + 8, (MEM_LENGTH-1)*sizeof(unsigned long long)/NUM_THREADS);
    pthread_exit(NULL);
}

int main() {
    pthread_t threads[NUM_THREADS];
    unsigned long long *mem = (unsigned long long *)malloc(MEM_SIZE);
    int rc;
    long t;
    for(t = 0; t < NUM_THREADS; t++) {
        rc = pthread_create(&threads[t], NULL, moveMem, (void *)(mem + t*MEM_LENGTH/NUM_THREADS));
        if (rc){
            fprintf(stderr, "Unable to start threads\n");
            return 1;
        }
    }
    // Wait for threads to finish
    for(t = 0; t < NUM_THREADS; t++) {
        (void)pthread_join(threads[t], NULL);
    }
    printf("%u\n", ((unsigned int *)mem)[rand() % MEM_LENGTH]);
    return 0;
}
