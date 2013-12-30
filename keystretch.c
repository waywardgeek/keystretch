// This file was wrtten by me, Bill Cox, in December of  2013.  I release it fully into
// the public domain, and disclaim any patent rights.  I believe it does not infringe on
// any current patents.
//
// Variables ending in "size" are in bytes, while variables ending in "length" are in
// 64-bit words.

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include "sha256.h"
#include "keystretch.h"

typedef struct threadContextStruct *ThreadContext;

struct threadContextStruct {
    uint64 *mem;
    uint64 *threadKeys;
    volatile uint32 *nextPageNumPtr; // This pointer points to the same value in each thread
    ThreadContext nextContext;
    uint32 pageLength;
    uint32 numPages;
    uint32 keyLength;
    volatile bool spinLock;
};

// Fill toPage, hashing with the key and fromPage as we go.
static void fillPage(ThreadContext c, uint64 *key, uint32 fromPageNum, uint32 toPageNum) {
    uint32 pageLength = c->pageLength;
    uint64 *fromPage = c->mem + fromPageNum*pageLength;
    uint64 *toPage = c->mem + toPageNum*pageLength;
    uint32 pageMask = pageLength - 1;
    uint64 keyData, pageData, lastPageData = 1;
    uint32 i;
    uint64 *k = key;
    uint64 *kEnd = key + c->keyLength;
    uint64 *t = toPage;
    for(i = 0; i < pageLength; i++) {
        keyData = *k;
        *t++ = keyData;
        pageData = fromPage[keyData & pageMask];
        *k++ += (pageData*keyData) ^ lastPageData;
        if(k == kEnd) {
            k = key;
        }
        lastPageData = pageData;
    }
}

// Hash pages randomly into the derived key.
static void *hashMem(void *threadContextPtr) {
    ThreadContext c = (ThreadContext)threadContextPtr;
    uint32 fromPageNum = 0;
    uint32 toPageNum;
    uint32 numPages = c->numPages;
    uint32 hash = 0;
    uint64 *key;
    while(true) {
        while(!c->spinLock);
        c->spinLock = false;
        toPageNum = (*(c->nextPageNumPtr))++;
        c->nextContext->spinLock = true;
        if(toPageNum >= numPages) {
            pthread_exit(NULL);
        }
        key = c->threadKeys + (toPageNum & THREAD_MASK)*c->keyLength;
        hash = (uint32)(key[0]);
        if(toPageNum > MAX_THREADS) {
            fromPageNum = hash % (toPageNum - MAX_THREADS);
        }
        fillPage(c, key, fromPageNum, toPageNum);
    }
}

/* This is the main key derivation function.  Parameters are:
    initialHashingFactor - Parameter for increasing initial key stretching beyond 4096 SHA-256 rounds
    memorySize           - Memory to hash in bytes
    pageSize             - Memory block size assumed to fit in L1 cache - must be a power of 2
    numThreads,          - Number of threads to run in parallel to help fill memory bandwidth
    derivedKey           - Result derived key
    derivedKeySize       - Length of the result key - must be a power of 2
    salt                 - Salt/nonce
    saltSize             - Length of salt in bytes
    password             - The password, which may contain 0's or any other value
    passwordSize         - Length of password in bytes
    clearMemory          - Set memory to 0's before returning
    freeMemory           - Free memory before returning
*/
bool keystretch(uint32 initialHashingFactor, uint64 memorySize, uint32 pageSize, uint32 numThreads,
        uint8 *derivedKey, uint32 derivedKeySize, uint8 *salt, uint32 saltSize,
        uint8 *password, uint32 passwordSize, bool clearMemory, bool freeMemory) {

    // Step 1: Do the 2X or more of the max key stretching OpenSSL Truecrypt allow, and and clear the password
    PBKDF2_SHA256(password, passwordSize, salt, saltSize, (4 + initialHashingFactor) << 10, derivedKey, derivedKeySize);
    memset(password, '\0', passwordSize);

    // Now we're in pure security improvement territory... allocate memory
    uint32 pageLength = pageSize/sizeof(uint64);
    uint32 numPages = (uint32)(memorySize/(pageLength*sizeof(uint64)));
    uint64 memoryLength = ((uint64)pageLength)*numPages;
    uint64 *mem = (uint64 *)malloc(memoryLength * sizeof(uint64));
    uint32 keyLength = (derivedKeySize + 7)/8;
    uint64 *threadKeys = (uint64 *)calloc(MAX_THREADS*keyLength, sizeof(uint64));
    if(mem == NULL || threadKeys == NULL) {
        fprintf(stderr, "Unable to allocate memory\n");
        return false;
    }

    // Initialize thread keys from derivedKey, and erase derivedKey
    PBKDF2_SHA256(derivedKey, derivedKeySize, salt, saltSize, 1, (uint8 *)(void *)threadKeys,
        MAX_THREADS*keyLength*sizeof(uint64));
    memset(derivedKey, '\0', derivedKeySize);

    // Initialize the first page from the salt, without depending on the user's password
    PBKDF2_SHA256((uint8 *)(void *)salt, saltSize, salt, saltSize, 1,
        (uint8 *)(void *)mem, pageLength*sizeof(uint64));

    // Launch the threads, using a spin-lock for synchronization.  The first thread starts
    // with the spin-lock, and then passes it to the next round-robin.
    pthread_t threads[MAX_THREADS];
    struct threadContextStruct contexts[MAX_THREADS];
    ThreadContext c = NULL;
    int rc;
    long t;
    volatile uint32 nextPageNum = 1;
    for(t = 0; t < numThreads; t++) {
        c = contexts + t;
        c->mem = mem;
        c->threadKeys = threadKeys;
        c->keyLength = keyLength;
        c->pageLength = pageLength;
        c->numPages = numPages;
        c->nextPageNumPtr = &nextPageNum;
        c->nextContext = c + 1;
    }
    c->nextContext = contexts;
    contexts[0].spinLock = true;
    for(t = 0; t < numThreads; t++) {
        c = contexts + t;
        rc = pthread_create(&threads[t], NULL, hashMem, (void *)c);
        if (rc){
            fprintf(stderr, "Unable to start threads\n");
            return false;
        }
    }

    // Wait for threads to finish
    for(t = 0; t < numThreads; t++) {
        (void)pthread_join(threads[t], NULL);
    }

    // Hash derived keys together and clear the thread keys
    PBKDF2_SHA256((uint8 *)(void *)threadKeys, MAX_THREADS*keyLength*sizeof(uint64), salt, saltSize, 1,
        derivedKey, derivedKeySize);
    memset(threadKeys, '\0', MAX_THREADS*keyLength*sizeof(uint64));
    memset(contexts, '\0', MAX_THREADS*sizeof(struct threadContextStruct));

    // Clear used memory if requested.  This slows down the code by about 1/3.
    if(clearMemory) {
        memset(mem, '\0', memoryLength*sizeof(uint64)); 
    }
    if(freeMemory) {
        free(mem);
        free(threadKeys);
    }

    return true;
}