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
    uint64 key[8];
    uint64 lastPageData;
    uint64 *mem;
    uint32 pageLength;
    uint32 numPages;
    uint32 cpuWorkMultiplier;
};

// Fill toPage, hashing with the key and fromPage as we go.
static void fillPage(ThreadContext c, uint32 fromPageNum, uint32 toPageNum) {
    uint32 pageLength = c->pageLength;
    uint64 *fromPage = c->mem + fromPageNum*pageLength;
    uint64 key0 = c->key[0];
    uint64 key1 = c->key[1];
    uint64 key2 = c->key[2];
    uint64 key3 = c->key[3];
    uint64 key4 = c->key[4];
    uint64 key5 = c->key[5];
    uint64 key6 = c->key[6];
    uint64 key7 = c->key[7];
    uint64 lastPageData =  c->lastPageData;
    uint64 pageData0, pageData1, pageData2, pageData3;
    uint64 pageData4, pageData5, pageData6, pageData7 = 0;
    uint32 pageMask = pageLength - 1;
    uint32 workMultiplier = c->cpuWorkMultiplier;
    while(workMultiplier--) {
        uint32 numLoops = pageLength >> 3;
        uint64 *toPage = c->mem + toPageNum*pageLength;
        while(numLoops--) {
            pageData0 = fromPage[key0 & pageMask];
            pageData1 = fromPage[key1 & pageMask];
            pageData2 = fromPage[key2 & pageMask];
            pageData3 = fromPage[key3 & pageMask];
            pageData4 = fromPage[key4 & pageMask];
            pageData5 = fromPage[key5 & pageMask];
            pageData6 = fromPage[key6 & pageMask];
            pageData7 = fromPage[key7 & pageMask];

            key0 += (pageData0*key1) ^ lastPageData;
            key1 += (pageData1*key2) ^ pageData0;
            key2 += (pageData2*key3) ^ pageData1;
            key3 += (pageData3*key4) ^ pageData2;
            key4 += (pageData4*key5) ^ pageData3;
            key5 += (pageData5*key6) ^ pageData4;
            key6 += (pageData6*key7) ^ pageData5;
            key7 += (pageData7*key0) ^ pageData6;
            lastPageData = pageData7;

            *toPage++ = key0;
            *toPage++ = key1;
            *toPage++ = key2;
            *toPage++ = key3;
            *toPage++ = key4;
            *toPage++ = key5;
            *toPage++ = key6;
            *toPage++ = key7;

            /*
            printf("%llu\n", key0);
            printf("%llu\n", key1);
            printf("%llu\n", key2);
            printf("%llu\n", key3);
            printf("%llu\n", key4);
            printf("%llu\n", key5);
            printf("%llu\n", key6);
            printf("%llu\n", key7);
            */
        }
    }
    c->key[0] = key0;
    c->key[1] = key1;
    c->key[2] = key2;
    c->key[3] = key3;
    c->key[4] = key4;
    c->key[5] = key5;
    c->key[6] = key6;
    c->key[7] = key7;
    c->lastPageData = lastPageData;
}

// Hash pages randomly into the derived key.
static void *hashMem(void *threadContextPtr) {
    ThreadContext c = (ThreadContext)threadContextPtr;
    uint32 fromPageNum = 0;
    uint32 toPageNum;
    uint32 numPages = c->numPages;
    uint32 hash;
    for(toPageNum = 1; toPageNum < numPages; toPageNum++) {
        hash = c->key[0];
        fromPageNum = hash % toPageNum;
        fillPage(c, fromPageNum, toPageNum);
    }
    pthread_exit(NULL);
}

/* This is the main key derivation function.  Parameters are:
    initialHashingFactor - Parameter for increasing initial key stretching beyond 4096 SHA-256 rounds
    hashingMultipler     - How many times to repeat hashing the entire memory.  Most often, this should be 1
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
bool keystretch(uint32 sha256HashRounds, uint32 cpuWorkMultiplier, uint64 memorySize,
        uint32 pageSize, uint32 numThreads, void *derivedKey, uint32 derivedKeySize, const void *salt,
        uint32 saltSize, void *password, uint32 passwordSize, bool clearPassword, bool clearMemory, bool freeMemory) {

    printf("sha256HashRounds:%u cpuWorkMultiplier:%u memorySize:%llu pageSize:%u numThreads:%u\n",
        sha256HashRounds, cpuWorkMultiplier, memorySize, pageSize, numThreads);
    // Step 1: Do the 2X or more of the max key stretching OpenSSL Truecrypt allow, and and clear the password
    PBKDF2_SHA256(password, passwordSize, salt, saltSize, sha256HashRounds, derivedKey, derivedKeySize);
    if(clearPassword) {
        memset(password, '\0', passwordSize); // It's a good idea to clear the password ASAP
    }

    // Now we're in pure security improvement territory... allocate memory
    uint32 pageLength = pageSize/sizeof(uint64);
    uint32 numPages = (uint32)(memorySize/(pageLength*sizeof(uint64)));
    uint64 memoryLength = ((uint64)pageLength)*numPages;
    uint64 *mem = (uint64 *)malloc(memoryLength * sizeof(uint64));
    if(mem == NULL) {
        fprintf(stderr, "Unable to allocate memory\n");
        return false;
    }

    // Initialize thread keys from derivedKey, and erase derivedKey
    PBKDF2_SHA256(derivedKey, derivedKeySize, salt, saltSize, 1, (uint8 *)(void *)mem, pageLength*sizeof(uint64));
    memset(derivedKey, '\0', derivedKeySize);

    pthread_t threads[MAX_THREADS];
    struct threadContextStruct contexts[MAX_THREADS];
    ThreadContext c = NULL;
    // Launch the threads, using a spin-lock for synchronization.  The first thread starts
    // with the spin-lock, and then passes it to the next round-robin.
    int rc;
    long t;
    for(t = 0; t < numThreads; t++) {
        c = contexts + t;
        c->mem = mem;
        c->pageLength = pageLength;
        c->numPages = numPages;
        c->cpuWorkMultiplier = cpuWorkMultiplier;
        PBKDF2_SHA256((uint8 *)(void *)(mem + t*8*sizeof(uint64)), 8*sizeof(uint64), salt, saltSize, 1,
            (uint8 *)(void *)(c->key + t), 8*sizeof(uint64));
    }
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

    // Hash the last page to form the key.
    PBKDF2_SHA256((uint8 *)(void *)(mem + (numPages-1)*pageLength), pageLength*sizeof(uint64), salt, saltSize, 1,
        derivedKey, derivedKeySize);
    memset(contexts, '\0', MAX_THREADS*sizeof(struct threadContextStruct));

    // Clear used memory if requested.  This slows down the code by about 1/3.
    if(clearMemory) {
        memset(mem, '\0', memoryLength*sizeof(uint64)); 
    }
    if(freeMemory) {
        free(mem);
    }

    return true;
}

// Wrapper for the password hashing competition. Note that the password, "in" cannot be
// cleared!  This leaves the unencrypted password lying around memory for the entire
// hashing session.
int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen,
        unsigned int t_cost, unsigned int m_cost) {
    return keystretch(4096, t_cost, m_cost, 16*(1 << 10), 2, out, outlen, salt, saltlen, (void *)in, inlen,
        false, false, false);
}
