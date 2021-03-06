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
#include "sha256.h"
#include "keystretch.h"

typedef struct ContextStruct *Context;

struct ContextStruct {
    uint64 key[8];
    uint64 lastPageData;
    uint64 *mem;
    uint32 pageLength;
    uint32 numPages;
    uint32 cpuWorkMultiplier;
};

// Fill toPage, hashing with the key and fromPage as we go.
static void fillPage(Context c, uint32 fromPageNum, uint32 toPageNum) {
    uint64 *fromPage = c->mem + fromPageNum*c->pageLength;
    uint32 workMultiplier = c->cpuWorkMultiplier;
    while(workMultiplier--) {
        uint64 *toPage = c->mem + toPageNum*c->pageLength;
        uint32 i;
        for(i = 0; i < c->pageLength; i++) {
            uint64 pageData = fromPage[i];
            c->key[i & 7] += (pageData*c->key[(i+1) & 7]) ^ c->lastPageData;
            *toPage++ = c->key[i & 7];
            //printf("%llu\n", c->key[i & 7]);
            c->lastPageData = pageData;
        }
    }
}

// Hash pages randomly into the derived key.
static void hashMem(Context c) {
    uint32 fromPageNum = 0;
    uint32 toPageNum;
    uint32 numPages = c->numPages;
    uint32 hash;
    for(toPageNum = 1; toPageNum < numPages; toPageNum++) {
        hash = c->key[0];
        fromPageNum = hash % toPageNum;
        fillPage(c, fromPageNum, toPageNum);
    }
}

/* This is the main key derivation function.  Parameters are:
    sha256HashRounds     - Parameter for increasing initial key stretching beyond 4096 SHA-256 rounds
    cpuWorkMultiplier    - How many times to repeat hashing the entire memory.  Most often, this should be 1
    memorySize           - Memory to hash in bytes
    pageSize             - Memory block size assumed to fit in L1 cache - must be a power of 2
    numThreads,          - Number of threads - ignored in ref version
    derivedKey           - Result derived key
    derivedKeySize       - Length of the result key - must be a power of 2
    salt                 - Salt/nonce
    saltSize             - Length of salt in bytes
    password             - The password, which may contain 0's or any other value
    passwordSize         - Length of password in bytes
    clearPassword        - If true, set password to 0's after initial hashing
    clearMemory          - Set memory to 0's before returning
    freeMemory           - Free memory before returning
*/
bool keystretch(uint32 sha256HashRounds, uint32 cpuWorkMultiplier, uint64 memorySize,
        uint32 pageSize, uint32 numThreads, void *derivedKey, uint32 derivedKeySize, const void *salt,
        uint32 saltSize, void *password, uint32 passwordSize, bool clearPassword, bool clearMemory, bool freeMemory) {

    printf("sha256HashRounds:%u cpuWorkMultiplier:%u memorySize:%llu pageSize:%u numThreads:%u\n",
        sha256HashRounds, cpuWorkMultiplier, memorySize, pageSize, numThreads);

    // Do standard key stretching and and clear the password
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

    // Initialize initial page from derivedKey
    PBKDF2_SHA256(derivedKey, derivedKeySize, salt, saltSize, 1, (uint8 *)(void *)mem, pageLength*sizeof(uint64));

    struct ContextStruct c;
    c.mem = mem;
    c.pageLength = pageLength;
    c.numPages = numPages;
    c.cpuWorkMultiplier = cpuWorkMultiplier;
    c.lastPageData = mem[0];
    PBKDF2_SHA256((uint8 *)(void *)mem, 8*sizeof(uint64), salt, saltSize, 1, (uint8 *)(void *)(c.key), 8*sizeof(uint64));

    // Hash memory
    hashMem(&c);

    // Hash the last page to form the key.
    PBKDF2_SHA256((uint8 *)(void *)(mem + (numPages-1)*pageLength), pageLength*sizeof(uint64), salt, saltSize, 1,
        derivedKey, derivedKeySize);
    memset((void *)&c, '\0', sizeof(struct ContextStruct));

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
    return keystretch(2048, t_cost, m_cost, 16*(1 << 10), 1, out, outlen, salt, saltlen, (void *)in, inlen,
        false, false, false);
}
