#include <stdbool.h>

typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned long long uint64;
typedef unsigned int uint32;

#define MAX_THREADS 16 // Must be power of 2
#define THREAD_MASK (MAX_THREADS - 1)

bool keystretch(uint32 initialHashingFactor, uint32 cpuWorkMultiplier, uint64 memorySize, uint32
        pageSize, uint32 numThreads, void *derivedKey, uint32 derivedKeySize, const void *salt, uint32 saltSize,
        void *password, uint32 passwordSize, bool clearPassword, bool clearMemory, bool freeMemory);

// This is the prototype required for the password hashing competition.  It just sets
// initialHashingFactor to 0,  pageSize to 16KB, numThreads to 2, and clearMemory and
// freeMemory to false.
int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen,
    unsigned int t_cost, unsigned int m_cost);
