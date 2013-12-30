#include <stdbool.h>

typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned long long uint64;
typedef unsigned int uint32;

#define MAX_THREADS 16 // Must be power of 2
#define THREAD_MASK (MAX_THREADS - 1)

bool keystretch(uint32 initialHashingFactor, uint64 memorySize, uint32 pageSize, uint32 numThreads,
        uint8 *derivedKey, uint32 derivedKeySize, uint8 *salt, uint32 saltSize,
        uint8 *password, uint32 passwordSize, bool clearMemory, bool freeMemory);
