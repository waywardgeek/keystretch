#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include "keystretch.h"

static void usage(char *format, ...) {
    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, (char *)format, ap);
    va_end(ap);
    fprintf(stderr, "\nUsage: keystretch <initial hashing factor> <hashing multiplier> <memory size> <page size> <num threads> +\n"
            "        <derived key size> <salt in hex> <password>\n"
        "    Initial hashing factor is 4096 + N*1024 rounds of SHA-256\n"
        "    Hashing multiplier is an integer >=1 and mutiplies the number of times we hash memory\n"
        "    Memory size in MB\n"
        "    Page size in KB\n"
        "    Hashing factor is integer difficulty multiplier\n"
        "    Derived key size in bytes\n");
    exit(1);
}

static uint32 readUint32(char **argv, uint32 xArg) {
    char *endPtr;
    char *p = argv[xArg];
    uint32 value = strtol(p, &endPtr, 0);
    if(*p == '\0' || *endPtr != '\0') {
        usage("Invalid integer for parameter %u", xArg);
    }
    return value;
}

// Read a 2-character hex byte.
static bool readHexByte(uint8 *dest, char *value) {
    char c = toupper((uint8)*value++);
    uint8 byte;
    if(c >= '0' && c <= '9') {
        byte = c - '0';
    } else if(c >= 'A' && c <= 'F') {
        byte = c - 'A' + 10;
    } else {
        return false;
    }
    byte <<= 4;
    c = toupper((uint8)*value);
    if(c >= '0' && c <= '9') {
        byte |= c - '0';
    } else if(c >= 'A' && c <= 'F') {
        byte |= c - 'A' + 10;
    } else {
        return false;
    }
    *dest = byte;
    return true;
}

static uint8 *readHexSalt(char *p, uint32 *saltLength) {
    uint32 length = strlen(p);
    if(length & 1) {
        usage("hex salt string must have an even number of digits.\n");
    }
    *saltLength = strlen(p) >> 1;
    uint8 *salt = malloc(*saltLength*sizeof(uint8));
    if(salt == NULL) {
        usage("Unable to allocate salt");
    }
    uint8 *dest = salt;
    while(*p != '\0' && readHexByte(dest++, p)) {
        p += 2;
    }
    return salt;
}

static char findHexDigit(
    uint8 value)
{
    if(value <= 9) {
        return '0' + value;
    }
    return 'A' + value - 10;
}

static void printHex(
    uint8 *values,
    uint32 size)
{
    uint8 value;
    while(size-- != 0) {
        value = *values++;
        putchar(findHexDigit((uint8)(0xf & (value >> 4))));
        putchar((uint8)findHexDigit(0xf & value));
    }
}

static void readArguments(int argc, char **argv, uint32 *initialHashingFactor, uint32 *hashingMultiplier,
        uint64 *memorySize, uint32 *pageSize, uint32 *numThreads, uint32 *derivedKeySize,
        uint8 **salt, uint32 *saltSize, char **password, uint32 *passwordSize) {
    if(argc != 9) {
        usage("Incorrect number of arguments");
    }
    *initialHashingFactor = readUint32(argv, 1);
    *hashingMultiplier = readUint32(argv, 2);
    *memorySize = readUint32(argv, 3) * (1LL << 20); // Number of MB
    *pageSize = readUint32(argv, 4) * (1 << 10); // Number of KB
    *numThreads = readUint32(argv, 5);
    *derivedKeySize = readUint32(argv, 6);
    *salt = readHexSalt(argv[7], saltSize);
    *password = argv[8];
    *passwordSize = strlen(*password);
}

// Verify the input parameters are reasonalble.
static void verifyParameters(uint32 initialHashingFactor, uint32 hashingMultiplier, uint64
        memorySize, uint32 pageSize, uint32 numThreads, uint32 derivedKeySize, uint32 saltSize,
        uint32 passwordSize) {
    if(initialHashingFactor > (1 << 20)) {
        usage("Invalid hashing factor");
    }
    if(hashingMultiplier < 1 || hashingMultiplier > (1 << 20)) {
        usage("Invalid hashing multipler");
    }
    if(memorySize > (1LL << 32)*100 || memorySize < (1 << 20)) {
        usage("Invalid memory size");
    }
    if(pageSize > (1 << 28) || pageSize < (1 << 8)) {
        usage("Invalid page size");
    }
    if(numThreads == 0 || numThreads > MAX_THREADS) {
        usage("Invalid number of threads");
    }
    if(derivedKeySize < 8 || derivedKeySize > (1 << 20)) {
        usage("Invalid derived key size");
    }
    if(saltSize > (1 << 9) || saltSize < 4) {
        usage("Invalid salt size");
    }
    if(passwordSize == 0) {
        usage("Invalid password size");
    }
    while((pageSize & 1) == 0) {
        pageSize >>= 1;
    }
    if(pageSize != 1) {
        usage("Page size must be a power of 2");
    }
    while((derivedKeySize & 1) == 0) {
        derivedKeySize >>= 1;
    }
    if(derivedKeySize != 1) {
        usage("Derived key size must be a power of 2");
    }
}

int main(int argc, char **argv) {
    uint64 memorySize;
    uint32 initialHashingFactor, hashingMultiplier, pageSize, numThreads, derivedKeySize, saltSize, passwordSize;
    uint8 *salt;
    char *password;
    readArguments(argc, argv, &initialHashingFactor, &hashingMultiplier, &memorySize, &pageSize, &numThreads,
        &derivedKeySize, &salt, &saltSize, &password, &passwordSize);
    verifyParameters(initialHashingFactor, hashingMultiplier, memorySize, pageSize, numThreads, derivedKeySize,
        saltSize, passwordSize);
    uint8 *derivedKey = (uint8 *)calloc(derivedKeySize, sizeof(uint8));
    if(!keystretch(initialHashingFactor, hashingMultiplier, memorySize, pageSize, numThreads, derivedKey, derivedKeySize,
            salt, saltSize, (uint8 *)password, passwordSize, true, false, false)) {
        fprintf(stderr, "Key stretching failed.\n");
        return 1;
    }
    printHex(derivedKey, derivedKeySize);
    memset(derivedKey, '\0', derivedKeySize*sizeof(uint8));
    free(derivedKey);
    return 0;
}
