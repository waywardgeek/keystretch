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
    fprintf(stderr, "\nUsage: phs_keystretch outlen password salt t_cost m_cost\n"
        "    outlen is the output derived key in bytes\n"
        "    t_cost is an integer multiplier CPU work\n"
        "    m_cost is the ammount of memory to use in MB\n");
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

static void readArguments(int argc, char **argv, uint32 *derivedKeySize, char **password, uint32 *passwordSize,
        uint8 **salt, uint32 *saltSize, uint32 *cpuWorkMultiplier, uint64 *memorySize) {
    if(argc != 6) {
        usage("Incorrect number of arguments");
    }
    *derivedKeySize = readUint32(argv, 1);
    *password = argv[2];
    *passwordSize = strlen(*password);
    *salt = readHexSalt(argv[3], saltSize);
    *cpuWorkMultiplier = readUint32(argv, 4);
    *memorySize = readUint32(argv, 5) * (1LL << 20); // Number of MB
}

// Verify the input parameters are reasonalble.
static void verifyParameters(uint32 cpuWorkMultiplier, uint64 memorySize, uint32
        derivedKeySize, uint32 saltSize, uint32 passwordSize) {
    if(cpuWorkMultiplier < 1 || cpuWorkMultiplier > (1 << 20)) {
        usage("Invalid hashing multipler");
    }
    if(memorySize > (1LL << 32)*100 || memorySize < (1 << 20)) {
        usage("Invalid memory size");
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
    while((derivedKeySize & 1) == 0) {
        derivedKeySize >>= 1;
    }
    if(derivedKeySize != 1) {
        usage("Derived key size must be a power of 2");
    }
}

int main(int argc, char **argv) {
    uint64 memorySize;
    uint32 cpuWorkMultiplier, derivedKeySize, saltSize, passwordSize;
    uint8 *salt;
    char *password;
    readArguments(argc, argv, &derivedKeySize, &password, &passwordSize, &salt, &saltSize, &cpuWorkMultiplier, &memorySize);
    verifyParameters(cpuWorkMultiplier, memorySize, derivedKeySize, saltSize, passwordSize);
    uint8 *derivedKey = (uint8 *)calloc(derivedKeySize, sizeof(uint8));
    if(!PHS(derivedKey, derivedKeySize, password, passwordSize, salt, saltSize, cpuWorkMultiplier, memorySize)) {
        fprintf(stderr, "Key stretching failed.\n");
        return 1;
    }
    printHex(derivedKey, derivedKeySize);
    printf("\n");
    memset(derivedKey, '\0', derivedKeySize*sizeof(uint8));
    free(derivedKey);
    return 0;
}
