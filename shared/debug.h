#ifndef SHARED_DEBUG_H
#define SHARED_DEBUG_H

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

#ifndef DEBUG_PRINT_INFO
#define DEBUG_PRINT_INFO (0)
#endif
#define debug_info(...) if (DEBUG_PRINT_INFO) fprintf(stdout, __VA_ARGS__)
#define debug_winfo(...) if (DEBUG_PRINT_INFO) fwprintf(stdout, __VA_ARGS__)


#define PRINT_ADDRESS 0x1
#define PRINT_16 0x2 // exclusive option
#define PRINT_32 0x4 // exclusive option
#define PRINT_64 0x6 // exclusive option

void printMemory(
    void* mem,
    uint32_t n,
    uint16_t bs,
    int flags
);

void PrintHexDump(
    void* buf,
    size_t length, 
    FILE* out
);

#endif
