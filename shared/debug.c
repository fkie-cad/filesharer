#define _CRT_SECURE_NO_WARNINGS

#include "debug.h"

void printMemory(
    void* mem, 
    uint32_t n, 
    uint16_t bs, 
    int flags
)
{
    uint8_t* b = (uint8_t*)mem;
    uint32_t i, j;
    uint32_t parts;
    uint32_t rest;

    // print 16bit blocks
    if ( flags & PRINT_16 )
    {
        parts = n / 2;
        rest = n % 2;
        j = 0;
        for ( i = 0; i < parts; i++ )
        {
            if ( ( bs > 0 ) && (j % bs == 0 ) )
            {
                printf("\n");
                if ( flags & PRINT_ADDRESS )
                    printf("%p | ", (void*)&b[j]);
            }
            printf("%04x ", (uint16_t)*(uint16_t*)(&b[j]));
            j += 4;
        }
        if ( rest > 0 )
        {
            j = i;
            for ( i = 0; i < rest; i++ )
            {
                if ( ( bs > 0 ) && (j % bs == 0 ) )
                {
                    printf("\n");
                    if ( flags & PRINT_ADDRESS )
                        printf("%p | ", (void*)&b[i]);
                }
                printf("%02x", b[i]);
            }
        }
    }
    // print 32bit blocks
    else if ( flags & PRINT_32 )
    {
        parts = n / 4;
        rest = n % 4;
        j = 0;
        for ( i = 0; i < parts; i++ )
        {
            if ( ( bs > 0 ) && (j % bs == 0 ) )
            {
                printf("\n");
                if ( flags & PRINT_ADDRESS )
                    printf("%p | ", (void*)&b[j]);
            }
            printf("%08x ", (uint32_t)*(uint32_t*)(&b[j]));
            j += 4;
        }
        if ( rest > 0 )
        {
            j = i;
            for ( i = 0; i < rest; i++ )
            {
                if ( ( bs > 0 ) && (j % bs == 0 ) )
                {
                    printf("\n");
                    if ( flags & PRINT_ADDRESS )
                        printf("%p | ", (void*)&b[i]);
                }
                printf("%02x", b[i]);
            }
        }
    }
    // print 64bit blocks
    else if ( flags & PRINT_64 )
    {
        parts = n / 8;
        rest = n % 8;
        j = 0;
        for ( i = 0; i < parts; i++ )
        {
            if ( ( bs > 0 ) && (j % bs == 0 ) )
            {
                printf("\n");
                if ( flags & PRINT_ADDRESS )
                    printf("%p | ", (void*)&b[j]);
            }
            printf("%016"PRIX64" ", (uint64_t)*(uint64_t*)(&b[j]));
            j += 8;
        }
        if ( rest > 0 )
        {
            j = i;
            for ( i = 0; i < rest; i++ )
            {
                if ( ( bs > 0 ) && (j % bs == 0 ) )
                {
                    printf("\n");
                    if ( flags & PRINT_ADDRESS )
                        printf("%p | ", (void*)&b[i]);
                }
                printf("%02x", b[i]);
            }
        }
    }
    // print bytes
    else
    {
        for ( i = 0; i < n; i++ )
        {
            if ( ( bs > 0 ) && (i % bs == 0 ) )
            {
                printf("\n");
                if ( flags & PRINT_ADDRESS )
                    printf("%p | ", (void*)&b[i]);
            }
            printf("%02x ", b[i]);
        }
    }
    printf("\n");
}

void 
PrintHexDump(
    void* buf,
    size_t length, 
    FILE* out
)
{
    size_t i,count,index;
    char rgbDigits[]="0123456789abcdef";
    char rgbLine[100];
    int cbLine;
    uint8_t* buffer = (uint8_t*)buf;

    for ( index = 0; length; length -= count, buffer += count, index += count) 
    {
        count = (length > 16) ? 16:length;

        sprintf(rgbLine, "%4.4zx  ", index);
        cbLine = 6;

        for ( i = 0; i < count; i++ )  
        {
            rgbLine[cbLine++] = rgbDigits[buffer[i] >> 4];
            rgbLine[cbLine++] = rgbDigits[buffer[i] & 0x0f];
            if(i == 7) 
            {
                rgbLine[cbLine++] = ' ';
                rgbLine[cbLine++] = ' ';
            } 
            else 
            {
                rgbLine[cbLine++] = ' ';
            }
        }
        for(; i < 16; i++) 
        {
            rgbLine[cbLine++] = ' ';
            rgbLine[cbLine++] = ' ';
            rgbLine[cbLine++] = ' ';
        }

        rgbLine[cbLine++] = ' ';

        for(i = 0; i < count; i++) 
        {
            if(buffer[i] < 32 || buffer[i] > 126 || buffer[i] == '%') 
            {
                rgbLine[cbLine++] = '.';
            } 
            else 
            {
                rgbLine[cbLine++] = buffer[i];
            }
        }

        rgbLine[cbLine++] = 0;
        fprintf(out, "%s\n", rgbLine);
    }
}
