//C4996: 'xxx': This function or variable may be unsafe.
#pragma warning( disable : 4996 )
#include <stdio.h>
#include <stdio.h>
#include <strsafe.h>

#include "HasherCNG.h"
#include "../../files/Files.h"
#include "../../winDefs.h"
#include "../../print.h"


#define BUFFER_SIZE (0x1000)

#define STATUS_BUFFER_TOO_SMALL          ((NTSTATUS)0xC0000023L)


static int createHash(PSha256Ctxt ctxt);



int sha256File(const char* path, unsigned char* hash_bytes, uint16_t hash_bytes_size)
{
    Sha256Ctxt ctxt;
    int s = 0;

    s = initSha256(&ctxt);
    if ( s != 0 )
    {
        goto clean;
    }

    s = sha256FileC(path, hash_bytes, hash_bytes_size, &ctxt);

clean:
    cleanSha256(&ctxt);

    return s;
}

__forceinline
int hashData(
    UCHAR* buffer,
    size_t to_read,
    size_t offset,
    FILE* fp, 
    PSha256Ctxt ctxt
)
{
    size_t bytes_read;
    int errsv;
    int status = 0;

    (offset);
    //fseek(fp, SEEK_SET, offset);

    errno = 0;
    bytes_read = fread(buffer, 1, to_read, fp);
    errsv = errno;
    if ( (bytes_read == 0 || bytes_read != to_read) && errsv != 0 )
    {
        status = errsv;
        goto clean;
    }

    status = BCryptHashData(ctxt->hash, buffer, (ULONG)bytes_read, 0);
    if (!NT_SUCCESS(status))
    {
        goto clean;
    }
clean:
    ;

    return status;
}

int sha256FileC(const char* path, unsigned char* hash_bytes, uint16_t hash_bytes_size, PSha256Ctxt ctxt)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    FILE* fp = NULL;
    size_t file_size = 0;
    UCHAR buffer[BUFFER_SIZE];
    size_t offset = 0;
    int s = 0;
    size_t parts;
    size_t rest;
    size_t i;
    int errsv;

    if ( hash_bytes_size < ctxt->hash_size )
    {
        s = -9;
        goto clean;
    }

    s = createHash(ctxt);
    if ( s != 0 )
    {
        s = -8;
        goto clean;
    }
    
    errno = 0;
    fp = fopen(path, "rb");
    errsv = errno;
    if ( !fp )
    {
        s = errsv;
        goto clean;
    }

    s = getFileSize(path, &file_size);
    if ( s != 0 )
    {
        goto clean;
    }

    parts = file_size / BUFFER_SIZE;
    rest = file_size % BUFFER_SIZE;
    for ( i = 0; i < parts; i++ )
    {
        s = hashData(buffer, BUFFER_SIZE, offset, fp, ctxt);
        if ( !NT_SUCCESS(s) )
        {
            goto clean;
        }

        offset += BUFFER_SIZE;
    }
    if ( rest != 0 )
    {
        s = hashData(buffer, rest, offset, fp, ctxt);
        if ( !NT_SUCCESS(s) )
        {
            goto clean;
        }
    }

    // close the hash
    status = BCryptFinishHash(ctxt->hash, hash_bytes, ctxt->hash_size, 0);
    if (!NT_SUCCESS(status))
    {
        s = status;
        goto clean;
    }

clean:
    if (fp)
    {
        fclose(fp);
    }

    return s;
}

NTSTATUS hashBufferC(
    uint8_t* buffer, 
    size_t buffer_ln, 
    unsigned char* hash_bytes, 
    uint16_t hash_bytes_size, 
    PSha256Ctxt ctxt
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    SIZE_T parts;
    ULONG rest;
    SIZE_T i;
    SIZE_T offset;

    if ( hash_bytes_size < ctxt->hash_size )
    {
        status = STATUS_BUFFER_TOO_SMALL;
        goto clean;
    }

    status = createHash(ctxt);
    if ( !NT_SUCCESS(status) )
    {
        goto clean;
    }

    offset = 0;
    parts = buffer_ln / ULONG_MAX;
    rest = (ULONG)(buffer_ln % ULONG_MAX);

    for ( i = 0; i < parts; i++ )
    {
        status = BCryptHashData(ctxt->hash, &buffer[offset], (ULONG)ULONG_MAX, 0);
        if ( !NT_SUCCESS(status) )
        {
            goto clean;
        }
        offset += ULONG_MAX;
    }
    if ( rest != 0 )
    {
        status = BCryptHashData(ctxt->hash, &buffer[offset], rest, 0);
        if ( !NT_SUCCESS(status) )
        {
            goto clean;
        }
    }

    // close the hash
    status = BCryptFinishHash(ctxt->hash, hash_bytes, ctxt->hash_size, 0);
    if ( !NT_SUCCESS(status) )
    {
        goto clean;
    }

clean:
    ;

    return status;
}

int sha256Buffer(
    uint8_t* buffer, 
    size_t buffer_ln, 
    unsigned char* hash_bytes, 
    uint16_t hash_bytes_size
)
{
    Sha256Ctxt ctxt;
    int s = 0;

    s = initSha256(&ctxt);
    if (s != 0)
    {
        goto clean;
    }

    s = sha256BufferC(buffer, buffer_ln, hash_bytes, hash_bytes_size, &ctxt);

clean:
    cleanSha256(&ctxt);

    return s;
}

int sha256BufferC(
    uint8_t* buffer, 
    size_t buffer_ln, 
    unsigned char* hash_bytes, 
    uint16_t hash_bytes_size, 
    PSha256Ctxt ctxt
)
{
    return hashBufferC(buffer, buffer_ln, hash_bytes, hash_bytes_size, ctxt);
}

void hashToString(const unsigned char* hash, uint16_t hash_size, char* output, uint16_t output_size)
{
    uint16_t i = 0;
    //uint16_t rest = output_size;
    char* digitMap = "0123456789abcdef";

    if ( (hash_size * 2) + 1 > output_size )
    {
        EPrint(STATUS_BUFFER_TOO_SMALL, "output_size too small!\n");
        return;
    }

    for ( i = 0; i < hash_size; i++ )
    {
        output[i] = digitMap[(hash[i]>>4)&0xF];
        output[i+1] = digitMap[(hash[i])&0xF];
        //StringCchPrintfA(output + (i * 2), rest--, "%02x", hash[i]);
    }

    output[output_size-1] = 0;
}

void printHash(const unsigned char* hash, uint16_t hash_size, const char* prefix, const char* postfix)
{
    uint16_t i = 0;

    printf("%s", prefix);
    for (i = 0; i < hash_size; i++)
    {
        printf("%02x", hash[i]);
    }
    printf("%s", postfix);
}

int initSha256(PSha256Ctxt ctxt)
{
    int s = 0;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HANDLE heap = GetProcessHeap();

    memset(ctxt, 0, sizeof(Sha256Ctxt));

    //open an algorithm handle
    status = BCryptOpenAlgorithmProvider(
        &(ctxt->alg),
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        0);
    if (!NT_SUCCESS(status))
    {
        cleanSha256(ctxt);
        return 1;
    }

    //calculate the size of the buffer to hold the hash object
    status = BCryptGetProperty(
        ctxt->alg,
        BCRYPT_OBJECT_LENGTH,
        (PBYTE) & (ctxt->hash_object_size),
        sizeof(DWORD),
        &(ctxt->data_size),
        0);
    if (!NT_SUCCESS(status))
    {
        cleanSha256(ctxt);
        return 2;
    }

    //printf("cbHashObject: 0x%lx\n", cbHashObject);
    //printf("cbData: 0x%lx\n", cbData);

    // allocate the hash object on the heap
    ctxt->hash_object = (PBYTE)HeapAlloc(heap, 0, ctxt->hash_object_size);
    if ( NULL == ctxt->hash_object )
    {
        cleanSha256(ctxt);
        return 3;
    }

    // calculate the length of the hash
    status = BCryptGetProperty(
        ctxt->alg,
        BCRYPT_HASH_LENGTH,
        (PBYTE) & (ctxt->hash_size),
        sizeof(DWORD),
        &(ctxt->data_size),
        0);
    if (!NT_SUCCESS(status))
    {
        cleanSha256(ctxt);
        return 4;
    }

    return s;
}

int createHash(PSha256Ctxt ctxt)
{
    if (ctxt->hash)
    {
        BCryptDestroyHash(ctxt->hash);
        ctxt->hash = NULL;
    }

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    status = BCryptCreateHash(
        ctxt->alg,
        &(ctxt->hash),
        ctxt->hash_object,
        ctxt->hash_object_size,
        NULL,
        0,
        0);
    if (!NT_SUCCESS(status))
    {
        cleanSha256(ctxt);
        return 6;
    }
    return status;
}

int cleanSha256(PSha256Ctxt ctxt)
{
    HANDLE heap = GetProcessHeap();

    if (ctxt->alg)
    {
        BCryptCloseAlgorithmProvider(ctxt->alg, 0);
        ctxt->alg = NULL;
    }

    if (ctxt->hash)
    {
        BCryptDestroyHash(ctxt->hash);
        ctxt->hash = NULL;
    }

    if (ctxt->hash_object)
    {
        HeapFree(heap, 0, ctxt->hash_object);
        ctxt->hash_object = NULL;
    }

    return 0;
}
