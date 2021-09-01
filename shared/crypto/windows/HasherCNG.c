#define  _CRT_SECURE_NO_WARNINGS

#if defined(__linux__) || defined(__linux) || defined(linux)
#include <errno.h>
#endif

#include <stdio.h>

#include "HasherCNG.h"
#include "../../files/Files.h"
#include "../../winDefs.h"


#define BUFFER_SIZE (0x1000)



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
#ifdef ERROR_PRINT
        printf("ERROR (0x%x): Reading bytes failed!\n", errsv);
#endif
        status = 10;
        goto clean;
    }

    status = BCryptHashData(ctxt->hash, buffer, (ULONG)bytes_read, 0);
    if (!NT_SUCCESS(status))
    {
#ifdef ERROR_PRINT
        printf("Error 0x%x returned by BCryptHashData\n", status);
#endif
        status = 8;
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

    if ( hash_bytes_size < ctxt->hash_size )
    {
        s = 9;
        goto clean;
    }

    s = createHash(ctxt);
    if ( s != 0 )
    {
        s = 8;
        goto clean;
    }

    fp = fopen(path, "rb");
    if ( !fp )
    {
#ifdef ERROR_PRINT
        printf("ERROR: Could not open file \"%s\"!\n", path);
#endif
        s = 7;
        goto clean;
    }

    s = getFileSize(path, &file_size);
    if ( s != 0 )
    {
#ifdef ERROR_PRINT
        printf("ERROR (0x%x): getFileSize \"%s\"!\n", s, path);
#endif
        s = 10;
        goto clean;
    }

    parts = file_size / BUFFER_SIZE;
    rest = file_size % BUFFER_SIZE;
    i;
    for ( i = 0; i < parts; i++ )
    {
        s = hashData(buffer, BUFFER_SIZE, offset, fp, ctxt);
        if ( !NT_SUCCESS(s) )
        {
#ifdef ERROR_PRINT
            printf("Error 0x%x returned by BCryptHashData\n", status);
#endif
            s = 8;
            goto clean;
        }

        offset += BUFFER_SIZE;
    }
    if ( rest != 0 )
    {
        s = hashData(buffer, rest, offset, fp, ctxt);
        if ( !NT_SUCCESS(s) )
        {
#ifdef ERROR_PRINT
            printf("Error 0x%x returned by BCryptHashData\n", status);
#endif
            s = 8;
            goto clean;
        }
    }

//    size_t bytes_read;
//    size_t to_read;
//    int errsv;
//    while ( offset < file_size )
//    {
//        to_read = BUFFER_SIZE;
//        if (offset + to_read > file_size)
//            to_read = file_size - offset;
//        errno = 0;
//        bytes_read = fread(buffer, 1, to_read, fp);
//        errsv = errno;
//        if ((bytes_read == 0 || bytes_read != to_read) && errsv != 0)
//        {
//#ifdef ERROR_PRINT
//            printf("ERROR (0x%x): Reading bytes failed!\n", errsv);
//#endif
//            s = 10;
//            goto clean;
//        }
//
//        status = BCryptHashData(ctxt->hash, buffer, (ULONG)bytes_read, 0);
//        if (!NT_SUCCESS(status))
//        {
//#ifdef ERROR_PRINT
//            printf("Error 0x%x returned by BCryptHashData\n", status);
//#endif
//            s = 8;
//            goto clean;
//        }
//
//        if (to_read < BUFFER_SIZE)
//            break;
//
//        offset += to_read;
//    }
    //while ((bytes_read = fread(buffer, 1, buf_size, file)))
    //{
    //    status = BCryptHashData(hHash, buffer, bytes_read, 0);
    //    if (!NT_SUCCESS(status))
    //    {
    //        printf("Error 0x%x returned by BCryptHashData\n", status);
    //        s = 8;
    //        goto clean;
    //    }
    //}

    // close the hash
    status = BCryptFinishHash(ctxt->hash, hash_bytes, ctxt->hash_size, 0);
    if (!NT_SUCCESS(status))
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptFinishHash\n", status);
#endif
        s = 9;
        goto clean;
    }

    //printf("cbHash %d:\n", cbHash);
    //printf("SHA256 of %s:\n", path);
    //for (DWORD i = 0; i < cbHash; i++)
    //{
    //    printf("%02x", hash_bytes[i]);
    //}
    //printf("\n");

clean:
    if (fp)
    {
        fclose(fp);
    }

    return s;
}

int sha256Buffer(
    uint8_t* buffer, 
    uint32_t buffer_ln, 
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
    uint32_t buffer_ln, 
    unsigned char* hash_bytes, 
    uint16_t hash_bytes_size, 
    PSha256Ctxt ctxt
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    int s = 0;

    if ( hash_bytes_size < ctxt->hash_size )
    {
        s = 9;
        goto clean;
    }

    s = createHash(ctxt);
    if ( s != 0 )
    {
        s = 8;
        goto clean;
    }

    status = BCryptHashData(ctxt->hash, buffer, (ULONG)buffer_ln, 0);
    if ( !NT_SUCCESS(status) )
    {
        printf("Error 0x%x returned by BCryptHashData\n", status);
        s = 8;
        goto clean;
    }

    // close the hash
    status = BCryptFinishHash(ctxt->hash, hash_bytes, ctxt->hash_size, 0);
    if ( !NT_SUCCESS(status) )
    {
        printf("Error (0x%x): BCryptFinishHash\n", status);
        s = 9;
        goto clean;
    }

    //printf("cbHash %d:\n", cbHash);
    //printf("SHA256 of %s:\n", path);
    //for (DWORD i = 0; i < cbHash; i++)
    //{
    //    printf("%02x", hash_bytes[i]);
    //}
    //printf("\n");

clean:
    ;

    return s;
}

void hashToString(const unsigned char* hash, uint16_t hash_size, char* output, uint16_t output_size)
{
    uint16_t i = 0;

    for (i = 0; i < hash_size; i++)
    {
        sprintf(output + (i * 2), "%02x", hash[i]);
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
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptOpenAlgorithmProvider\n", status);
#endif
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
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptGetProperty\n", status);
#endif
        cleanSha256(ctxt);
        return 2;
    }

    //printf("cbHashObject: 0x%lx\n", cbHashObject);
    //printf("cbData: 0x%lx\n", cbData);

    // allocate the hash object on the heap
    ctxt->hash_object = (PBYTE)HeapAlloc(heap, 0, ctxt->hash_object_size);
    if ( NULL == ctxt->hash_object )
    {
#ifdef ERROR_PRINT
        printf("ERROR: memory allocation failed\n");
#endif
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
#ifdef ERROR_PRINT
        printf("Error 0x%x returned by BCryptGetProperty\n", status);
#endif
        cleanSha256(ctxt);
        return 4;
    }
    //printf("cbHash: 0x%lx\n", cbHash);
    //printf("cbData: 0x%lx\n", cbData);


    //printf("hHash: 0x%p\n", hHash);
    //printf("pbHashObject: 0x%p\n", pbHashObject);

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
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptCreateHash\n", status);
#endif
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
