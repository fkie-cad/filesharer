#include "AESCNG.h"

#include <winternl.h>
#include <stdio.h>
#include <wincrypt.h> // old
#include <stdlib.h>

#include "../../winDefs.h"
#include "../../winErrPrint.h"


int AES_init(
    PAES_CTXT ctxt
)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG size;
    
    RtlZeroMemory(ctxt, sizeof(AES_CTXT));

    // Open provider.
    status = BCryptOpenAlgorithmProvider(
        &ctxt->alg,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0
    );
    if ( !NT_SUCCESS(status) )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptOpenAlgorithmProvider\n", status);
#endif
        return -1;
    }

    // Calculate the block length
    status = BCryptGetProperty(
        ctxt->alg, 
        BCRYPT_BLOCK_LENGTH, 
        (PUCHAR)&ctxt->block_size, 
        sizeof(ctxt->block_size), 
        &size, 
        0
    );
    if ( !NT_SUCCESS(status) )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): get block length\n", status);
        PrintCSBackupAPIErrorMessage(status);
#endif
        ctxt->block_size = 0;
        return -1;
    }

    // Set chain mode CBC
    status = BCryptSetProperty(
        ctxt->alg, 
        BCRYPT_CHAINING_MODE, 
        (PBYTE)BCRYPT_CHAIN_MODE_CBC, 
        sizeof(BCRYPT_CHAIN_MODE_CBC), 
        0
    );
    if ( !NT_SUCCESS(status) )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): set chain mode\n", status);
        PrintCSBackupAPIErrorMessage(status);
#endif
        return -1;
    }

    return 0;
}

int AES_generateKey(
    PAES_CTXT ctxt,
    PUCHAR secret,
    ULONG secret_ln
)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG data_ln;

    // get needed length of key block
    status = BCryptGetProperty(
        ctxt->alg,
        BCRYPT_OBJECT_LENGTH, 
        (PBYTE)&ctxt->key_obj_ln, 
        sizeof(ULONG), 
        &data_ln, 
        0
    );
    if ( !NT_SUCCESS(status) )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptGetProperty\n", status);
#endif
        goto clean;
    }

    // Allocate the key object on the heap.
    ctxt->key_obj = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, ctxt->key_obj_ln);
    if( ctxt->key_obj == NULL )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): HeapAlloc\n", GetLastError());
        PrintCSBackupAPIErrorMessage(GetLastError());
#endif
        status = STATUS_NO_MEMORY;
        goto clean;
    }

    // generate key 
    status = BCryptGenerateSymmetricKey(
        ctxt->alg,
        &ctxt->key,
        ctxt->key_obj,
        ctxt->key_obj_ln,
        secret,
        secret_ln,
        0
    );
    if ( !NT_SUCCESS(status) )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptGenerateSymmetricKey\n", status);
        PrintCSBackupAPIErrorMessage(status);
#endif
        goto clean;
    }

clean:
    ;
    return (int)status;
}

int AES_encrypt(
    PAES_CTXT ctxt,
    PUCHAR plain,
    ULONG plain_ln,
    PUCHAR* encrypted,
    PULONG encrypted_ln,
    PUCHAR iv,
    ULONG iv_ln
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PUCHAR ivt = NULL;
    ULONG size;
    
    // copy iv, because it will be consumed during encryption
    ivt = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, iv_ln);
    if ( ivt == NULL )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): HeapAlloc ivt\n", GetLastError());
        PrintCSBackupAPIErrorMessage(GetLastError());
#endif
        status = STATUS_NO_MEMORY;
        goto clean;
    }
    memcpy(ivt, iv, iv_ln);
    
    // Get the output buffer size.
    status = BCryptEncrypt(
        ctxt->key, 
        plain, 
        plain_ln,
        NULL,
        ivt,
        ctxt->block_size,
        NULL, 
        0, 
        &size, 
        BCRYPT_BLOCK_PADDING
    );
    if( !NT_SUCCESS(status) )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptEncrypt get size\n", status);
#endif
        goto clean;
    }
    
    if ( *encrypted == NULL )
    {
        *encrypted = (PUCHAR)malloc(size);
        if ( *encrypted == NULL )
        {
#ifdef ERROR_PRINT
            printf("Error (0x%x): malloc out buffer\n", GetLastError());
            PrintCSBackupAPIErrorMessage(GetLastError());
#endif
            status = STATUS_NO_MEMORY;
            goto clean;
        }
    }
    else
    {
        if ( size > *encrypted_ln )
        {
#ifdef ERROR_PRINT
            printf("Error: Provided encryption buffer[0x%x] is too small! 0x%x needed.\n", *encrypted_ln, size);
#endif
            status = STATUS_NO_MEMORY;
            goto clean;
        }
    }
    *encrypted_ln = size;
    
    if ( plain != *encrypted )
        RtlZeroMemory(*encrypted, *encrypted_ln);
    
    // Use the key to encrypt the plaintext buffer.
    // For block sized messages, block padding will add an extra block.
    status = BCryptEncrypt(
        ctxt->key, 
        plain, 
        plain_ln,
        NULL,
        ivt,
        ctxt->block_size, 
        *encrypted, 
        *encrypted_ln, 
        &size, 
        BCRYPT_BLOCK_PADDING
    );
    if ( !NT_SUCCESS(status) )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptEncrypt\n", status);
        PrintCSBackupAPIErrorMessage(status);
#endif
        goto clean;
    }

clean:
    if ( ivt != NULL )
        HeapFree(GetProcessHeap(), 0, ivt);

    return (int)status;
}

int AES_decrypt(
    PAES_CTXT ctxt,
    PUCHAR encrypted,
    ULONG encrypted_ln,
    PUCHAR* plain,
    PULONG plain_ln,
    PUCHAR iv,
    ULONG iv_ln
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PUCHAR ivt = NULL;
    ULONG size;
    
    // copy iv, because it will be consumed during encryption
    ivt = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, iv_ln);
    if ( ivt == NULL )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): HeapAlloc ivt\n", GetLastError());
        PrintCSBackupAPIErrorMessage(GetLastError());
#endif
        status = STATUS_NO_MEMORY;
        goto clean;
    }
    memcpy(ivt, iv, iv_ln);
    
    // Get the output buffer size.
    status = BCryptDecrypt(
        ctxt->key, 
        encrypted, 
        encrypted_ln, 
        NULL,
        ivt,
        ctxt->block_size,
        NULL, 
        0, 
        &size, 
        BCRYPT_BLOCK_PADDING
    );
    if ( !NT_SUCCESS(status) )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptDecrypt get size\n", status);
        PrintCSBackupAPIErrorMessage(status);
#endif
        goto clean;
    }
#ifdef DEBUG_PRINT
    printf("required_size: 0x%x\n", size);
#endif
    
    if ( *plain == NULL )
    {
        *plain = (PUCHAR)malloc(size);
        if ( *plain == NULL )
        {
#ifdef ERROR_PRINT
            printf("Error (0x%x): malloc out buffer\n", GetLastError());
            PrintCSBackupAPIErrorMessage(GetLastError());
#endif
            status = STATUS_NO_MEMORY;
            goto clean;
        }
    }
    else
    {
        if ( size > *plain_ln )
        {
#ifdef ERROR_PRINT
            printf("Error: Provided plain buffer[0x%x] is too small! 0x%x needed.\n", *plain_ln, size);
#endif
            status = STATUS_NO_MEMORY;
            goto clean;
        }
    }
    *plain_ln = size;
    
    if ( encrypted != *plain )
        RtlZeroMemory(*plain, *plain_ln);
    
    status = BCryptDecrypt(
        ctxt->key,
        encrypted, 
        encrypted_ln, 
        NULL,
        ivt,
        ctxt->block_size,
        *plain, 
        *plain_ln, 
        plain_ln, 
        BCRYPT_BLOCK_PADDING
    );
    if ( !NT_SUCCESS(status) )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptDecrypt\n", status);
        PrintCSBackupAPIErrorMessage(status);
#endif
        goto clean;
    }

clean:
    if ( ivt != NULL )
        HeapFree(GetProcessHeap(), 0, ivt);

    return (int)status;
}

int AES_clean(
    PAES_CTXT ctxt
)
{
    if (ctxt->alg)
    {
        BCryptCloseAlgorithmProvider(ctxt->alg, 0);
        ctxt->alg = NULL;
    }

    AES_deleteKey(ctxt);

    ZeroMemory(ctxt, sizeof(*ctxt));

    return 0;
}

int AES_deleteKey(
    PAES_CTXT ctxt
)
{
    if ( ctxt->key )
    {
        BCryptDestroyKey(ctxt->key);
        ctxt->key = NULL;
    }

    if ( ctxt->key_obj )
    {
        ZeroMemory(ctxt->key_obj, ctxt->key_obj_ln);
        HeapFree(GetProcessHeap(), 0, ctxt->key_obj);
        ctxt->key_obj = NULL;
        ctxt->key_obj_ln = 0;
    }

    return 0;
}
