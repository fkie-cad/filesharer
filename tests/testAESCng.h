#ifndef TEST_AES_H
#define TEST_AES_H

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "../shared/crypto/windows/AESCNG.h"


#define SECRET_SIZE (0x20)


void testAES(int argc , char *argv[])
{
    printf("testAES\n");
    printf("-----------------------------\n");
    AES_CTXT ctxt;
    int s = 0;
    UCHAR secret[SECRET_SIZE];
    ULONG secret_ln = SECRET_SIZE;
    UCHAR iv[AES_STD_BLOCK_SIZE];
    ULONG iv_ln = AES_STD_BLOCK_SIZE;
    ULONG i;
    UCHAR plain[0x80] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40};
    ULONG plain_ln = 40;
    UCHAR o_plain[40];
    memcpy(o_plain, plain, 40);
    // in place en/decryption
    int allocated = 0;
    PUCHAR encrypted = (PUCHAR)plain;
    ULONG encrypted_ln = 0x80;
    PUCHAR decrypted = (PUCHAR)plain;
    ULONG decrypted_ln = 0x80;
    // to new buffer
    //int allocated = 1;
    //PUCHAR encrypted = NULL;
    //ULONG encrypted_ln;
    //PUCHAR decrypted = NULL;
    //ULONG decrypted_ln;

    (void)argc;
    (void)argv;
    //if ( argc > 1 )
    //{
    //    plain = (PUCHAR)argv[1];
    //    plain_ln = (ULONG)strlen(argv[1]);
    //}

    printf("AES_getProvider\n");
    s = AES_init(&ctxt);
    if ( s < 0 )
    {
        printf("AES_getProvider failed\n");
        goto clean;
    }
    printf("AES_getProvider success\n");
    printf("AES BlockSize: 0x%x\n", ctxt.block_size);
    
    printf("generate secret\n");
    RtlZeroMemory(secret, SECRET_SIZE);
    s = BCryptGenRandom(
        NULL,
        secret,
        secret_ln,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    if ( s != 0 )
    {
        printf("BCryptGenRandom failed\n");
        goto clean;
    }
    for ( i = 0; i < secret_ln; i++ )
    {
        printf("%02x ", secret[i]);
    }
    printf("\n");
    
    //printf("AES_getBlockSize\n");
    //s = AES_getBlockSize(&ctxt, &ctxt.block_size);
    //if ( s < 0 )
    //{
    //    printf("AES_getBlockSize failed\n");
    //    goto clean;
    //}
    //printf("AES BlockSize: 0x%x\n", ctxt.block_size);
    if ( AES_STD_BLOCK_SIZE != ctxt.block_size )
    {
        printf("static BLOCK_SIZE != calculated block size\n");
        goto clean;
    }

    printf("generate initial vector\n");
    RtlZeroMemory(iv, AES_STD_BLOCK_SIZE);
    s = BCryptGenRandom(
        NULL,
        iv,
        iv_ln,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    if ( s != 0 )
    {
        printf("BCryptGenRandom failed\n");
        goto clean;
    }
    for ( i = 0; i < iv_ln; i++ )
    {
        printf("%02x ", iv[i]);
    }
    printf("\n");

    printf("generate key\n");
    s = AES_generateKey(
        &ctxt,
        secret,
        secret_ln
    );
    if ( s < 0 )
    {
        printf("AES_generateKey failed\n");
        goto clean;
    }
    printf("AES_generateKey success\n");

    printf("encrypt\n");
    printf("plain:");
    for ( i = 0; i < plain_ln; i++ )
    {
        if ( i%ctxt.block_size==0 )
            printf("\n");
        printf("%02x ", plain[i]);
    }
    printf("\n");
    s = AES_encrypt(
        &ctxt,
        plain,
        plain_ln,
        &encrypted,
        &encrypted_ln,
        iv,
        iv_ln
    );
    if ( s < 0 )
    {
        printf("AES_encrypt failed\n");
        goto clean;
    }
    printf("AES_encrypt success\n");
    printf("encrypted:");
    for ( i = 0; i < encrypted_ln; i++ )
    {
        if ( i%ctxt.block_size==0 )
            printf("\n");
        printf("%02x ", encrypted[i]);
    }
    printf("\n");

    s = AES_decrypt(
        &ctxt,
        encrypted,
        encrypted_ln,
        &decrypted,
        &decrypted_ln,
        iv,
        iv_ln
    );
    if ( s < 0 )
    {
        printf("AES_decrypt failed\n");
        goto clean;
    }
    printf("AES_decrypt success\n");
    printf("decrypted");
    for ( i = 0; i < decrypted_ln; i++ )
    {
        if ( i%ctxt.block_size==0 )
            printf("\n");
        printf("%02x ", decrypted[i]);
    }
    printf("\n");
    if ( memcmp(o_plain, decrypted, plain_ln) == 0 && plain_ln == decrypted_ln )
        printf("decrypted == plain\n");
    else
        printf("decrypted != plain\n");

clean:
    printf("cleanup\n");
    
    if ( encrypted != NULL && allocated )
        free(encrypted);
    if ( decrypted != NULL && allocated )
        free(decrypted);
    RtlZeroMemory(secret, secret_ln);

    AES_clean(&ctxt);
    printf("===================================\n\n");
}

#endif
