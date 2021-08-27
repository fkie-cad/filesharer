#ifndef TEST_AES_H
#define TEST_AES_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../shared/debug.h"
#include "../shared/crypto/linux/AESOpenSSL.h"


#define SECRET_SIZE (0x20)


void testAES(int argc , char *argv[])
{
    printf("testAES\n");
    printf("-----------------------------\n");
    AES_CTXT ctxt;
    int s;
    uint8_t secret[SECRET_SIZE];
    uint32_t secret_ln = SECRET_SIZE;
    uint8_t iv[AES_STD_BLOCK_SIZE];
    uint32_t iv_ln = AES_STD_BLOCK_SIZE;
    uint32_t i;
    uint8_t plain[0x80] = {0};
    uint32_t plain_ln = 40;
    for ( i = 0; i < plain_ln; i++ )
        plain[i] = i+1;
    uint8_t o_plain[40];
    memcpy(o_plain, plain, 40);
    // in place en/decryption
    int allocated = 0;
    uint8_t* encrypted = (uint8_t*)plain;
    uint32_t encrypted_ln = 0x80;
    uint8_t* decrypted = (uint8_t*)plain;
    uint32_t decrypted_ln = 0x80;
    // to new buffer
    //int allocated = 1;
    //uint8_t* encrypted = NULL;
    //uint32_t encrypted_ln;
    //uint8_t* decrypted = NULL;
    //uint32_t decrypted_ln;

    (void)argc;
    (void)argv;
    //if ( argc > 1 )
    //{
    //    plain = (uint8_t*)argv[1];
    //    plain_ln = (uint32_t)strlen(argv[1]);
    //}

    printf("AES_init\n");
    s = AES_init(&ctxt);
    if ( s < 0 )
    {
        printf("AES_init failed\n");
        goto clean;
    }
    printf("AES_init success\n");
    printf("-----------------------------------------------\n");
    uint32_t rounds = 2;
    for ( i = 0; i < rounds; i++ )
    {
        printf("Round %2u / %2u ---------------------------------\n", i+1, rounds);

        encrypted_ln = 0x80;
        decrypted_ln = 0x80;

        printf("generate secret\n");
        memset(secret, 0, SECRET_SIZE);
        s = AES_generateRandom(
                secret,
                (int) secret_ln
        );
        if ( s != 0 )
        {
            printf("AES_generateRandom failed\n");
            goto clean;
        }
        printf("secret:");
        printMemory(secret, secret_ln, 0x10, 0);
        printf("-----------------------------------------------\n");

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
        memset(iv, 0, AES_STD_BLOCK_SIZE);
        s = AES_generateRandom(
                iv,
                (int) iv_ln
        );
        if ( s != 0 )
        {
            printf("AES_generateRandom failed\n");
            goto clean;
        }
        printf("iv:");
        printMemory(iv, iv_ln, 0x10, 0);
        printf("-----------------------------------------------\n");

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
        printf("-----------------------------------------------\n");

        printf("encrypt\n");
        printf("plain:");
        printMemory(plain, plain_ln, 0x10, 0);
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
        printMemory(encrypted, encrypted_ln, 0x10, 0);
        printf("-----------------------------------------------\n");

        printf("decrypt\n");
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
        printMemory(decrypted, decrypted_ln, 0x10, 0);
        if ( memcmp(o_plain, decrypted, plain_ln) == 0 && plain_ln == decrypted_ln )
            printf("decrypted == plain\n");
        else
            printf("decrypted != plain\n");
        printf("-----------------------------------------------\n");
        printf("iv:");
        printMemory(iv, iv_ln, 0x10, 0);
        printf("-----------------------------------------------\n");
    }
clean:
    printf("cleanup\n");

    if ( encrypted != NULL && allocated )
        free(encrypted);
    if ( decrypted != NULL && allocated )
        free(decrypted);
    memset(secret, 0, secret_ln);

    AES_clean(&ctxt);
    printf("===============================================\n\n");
}

#endif
