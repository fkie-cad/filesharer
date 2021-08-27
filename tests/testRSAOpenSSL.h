#ifndef TEST_RSA_H
#define TEST_RSA_H

#include <stdio.h>

#include "../shared/crypto/linux/RSAOpenSSL.h"

#define BUFFER_SIZE (0x400)
#define PLAIN_SIZE (0x14)
#define HASH_SIZE (0x20)

void testRSA(int argc , char *argv[])
{
    printf("testRSA\n");
    printf("-----------------------------\n");
    
    KEY_TYPE pub_key_type = KEY_TYPE_NONE;
    char* pub_key_path = NULL;
//    char pub_key_path_bck[PATH_MAX];
    KEY_TYPE priv_key_type = KEY_TYPE_NONE;
//    char priv_key_path_bck[PATH_MAX];
    char* priv_key_path = NULL;
    RSA_CTXT ctxt;
    int s = 0;
    size_t i = 0;
    uint8_t plain[BUFFER_SIZE] = {0};
    uint32_t plain_ln = BUFFER_SIZE;
    uint8_t o_plain[BUFFER_SIZE];
    uint32_t plain_buf_ln = BUFFER_SIZE;
    for ( i = 0; i < PLAIN_SIZE; i++ )
        plain[i] = i+1;
    memcpy(o_plain, plain, plain_ln);
    // in place en/decryption
    int allocated = 0;
    uint8_t* encrypted = (uint8_t*)plain;
    uint32_t encrypted_ln = BUFFER_SIZE;
    uint8_t* decrypted = (uint8_t*)plain;
    uint32_t decrypted_ln = plain_buf_ln;

    uint8_t hash[HASH_SIZE];
    for ( i = 0; i < HASH_SIZE; i++ )
        hash[i] = i+1;
    uint32_t hash_ln = HASH_SIZE;
    uint8_t signature[BUFFER_SIZE];
    uint8_t* signature_ptr = signature;
    uint32_t signature_ln = BUFFER_SIZE;
    uint8_t o_hash[HASH_SIZE];
    memcpy(o_hash, hash, hash_ln);

    uint32_t pem = 0x6d65702e;

    int test_encryption = 0;
    int test_signing = 1;
    int test_export = 0;

    if ( argc > 1 )
    {
        pub_key_path = argv[0];
        size_t strln = strlen(pub_key_path);
        uint32_t ftype = (uint32_t)*(uint32_t*)&pub_key_path[strln-4];
        if ( strln > 5 )
        {
            if ( ftype == pem )
                pub_key_type = KEY_TYPE_PEM;
            else
            {
                printf("Unknown file type\n");
                return ;
            }
        }

        priv_key_path = argv[1];
        strln = strlen(priv_key_path);
        ftype = (uint32_t)*(uint32_t*)&priv_key_path[strln-4];
        if ( strln > 5 )
        {
            if ( ftype == pem )
                priv_key_type = KEY_TYPE_PEM;
            else
            {
                printf("Unknown file type\n");
                return ;
            }
        }
    }
    else
    {
        printf("No keys provided. Pass pub.key priv.key in params.\n");
        return ;
    }
    printf("pub key path: %s\n", pub_key_path);
    printf("priv key path: %s\n", priv_key_path);
    printf("pub key_type: %u\n", pub_key_type);
    printf("priv key_type: %u\n", priv_key_type);

    printf("RSA_init\n");
    s = RSA_init(&ctxt);
    if ( s < 0 )
    {
        printf("RSA_init failed\n");
        goto clean;
    }
    printf("   success\n");
    printf("-----------------------------------------------\n");

    printf("RSA_importPubKeyFromFile\n");
    s = RSA_importPubKeyFromFile(&ctxt, pub_key_path);
    if ( s != 0 )
    {
        printf("RSA_importPubKeyFromFile failed\n");
        goto clean;
    }
    printf("RSA_importPubKeyFromFile success\n");
    printf("-----------------------------------------------\n");

    printf("RSA_importPrivKeyFromFile\n");
    s = RSA_importPrivKeyFromFile(&ctxt, priv_key_path);
    if ( s != 0 )
    {
        printf("   failed\n");
        goto clean;
    }
    printf("RSA_importPrivKeyFromFile success\n");
    printf("-----------------------------------------------\n");

    if ( test_encryption )
    {
        printf("RSA_encrypt\n");
        printf("plain:");
        printMemory(plain, plain_ln, 0x10, 0);
        s = RSA_encrypt(&ctxt, plain, plain_ln, &encrypted, &encrypted_ln);
        if ( s != 0 )
        {
            printf("RSA_encrypt failed\n");
            goto clean;
        }
        printf("encrypted:");
        printMemory(encrypted, encrypted_ln, 0x10, 0);
        printf("RSA_encrypt success\n");
        printf("-----------------------------------------------\n");


        printf("RSA_decrypt");
        printf("encrypted:");
        printMemory(encrypted, encrypted_ln, 0x10, 0);
        s = RSA_decrypt(&ctxt, encrypted, encrypted_ln, &decrypted, &decrypted_ln);
        if ( s != 0 )
        {
            printf("RSA_decrypt failed\n");
            goto clean;
        }
        printf("decrypted:");
        printMemory(decrypted, decrypted_ln, 0x10, 0);
        if ( memcmp(o_plain, decrypted, plain_ln) == 0 && plain_ln == decrypted_ln )
            printf("decrypted == plain\n");
        else
            printf("decrypted != plain\n");
        printf("RSA_decrypt success\n");
        printf("-----------------------------------------------\n");
    }

    if ( test_signing )
    {
        printf("RSA_sign");
        printMemory(hash, hash_ln, 0x10, 0);
        s = RSA_signHash(&ctxt, hash, hash_ln, &signature_ptr, &signature_ln);
//        s = RSA_signHash2(&ctxt, hash, hash_ln, &signature_ptr, &signature_ln);
        if ( s != 0 )
        {
            printf("RSA_sign failed\n");
            goto clean;
        }
        printf("RSA_sign success");
        printMemory(signature_ptr, signature_ln, 0x10, 0);
        printf("--------------------\n");

        printf("RSA_verify");
        printMemory(signature_ptr, signature_ln, 0x10, 0);
        s = RSA_verifyHash(&ctxt, hash, hash_ln, signature_ptr, signature_ln);
//        s = RSA_verifyHash2(&ctxt, hash, hash_ln, signature_ptr, signature_ln);
        if ( s != 0 )
        {
            printf("RSA_verify failed\n");
            goto clean;
        }
        printf("RSA_verify success");
        printf("--------------------\n");
    }

    if ( test_export)
    {
        //    printf("RSA_exportPubKeyToDER\n");
        //    sprintf_s(pub_key_path_bck, MAX_PATH, "%s%s", pub_key_path, ".bck");
        //    s = RSA_exportPubKeyToDER(&ctxt, pub_key_path_bck);
        //    if ( s < 0 )
        //    {
        //        printf("RSA_exportPubKeyToDER failed\n");
        //        goto clean;
        //    }
        //    printf("RSA_exportPubKeyToDER success\n");
        //    printf("-----------------------------------------------\n");
        //
        //
        //    printf("RSA_exportPrivKeyToDER\n");
        //    sprintf_s(priv_key_path_bck, MAX_PATH, "%s%s", priv_key_path, ".bck");
        //    s = RSA_exportPrivKeyToDER(&ctxt, priv_key_path_bck);
        //    if ( s < 0 )
        //    {
        //        printf("RSA_exportPrivKeyToDER failed\n");
        //        goto clean;
        //    }
        //    printf("RSA_exportPrivKeyToDER success\n");
        //    printf("-----------------------------------------------\n");
        //
    }
clean:
    printf("cleanup\n");

    if ( encrypted != NULL && allocated )
        free(encrypted);
    if ( decrypted != NULL && allocated )
        free(decrypted);
    RSA_clean(&ctxt);
    printf("===============================================\n\n");
}

#endif
