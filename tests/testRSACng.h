#ifndef TEST_RSA_H
#define TEST_RSA_H

#include <windows.h>
#include <stdio.h>

#include "../shared/crypto/windows/RSACNG.h"
#include "../shared/print.h"

#define BUFFER_SIZE (0x200)
#define PLAIN_SIZE (0x14)
#define HASH_SIZE (0x20)

void testRSA(int argc , char *argv[])
{
    printf("testRSA\n");
    printf("-----------------------------\n");
    
    KEY_TYPE pub_key_type = KEY_TYPE_NONE;
    char* pub_key_path = NULL;
    char pub_key_path_bck[MAX_PATH];
    KEY_TYPE priv_key_type = KEY_TYPE_NONE;
    char priv_key_path_bck[MAX_PATH];
    char* priv_key_path = NULL;
    RSA_CTXT ctxt;
    int s = 0;
    UCHAR plain[BUFFER_SIZE] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};
    ULONG plain_ln = PLAIN_SIZE;
    UCHAR o_plain[PLAIN_SIZE];
    memcpy(o_plain, plain, plain_ln);
    // in place en/decryption
    int allocated = 0;
    PUCHAR encrypted = (PUCHAR)plain;
    ULONG encrypted_ln = BUFFER_SIZE;
    PUCHAR decrypted = (PUCHAR)plain;
    ULONG decrypted_ln = plain_ln;

    UCHAR hash[HASH_SIZE] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
    ULONG hash_ln = HASH_SIZE;
    UCHAR signature[BUFFER_SIZE];
    PUCHAR signature_ptr = signature;
    ULONG signature_ln = BUFFER_SIZE;
    UCHAR o_hash[HASH_SIZE];
    memcpy(o_hash, hash, hash_ln);

    ULONG i;

    int test_encryption = 0;
    int test_signing = 1;
    int test_export = 0;

    if ( argc > 1 )
    {
        pub_key_path = argv[0];
        SIZE_T strln = strlen(pub_key_path);
        ULONG ftype = (ULONG)*(ULONG*)&pub_key_path[strln-4];
        if ( strln > 5 )
        {
            if ( ftype == 'red.' )
                pub_key_type = KEY_TYPE_DER;
//            else if ( ftype == 'bup.' )
//                pub_key_type = KEY_TYPE_PUB;
//            else if ( ftype == 'mep.' )
//                pub_key_type = KEY_TYPE_PEM;
//            else if ( ftype == 'bolb' )
//                pub_key_type = KEY_TYPE_BLOB;
            else
            {
                printf("Unknown file type\n");
                return ;
            }
        }

        priv_key_path = argv[1];
        strln = strlen(priv_key_path);
        ftype = (ULONG)*(ULONG*)&priv_key_path[strln-4];
        if ( strln > 5 )
        {
            if ( ftype == 'red.' )
                priv_key_type = KEY_TYPE_DER;
//            else if ( ftype == 'bup.' )
//                priv_key_type = KEY_TYPE_PUB;
//            else if ( ftype == 'mep.' )
//                priv_key_type = KEY_TYPE_PEM;
//            else if ( ftype == 'bolb' )
//                priv_key_type = KEY_TYPE_BLOB;
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
    printf("path: %s\n", pub_key_path);
    printf("key_type: %u\n", pub_key_type);

    printf("RSA_getProvider\n");
    s = RSA_init(&ctxt);
    if ( s < 0 )
    {
        printf("RSA_getProvider failed\n");
        goto clean;
    }
    printf("RSA_getProvider success\n");

    printf("RSA_importPubKeyFromFile\n");
    s = RSA_importPubKeyFromFile(&ctxt, pub_key_path, pub_key_type);
    if ( s != 0 )
    {
        printf("RSA_importPubKeyFromFile failed\n");
        goto clean;
    }
    printf("RSA_importPubKeyFromFile success\n");
    printf("--------------------\n");

    printf("RSA_importPrivKeyFromFile\n");
    s = RSA_importPrivKeyFromFile(&ctxt, priv_key_path, priv_key_type);
    if ( s != 0 )
    {
        printf("RSA_importPrivKeyFromFile failed\n");
        goto clean;
    }
    printf("RSA_importPrivKeyFromFile success\n");
    printf("--------------------\n");
    
    if ( test_encryption )
    {
        printf("RSA_encrypt");
        for ( i = 0; i < plain_ln; i++ )
        {
            if ( i%0x10==0 )
                printf("\n");
            printf("%02x ", plain[i]);
        }
        printf("\n");
        s = RSA_encrypt(&ctxt, plain, plain_ln, &encrypted, &encrypted_ln);
        if ( s != 0 )
        {
            printf("RSA_encrypt failed\n");
            goto clean;
        }
        printf("RSA_encrypt success");
        for ( i = 0; i < encrypted_ln; i++ )
        {
            if ( i%0x10==0 )
                printf("\n");
            printf("%02x ", encrypted[i]);
        }
        printf("\n");
        printf("--------------------\n");
    
    
        printf("RSA_decrypt");
        PrintMemCol8(encrypted, encrypted_ln, 0);
        s = RSA_decrypt(&ctxt, encrypted, encrypted_ln, &decrypted, &decrypted_ln);
        if ( s != 0 )
        {
            printf("RSA_decrypt failed\n");
            goto clean;
        }
        printf("RSA_decrypt success");
        PrintMemCol8(decrypted, decrypted_ln, 0);
        if ( memcmp(o_plain, decrypted, plain_ln) == 0 && plain_ln == decrypted_ln )
            printf("decrypted == plain\n");
        else
            printf("decrypted != plain\n");
        printf("--------------------\n");
    }

    if ( test_signing )
    {
        printf("RSA_sign");
        PrintMemCol8(hash, hash_ln, 0);
        s = RSA_signHash(&ctxt, hash, hash_ln, &signature_ptr, &signature_ln);
        //s = RSA_signHash2(&ctxt, hash, hash_ln, &signature_ptr, &signature_ln);
        if ( s != 0 )
        {
            printf("RSA_sign failed\n");
            goto clean;
        }
        printf("RSA_sign success");
        PrintMemCol8(signature_ptr, signature_ln, 0);
        printf("--------------------\n");

        printf("RSA_verify");
        PrintMemCol8(signature_ptr, signature_ln, 0);
        decrypted_ln = BUFFER_SIZE;
        s = RSA_verifyHash(&ctxt, hash, hash_ln, &signature_ptr, &signature_ln);
        //s = RSA_verifyHash2(&ctxt, signature_ptr, signature_ln, &decrypted, &decrypted_ln);
        if ( s != 0 )
        {
            printf("RSA_verify failed\n");
            goto clean;
        }
        printf("RSA_verify success");
        PrintMemCol8(decrypted, decrypted_ln, 0);
        PrintMemCol8(o_hash, hash_ln, 0);
        printf(" hash_ln: 0x%x\n", hash_ln);
        printf(" decrypted_ln: 0x%x\n", decrypted_ln);
        if ( memcmp(o_hash, decrypted, hash_ln) == 0 && hash_ln == decrypted_ln )
            printf("decrypted == hash\n");
        else
            printf("decrypted != hash\n");
        printf("--------------------\n");
    }
    
    if ( test_export )
    {
        printf("RSA_exportPubKeyToDER\n");
        sprintf_s(pub_key_path_bck, MAX_PATH, "%s%s", pub_key_path, ".bck");
        s = RSA_exportPubKeyToDER(&ctxt, pub_key_path_bck);
        if ( s < 0 )
        {
            printf("RSA_exportPubKeyToDER failed\n");
            goto clean;
        }
        printf("RSA_exportPubKeyToDER success\n");
        printf("--------------------\n");
    

        printf("RSA_exportPrivKeyToDER\n");
        sprintf_s(priv_key_path_bck, MAX_PATH, "%s%s", priv_key_path, ".bck");
        s = RSA_exportPrivKeyToDER(&ctxt, priv_key_path_bck);
        if ( s < 0 )
        {
            printf("RSA_exportPrivKeyToDER failed\n");
            goto clean;
        }
        printf("RSA_exportPrivKeyToDER success\n");
        printf("--------------------\n");
    }

clean:
    printf("cleanup\n");
    
    if ( encrypted != NULL && allocated )
        free(encrypted);
    if ( decrypted != NULL && allocated )
        free(decrypted);
    RSA_clean(&ctxt);
    printf("===================================\n\n");
}

#endif
