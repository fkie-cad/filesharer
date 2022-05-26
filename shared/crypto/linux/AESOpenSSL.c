#include "AESOpenSSL.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <openssl/err.h>
#include <openssl/rand.h>


//#define ERROR_PRINT
//#define DEBUG_PRINT

typedef const EVP_CIPHER * (*BLOCK_CIPHER)();
static BLOCK_CIPHER block_cipher = NULL;


int AES_init(
    PAES_CTXT ctxt
)
{
    memset(ctxt, 0, sizeof(*ctxt));
    ctxt->ctx = EVP_CIPHER_CTX_new();
    if ( !ctxt->ctx )
    {
#ifdef ERROR_PRINT
        printf("ERROR (0x%lx): Creating cipher context failed.\n", ERR_get_error());
#endif
        return -1;
    }

    block_cipher = &EVP_aes_256_cbc;
    ctxt->block_size = EVP_CIPHER_block_size((*block_cipher)());

    return 0;
}

int AES_generateRandom(
    uint8_t* random,
    int random_ln
)
{
    int status = 0;
//    status = RAND_bytes(random, random_ln);
    status = RAND_priv_bytes(random, random_ln);
//    status = RAND_priv_bytes_ex(OSSL_LIB_CTX *ctx, random, random_ln, unsigned int strength);
    if ( status != 1 )
    {
#ifdef ERROR_PRINT
        printf("ERROR (0x%lx): Generating random failed.\n", ERR_get_error());
#endif
        status = -1;
    }

    if ( status == 1 )
        status = 0;
    return (int)status;
}

int AES_generateKey(
    PAES_CTXT ctxt,
    uint8_t* secret,
    uint32_t secret_ln
)
{
    int status = 0;

    ctxt->key = (uint8_t*)OPENSSL_malloc(secret_ln);
    if ( !ctxt->key )
        return -1;
    memcpy(ctxt->key, secret, secret_ln);
    ctxt->key_ln = secret_ln;

    return (int)status;
}

int AES_encrypt(
    PAES_CTXT ctxt,
    uint8_t* plain,
    uint32_t plain_ln,
    uint8_t** encrypted,
    uint32_t* encrypted_ln,
    uint8_t* iv,
    uint32_t iv_ln
)
{
    int status = 0;
    int len = 0;
    uint32_t req_size = GET_ENC_AES_SIZE(plain_ln);

    if ( ctxt->key_ln != EVP_CIPHER_key_length((*block_cipher)()) )
    {
#ifdef ERROR_PRINT
        printf("ERROR: AES key is too small!\n");
#endif
        status = -1;
        goto clean;
    }

    if ( iv_ln != EVP_CIPHER_iv_length((*block_cipher)()) )
    {
#ifdef ERROR_PRINT
        printf("ERROR: IV is too small!\n");
#endif
        status = -1;
        goto clean;
    }

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    status = EVP_EncryptInit_ex(ctxt->ctx, (*block_cipher)(), NULL, ctxt->key, iv);
    if ( status != 1 )
    {
#ifdef ERROR_PRINT
        printf("ERROR (0x%lx): EVP_EncryptInit_ex failed.\n", ERR_get_error());
#endif
        status = -2;
        goto clean;
    }

    if ( *encrypted == NULL )
    {
        *encrypted = (uint8_t*)malloc(req_size);
        if ( *encrypted == NULL )
        {
#ifdef ERROR_PRINT
            printf("Error (0x%x): malloc out buffer\n", errno);
#endif
            status = -3;
            goto clean;
        }
    }
    else
    {
        if ( req_size > *encrypted_ln )
        {
#ifdef ERROR_PRINT
            printf("Error: Provided encryption buffer[0x%x] is too small! 0x%x needed.\n", *encrypted_ln, req_size);
#endif
            status = -3;
            goto clean;
        }
    }

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    status = EVP_EncryptUpdate(ctxt->ctx, *encrypted, &len, plain, (int)plain_ln);
    if ( status != 1 )
    {
#ifdef ERROR_PRINT
        printf("ERROR (0x%lx): EVP_EncryptUpdate failed.\n", ERR_get_error());
#endif
        status = -4;
        goto clean;
    }
    *encrypted_ln = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    status = EVP_EncryptFinal_ex(ctxt->ctx, *encrypted + len, &len);
    if ( status != 1 )
    {
#ifdef ERROR_PRINT
        printf("ERROR (0x%lx): EVP_EncryptFinal_ex failed.\n", ERR_get_error());
#endif
        status = -5;
        goto clean;
    }
    *encrypted_ln += len;

clean:
    if ( status == 1 )
        status = 0;

    return (int)status;
}

int AES_decrypt(
    PAES_CTXT ctxt,
    uint8_t* encrypted,
    uint32_t encrypted_ln,
    uint8_t** plain,
    uint32_t* plain_ln,
    uint8_t* iv,
    uint32_t iv_ln
)
{
    int status = 0;
    int len;
    *plain_ln = 0;

    if ( ctxt->key_ln != EVP_CIPHER_key_length((*block_cipher)()) )
    {
#ifdef ERROR_PRINT
        printf("ERROR: AES key is too small!\n");
#endif
        status = -1;
        goto clean;
    }

    if ( iv_ln != EVP_CIPHER_iv_length((*block_cipher)()) )
    {
#ifdef ERROR_PRINT
        printf("ERROR: IV is too small!\n");
#endif
        status = -1;
        goto clean;
    }

    status = EVP_DecryptInit_ex(ctxt->ctx, (*block_cipher)(), NULL, ctxt->key, iv);
    if( status != 1 )
    {
#ifdef ERROR_PRINT
        printf("ERROR (0x%lx): EVP_EncryptFinal_ex failed.\n", ERR_get_error());
#endif
        status = -2;
        goto clean;
    }

    if ( *plain == NULL )
    {
        *plain = (uint8_t*)malloc(encrypted_ln);
        if ( *plain == NULL )
        {
#ifdef ERROR_PRINT
            printf("ERROR (0x%x): malloc out buffer\n", errno);
#endif
            status = -1;
            goto clean;
        }
    }
    else
    {
//        if ( req_size > *encrypted_ln )
//        {
//#ifdef ERROR_PRINT
//            printf("ERROR: Provided encryption buffer[0x%x] is too small! 0x%x needed.\n", *encrypted_ln, size);
//#endif
//            status = -1;
//            goto clean;
//        }
    }

    status = EVP_DecryptUpdate(ctxt->ctx, *plain, &len, encrypted, (int)encrypted_ln);
    if ( status != 1 )
    {
#ifdef ERROR_PRINT
        printf("ERROR (0x%lx): EVP_DecryptUpdate failed.\n", ERR_get_error());
#endif
        status = -3;
        goto clean;
    }
    *plain_ln = len;

    // Finalise the decryption.
    // Further plaintext bytes may be written at this stage.
    status = EVP_DecryptFinal_ex(ctxt->ctx, *plain + len, &len);
    if ( status != 1 )
    {
#ifdef ERROR_PRINT
        printf("ERROR (0x%lx): EVP_DecryptFinal_ex failed.\n", ERR_get_error());
#endif
        status = -4;
        goto clean;
    }
    *plain_ln += len;

clean:
    ;

    if ( status == 1 )
        status = 0;
    return (int)status;
}

int AES_clean(
    PAES_CTXT ctxt
)
{
    if ( ctxt->ctx )
        EVP_CIPHER_CTX_free(ctxt->ctx);
    AES_deleteKey(ctxt);

    memset(ctxt, 0, sizeof(*ctxt));

    return 0;
}

int AES_deleteKey(
    PAES_CTXT ctxt
)
{
    if ( !ctxt->key )
        return 0;

    memset(ctxt->key, 0, ctxt->key_ln);
    OPENSSL_free(ctxt->key);
    ctxt->key = NULL;
    ctxt->key_ln = 0;

    return 0;
}
