#include "RSAOpenSSL.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/decoder.h>
//#include <openssl/encoder.h>
#include <openssl/rsa.h>

#include "../../print.h"

#define INPUT_TYPE "PEM"
#define KEY_TYPE "RSA"

int RSA_init(
    PRSA_CTXT ctxt
)
{
    int status = 0;

    memset(ctxt, 0, sizeof(*ctxt));

//    ctxt->ctx = EVP_CIPHER_CTX_new();
//    if ( !ctxt->ctx )
//    {
//        printf("ERROR (0x%lx): Creating cipher context failed.\n", ERR_get_error());
//        return -1;
//    }

    ctxt->padding = RSA_PKCS1_PADDING;
//    ctxt->padding = RSA_PKCS1_OAEP_PADDING;

    return status;
}

int RSA_importPubKeyFromFile(
    PRSA_CTXT ctxt,
    const char* path
)
{
    int s = 0;
    int b;
    FILE *file = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_DECODER_CTX *ectx = NULL;
    const char *propq = NULL;
    OSSL_LIB_CTX *libctx = NULL;

    ectx = OSSL_DECODER_CTX_new_for_pkey(&pkey,
                                         INPUT_TYPE,
                                         NULL,
                                         KEY_TYPE,
                                         EVP_PKEY_PUBLIC_KEY,
                                         libctx,
                                         propq);
    if ( ectx == NULL )
    {
        EPrint((int)ERR_get_error(), "OSSL_DECODER_CTX_new_for_pkey failed.\n");
        return -1;
    }
    DPrint("pkey: %p\n", (void*)pkey);
    DPrint("libctx: %p\n", (void*)libctx);
//    if (pass != NULL)
//        OSSL_ENCODER_CTX_set_passphrase(ectx, pass, strlen(pass));

    file = fopen(path, "rb");
    if ( !file )
    {
        EPrint(errno, "fopen \"%s\" failed.\n", path);
        s = -1;
        goto clean;
    }

    b = OSSL_DECODER_from_fp(ectx, file);
    if ( !b )
    {
        EPrint((int)ERR_get_error(), "OSSL_DECODER_from_fp failed.\n");
        s = -1;
        goto clean;
    }

    ctxt->pub_key = pkey;
    s = 0;

    ctxt->pub_ctx = EVP_PKEY_CTX_new(ctxt->pub_key, NULL);
    if ( ctxt->pub_ctx == NULL )
    {
        EPrint((int)ERR_get_error(), "EVP_PKEY_CTX_new failed.\n");
        s = -4;
        goto clean;
    }
    DPrint("pub_ctx: %p\n", (void*)ctxt->pub_ctx);

clean:
    if ( file )
        fclose(file);
    if ( ectx )
        OSSL_DECODER_CTX_free(ectx);
    if ( libctx )
        OSSL_LIB_CTX_free(libctx);
    if ( s != 0 && pkey )
        EVP_PKEY_free(pkey);

    return s;
}

int RSA_exportPubKeyToDER(
    PRSA_CTXT ctxt,
    const char* path
)
{
    int status = 0;

    return (int)status;
}

int pass_cb(char *buf, int size, int rwflag, void *u)
{
    /* We'd probably do something else if 'rwflag' is 1 */
    printf("Enter pass phrase for \"%s\"\n", (char *)u);

    /* get pass phrase, length 'len' into 'tmp' */
    char *tmp = "hello";
    if (tmp == NULL) /* An error occurred */
        return -1;

    size_t len = strlen(tmp);

    if (len > (size_t)size)
        len = size;
    memcpy(buf, tmp, len);

    return len;
}

int RSA_importPrivKeyFromFile(
    PRSA_CTXT ctxt,
    const char* path
)
{
    int s = 0;
    int b;
    FILE *file = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_DECODER_CTX *ectx = NULL;
    const char *propq = NULL;
    OSSL_LIB_CTX *libctx = NULL;

    ectx = OSSL_DECODER_CTX_new_for_pkey(&pkey,
                                         INPUT_TYPE,
                                         NULL,
                                         KEY_TYPE,
                                         EVP_PKEY_KEYPAIR,
                                         libctx,
                                         propq);
    if ( ectx == NULL )
    {
        EPrint((int)ERR_get_error(), "OSSL_DECODER_CTX_new_for_pkey failed.\n");
        return -1;
    }
    DPrint("pkey: %p\n", (void*)pkey);
    DPrint("libctx: %p\n", (void*)libctx);

//    if (passphrase != NULL) {
//        if (OSSL_DECODER_CTX_set_passphrase(dctx,
//                                            (const unsigned char *)passphrase,
//                                            strlen(passphrase)) == 0) {
//            fprintf(stderr, "OSSL_DECODER_CTX_set_passphrase() failed\n");
//            goto cleanup;
//        }
//    }

    file = fopen(path, "rb");
    if ( !file )
    {
        EPrint(errno, "fopen \"%s\" failed.\n", path);
        s = -1;
        goto clean;
    }

    b = OSSL_DECODER_from_fp(ectx, file);
    if ( !b )
    {
        EPrint((int)ERR_get_error(), "OSSL_DECODER_from_fp failed.\n");
        s = -1;
        goto clean;
    }

    ctxt->priv_key = pkey;
    s = 0;

    ctxt->priv_ctx = EVP_PKEY_CTX_new(ctxt->priv_key, NULL);
    if ( ctxt->priv_ctx == NULL )
    {
        EPrint((int)ERR_get_error(), "EVP_PKEY_CTX_new failed.\n");
        s = -4;
        goto clean;
    }
    DPrint("priv_ctx: %p\n", (void*)ctxt->priv_ctx);

clean:
    if ( file )
        fclose(file);
    if ( ectx )
        OSSL_DECODER_CTX_free(ectx);
    if ( libctx )
        OSSL_LIB_CTX_free(libctx);
    if ( s != 0 && pkey )
        EVP_PKEY_free(pkey);

    return s;
}

int RSA_exportPrivKeyToDER(
    PRSA_CTXT ctxt,
    const char* path
)
{
    int status = 0;


    return (int)status;
}

int RSA_encrypt(
    PRSA_CTXT ctxt,
    uint8_t* plain,
    uint32_t plain_ln,
    uint8_t** encrypted,
    uint32_t* encrypted_ln
)
{
    int status;
    size_t req_size = 0;

    status = EVP_PKEY_encrypt_init(ctxt->pub_ctx);
    if ( status != 1 )
    {
        EPrint((int)ERR_get_error(), "EVP_PKEY_encrypt_init failed.\n");
        status = -1;
        goto clean;
    }

    status = EVP_PKEY_CTX_set_rsa_padding(ctxt->pub_ctx, ctxt->padding);
    if ( status != 1 )
    {
        EPrint((int)ERR_get_error(), "EVP_PKEY_CTX_set_rsa_padding failed.\n");
        status = -1;
        goto clean;
    }

    // Determine buffer length
    status = EVP_PKEY_encrypt(ctxt->pub_ctx, NULL, &req_size, plain, plain_ln);
    if ( status != 1 )
    {
        EPrint((int)ERR_get_error(), "VP_PKEY_encrypt get size failed.\n");
        status = -2;
        goto clean;
    }

    // alloc or check buffer
    if ( *encrypted == NULL )
    {
        *encrypted = (uint8_t*)OPENSSL_malloc(req_size);
        if ( *encrypted == NULL )
        {
            EPrint(errno, "OPENSSL_malloc out failed.\n");
            status = -3;
            goto clean;
        }
    }
    else
    {
        if ( req_size > *encrypted_ln )
        {
            EPrint(-1, "Error: Provided encryption buffer[0x%x] is too small! 0x%zx needed.\n", *encrypted_ln, req_size);
            status = -3;
            goto clean;
        }
    }

    status = EVP_PKEY_encrypt(ctxt->pub_ctx, *encrypted, &req_size, plain, plain_ln);
    if ( status != 1 )
    {
        EPrint((int)ERR_get_error(), "EVP_PKEY_CTX_set_rsa_padding failed.\n");
        status = -4;
        goto clean;
    }
    *encrypted_ln = req_size;

clean:
    ;
    if ( status == 1 )
        status = 0;
    return (int)status;
}

int RSA_decrypt(
    PRSA_CTXT ctxt,
    uint8_t* encrypted,
    uint32_t encrypted_ln,
    uint8_t** plain,
    uint32_t* plain_ln
)
{
    int status;
    size_t req_size = 0;

    status = EVP_PKEY_decrypt_init(ctxt->priv_ctx);
    if ( status != 1 )
    {
        EPrint((int)ERR_get_error(), "EVP_PKEY_decrypt_init failed.\n");
        status = -1;
        goto clean;
    }

    status = EVP_PKEY_CTX_set_rsa_padding(ctxt->priv_ctx, ctxt->padding);
    if ( status != 1 )
    {
        EPrint((int)ERR_get_error(), "EVP_PKEY_CTX_set_rsa_padding failed.\n");
        status = -2;
        goto clean;
    }

    // Determine buffer length
    status = EVP_PKEY_decrypt(ctxt->priv_ctx, NULL, &req_size, encrypted, encrypted_ln);
    if ( status != 1 )
    {
        EPrint((int)ERR_get_error(), "EVP_PKEY_decrypt get size failed.\n");
        status = -3;
        goto clean;
    }

    // alloc or check buffer
    if ( *plain == NULL )
    {
        *plain = (uint8_t*)OPENSSL_malloc(req_size);
        if ( *plain == NULL )
        {
            EPrint(errno, "OPENSSL_malloc decryption failed.\n");
            status = -4;
            goto clean;
        }
    }
    else
    {
        if ( req_size > *plain_ln )
        {
            EPrint(-1, "Provided decryption buffer[0x%x] is too small! 0x%zx needed.\n", *plain_ln, req_size);
            status = -4;
            goto clean;
        }
    }

    status = EVP_PKEY_decrypt(ctxt->priv_ctx, *plain, &req_size, encrypted, encrypted_ln);
    if ( status != 1 )
    {
        EPrint((int)ERR_get_error(), "EVP_PKEY_decrypt failed.\n");
        status = -5;
        goto clean;
    }
    *plain_ln = req_size;

clean:
    ;
    if ( status == 1 )
        status = 0;
    return (int)status;
}

int RSA_signHash(
    PRSA_CTXT ctxt,
    uint8_t* hash,
    uint32_t hash_ln,
    uint8_t** signature,
    uint32_t* signature_ln
)
{
    int s = 0;
    size_t req_size = 0;
    EVP_MD_CTX *mdctx = NULL;

    /* Create the Message Digest Context */
    mdctx = EVP_MD_CTX_create();
    if( !mdctx )
        goto clean;

    // Initialise the DigestSign operation
    s = EVP_DigestSignInit(mdctx, NULL, NULL, NULL, ctxt->priv_key);
    // SHA-256 has been selected as the message digest function in this example
//    s = EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, ctxt->priv_key);
    if ( s <= 0 )
    {
#ifdef ERROR_PRINT
        printf("ERROR (0x%lx): EVP_DigestSignInit failed.\n", ERR_get_error());
#endif
        goto clean;
    }

    /* Call update with the hash */
    s = EVP_DigestSignUpdate(mdctx, hash, hash_ln);
    if ( s <= 0 )
    {
#ifdef ERROR_PRINT
        printf("ERROR (0x%lx): EVP_DigestSignUpdate failed.\n", ERR_get_error());
#endif
        goto clean;
    }

    /* Finalise the DigestSign operation */
    /* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the
    * signature. Length is returned in slen */
    s = EVP_DigestSignFinal(mdctx, NULL, &req_size);
    if ( s <= 0 )
    {
#ifdef ERROR_PRINT
        printf("ERROR (0x%lx): EVP_DigestSignFinal failed.\n", ERR_get_error());
#endif
        goto clean;
    }

    // alloc or check buffer
    if ( *signature == NULL )
    {
        *signature = (uint8_t*)OPENSSL_malloc(req_size);
        if ( *signature == NULL )
        {
#ifdef ERROR_PRINT
            printf("Error (0x%x): OPENSSL_malloc signature buffer\n", errno);
#endif
            s = -4;
            goto clean;
        }
    }
    else
    {
        if ( req_size > *signature_ln )
        {
#ifdef ERROR_PRINT
            printf("Error: Provided signature buffer[0x%x] is too small! 0x%zx needed.\n", *signature_ln, req_size);
#endif
            s = -4;
            goto clean;
        }
    }

    /* Obtain the signature */
    s = EVP_DigestSignFinal(mdctx, *signature, &req_size);
    if ( s <= 0 )
    {
#ifdef ERROR_PRINT
        printf("ERROR (0x%lx): EVP_DigestSignFinal failed.\n", ERR_get_error());
#endif
        goto clean;
    }

    *signature_ln = req_size;

clean:
    if ( mdctx )
        EVP_MD_CTX_destroy(mdctx);

    if ( s == 0 )
        s = -1;
    else if ( s == 1 )
        s = 0;

    return s;
}

int RSA_verifyHash(
    PRSA_CTXT ctxt,
    uint8_t* hash,
    uint32_t hash_ln,
    uint8_t* signature,
    uint32_t signature_ln
)
{
    int s = 0;
    EVP_MD_CTX *mdctx = NULL;

    /* Create the Message Digest Context */
    mdctx = EVP_MD_CTX_create();
    if( !mdctx )
        goto clean;

    /* Initialize `key` with a public key */
    s = EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, ctxt->pub_key);
    if ( s <= 0 )
    {
#ifdef ERROR_PRINT
        printf("ERROR (0x%lx): EVP_DigestVerifyInit failed.\n", ERR_get_error());
#endif
        goto clean;
    }

    /* Call update with the hash */
    s = EVP_DigestVerifyUpdate(mdctx, hash, hash_ln);
    if ( s <= 0 )
    {
#ifdef ERROR_PRINT
        printf("ERROR (0x%lx): EVP_DigestVerifyUpdate failed.\n", ERR_get_error());
#endif
        goto clean;
    }

    s = EVP_DigestVerifyFinal(mdctx, signature, signature_ln);
    if ( s <= 0 )
    {
#ifdef ERROR_PRINT
        printf("ERROR (0x%lx): EVP_DigestVerifyFinal failed.\n", ERR_get_error());
#endif
        goto clean;
    }

clean:
    if ( mdctx )
        EVP_MD_CTX_destroy(mdctx);

    if ( s == 0 )
        s = -1;
    else if ( s == 1 )
        s = 0;

    return s;
}


int RSA_signHash2(
    PRSA_CTXT ctxt,
    uint8_t* hash,
    uint32_t hash_ln,
    uint8_t** signature,
    uint32_t* signature_ln
)
{
    int s = 0;
    size_t req_size = 0;

//    EVP_PKEY_CTX *ctx;

    /*
    * NB: assumes signing_key and hash are set up before the next
    * step. signing_key must be an RSA private key and hash must
    * point to the SHA-256 digest to be signed.
    */
//    ctx = EVP_PKEY_CTX_new(signing_key, NULL /* no engine */);
    s = EVP_PKEY_sign_init(ctxt->priv_ctx);
    if ( s <= 0 )
    {
#ifdef ERROR_PRINT
        printf("ERROR (0x%lx): EVP_PKEY_sign_init failed.\n", ERR_get_error());
#endif
        goto clean;
    }

    s = EVP_PKEY_CTX_set_rsa_padding(ctxt->priv_ctx, ctxt->padding);
    if ( s <= 0 )
    {
#ifdef ERROR_PRINT
        printf("ERROR (0x%lx): EVP_PKEY_sign_init failed.\n", ERR_get_error());
#endif
        goto clean;
    }

    s = EVP_PKEY_CTX_set_signature_md(ctxt->priv_ctx, EVP_sha256());
    if ( s <= 0 )
    {
#ifdef ERROR_PRINT
        printf("ERROR (0x%lx): EVP_PKEY_sign_init failed.\n", ERR_get_error());
#endif
        goto clean;
    }

    /* Determine buffer length */
    s = EVP_PKEY_sign(ctxt->priv_ctx, NULL, &req_size, hash, hash_ln) ;
    if ( s <= 0 )
    {
#ifdef ERROR_PRINT
        printf("ERROR (0x%lx): EVP_PKEY_sign get size failed.\n", ERR_get_error());
#endif
        goto clean;
    }

    // alloc or check buffer
    if ( *signature == NULL )
    {
        *signature = (uint8_t*)OPENSSL_malloc(req_size);
        if ( *signature == NULL )
        {
#ifdef ERROR_PRINT
            printf("Error (0x%x): OPENSSL_malloc signature buffer\n", errno);
#endif
            s = -4;
            goto clean;
        }
    }
    else
    {
        if ( req_size > *signature_ln )
        {
#ifdef ERROR_PRINT
            printf("Error: Provided signature buffer[0x%x] is too small! 0x%zx needed.\n", *signature_ln, req_size);
#endif
            s = -4;
            goto clean;
        }
    }

    s = EVP_PKEY_sign(ctxt->priv_ctx, *signature, &req_size, hash, hash_ln);
    if ( s <= 0 )
    {
#ifdef ERROR_PRINT
        printf("ERROR (0x%lx): EVP_PKEY_sign failed.\n", ERR_get_error());
#endif
        goto clean;
    }

    *signature_ln = req_size;

clean:
    if ( s == 0 )
        s = -1;
    else if ( s == 1 )
        s = 0;

    return s;
}

int RSA_verifyHash2(
    PRSA_CTXT ctxt,
    uint8_t* hash,
    uint32_t hash_ln,
    uint8_t* signature,
    uint32_t signature_ln
)
{
    int s = 0;

    /*
    * NB: assumes verify_key, *signature, *signature_ln hash and hash_ln are already set up
    * and that verify_key is an RSA public key
    */
//    ctx = EVP_PKEY_CTX_new(verify_key, NULL /* no engine */);
//    if (!ctx)
    /* Error occurred */
    s = EVP_PKEY_verify_init(ctxt->pub_ctx);
    if ( s <= 0)
    {
#ifdef ERROR_PRINT
        printf("ERROR (0x%lx): EVP_PKEY_verify_init failed.\n", ERR_get_error());
#endif
        goto clean;
    }

    s = EVP_PKEY_CTX_set_rsa_padding(ctxt->pub_ctx, ctxt->padding);
    if ( s <= 0 )
    {
#ifdef ERROR_PRINT
        printf("ERROR (0x%lx): EVP_PKEY_CTX_set_rsa_padding failed.\n", ERR_get_error());
#endif
        goto clean;
    }

    s = EVP_PKEY_CTX_set_signature_md(ctxt->pub_ctx, EVP_sha256());
    if ( s <= 0 )
    {
#ifdef ERROR_PRINT
        printf("ERROR (0x%lx): EVP_PKEY_CTX_set_signature_md failed.\n", ERR_get_error());
#endif
        goto clean;
    }

    /* Perform operation */
    s = EVP_PKEY_verify(ctxt->pub_ctx, signature, signature_ln, hash, hash_ln);
    if ( s <= 0 )
    {
#ifdef ERROR_PRINT
        printf("ERROR (0x%lx): EVP_PKEY_verify failed.\n", ERR_get_error());
#endif
        goto clean;
    }

    /*
    * ret == 1 indicates success, 0 verify failure and < 0 for some
    * other error.
    */

clean:
    if ( s == 0 )
        s = -1;
    else if ( s == 1 )
        s = 0;

    return s;
}

int RSA_clean(PRSA_CTXT ctxt)
{
    if ( ctxt->pub_ctx )
        EVP_PKEY_CTX_free(ctxt->pub_ctx);
    if ( ctxt->pub_key )
        EVP_PKEY_free(ctxt->pub_key);
    if ( ctxt->priv_ctx )
        EVP_PKEY_CTX_free(ctxt->priv_ctx);
    if ( ctxt->priv_key )
        EVP_PKEY_free(ctxt->priv_key);

    memset(ctxt, 0, sizeof(*ctxt));

    return 0;
}

void freeBuffer(uint8_t* buffer)
{
    OPENSSL_free(buffer);
}
