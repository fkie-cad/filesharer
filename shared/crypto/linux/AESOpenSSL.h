#ifndef SHARED_AES_OPEN_SSL_H
#define SHARED_AES_OPEN_SSL_H

//#include <openssl/conf.h>
#include <openssl/evp.h>

#include <stdint.h>


#define AES_STD_BLOCK_SIZE (0x10)
#define AES_IV_SIZE AES_STD_BLOCK_SIZE

#define GET_ENC_AES_SIZE(__ds__) ( __ds__ + ( AES_STD_BLOCK_SIZE - ( __ds__ % AES_STD_BLOCK_SIZE ) ) )


typedef struct _AES_CTXT {
    EVP_CIPHER_CTX *ctx;
    uint8_t *key;
    uint32_t key_ln;
    int block_size;
} AES_CTXT, * PAES_CTXT;

/**
 */
int AES_init(
    PAES_CTXT ctxt
);

/**
 * Generate AES key with given secret.
 * Remember to destroy.
 */
int AES_generateRandom(
    uint8_t* random,
    int random_ln
);

/**
 * Generate AES key with given secret.
 * Remember to destroy.
 */
int AES_generateKey(
    PAES_CTXT ctxt,
    uint8_t* secret,
    uint32_t secret_ln
);

/**
 * Encrypt buffer.
 * Allocates enrypted buffer. Be sure to free it afterwards.
 */
int AES_encrypt(
    PAES_CTXT ctxt,
    uint8_t* plain,
    uint32_t plain_ln,
    uint8_t** enrypted,
    uint32_t* encrypted_ln,
    uint8_t* iv,
    uint32_t iv_ln
);

/**
 * Decrypt buffer.
 * Allocates plain buffer. Be sure to free it afterwards.
 */
int AES_decrypt(
    PAES_CTXT ctxt,
    uint8_t* encrypted,
    uint32_t encrypted_ln,
    uint8_t** plain,
    uint32_t* plain_ln,
    uint8_t* iv,
    uint32_t iv_ln
);

/**
 * Clean up.
 * Close provider, destroy key, free key buffer.
 */
int AES_clean(
    PAES_CTXT ctxt
);

/**
 * Clean up.
 * Destroy key, free key buffer.
 */
int AES_deleteKey(
    PAES_CTXT ctxt
);

#endif
