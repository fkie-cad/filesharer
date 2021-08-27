#ifndef SHARED_AES_CNG_H
#define SHARED_AES_CNG_H

#include <windows.h>
#include <bcrypt.h>

#include <stdint.h>


#define AES_STD_BLOCK_SIZE (0x10)
#define AES_IV_SIZE AES_STD_BLOCK_SIZE


typedef struct _AES_CTXT {
    BCRYPT_ALG_HANDLE alg;
    BCRYPT_KEY_HANDLE key;
    PUCHAR key_obj;
    ULONG key_obj_ln;
    ULONG block_size;
} AES_CTXT, * PAES_CTXT;

/**
 * Open RSA provider, get block size, set cipher mode.
 * Remember to clean.
 */
int AES_init(
    PAES_CTXT ctxt
);

/**
 * Generate AES key with given secret.
 * Remember to destroy.
 */
int AES_generateKey(
    PAES_CTXT ctxt,
    PUCHAR secret,
    ULONG secret_ln
);

/**
 * Encrypt buffer.
 * Allocates enrypted buffer. Be sure to free it afterwards.
 */
int AES_encrypt(
    PAES_CTXT ctxt,
    PUCHAR plain,
    ULONG plain_ln,
    PUCHAR* enrypted,
    PULONG encrypted_ln,
    PUCHAR iv,
    ULONG iv_ln
);

/**
 * Decrypt buffer.
 * Allocates plain buffer. Be sure to free it afterwards.
 */
int AES_decrypt(
    PAES_CTXT ctxt,
    PUCHAR encrypted,
    ULONG encrypted_ln,
    PUCHAR* plain,
    PULONG plain_ln,
    PUCHAR iv,
    ULONG iv_ln
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
