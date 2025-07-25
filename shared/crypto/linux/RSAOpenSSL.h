#ifndef SHARED_RSA_CNG_H
#define SHARED_RSA_CNG_H

#include <stdint.h>

#include <openssl/evp.h>



typedef struct _RSA_CTXT {
    EVP_PKEY_CTX *pub_ctx;
    EVP_PKEY_CTX *priv_ctx;
    EVP_PKEY *pub_key;
    EVP_PKEY *priv_key;
    int padding;
} RSA_CTXT, * PRSA_CTXT;

typedef enum _KEY_TYPE {KEY_TYPE_NONE, KEY_TYPE_DER, KEY_TYPE_PEM, KEY_TYPE_PUB, KEY_TYPE_BLOB} KEY_TYPE;

/**
 * Open RSA provider.
 * Remember to close.
 * 
 * @param ctxt PRSA_CTXT The context to be filled
 * @param padding uint32_t Padding scheme: RSA_PKCS1_PADDING, RSA_PKCS1_OAEP_PADDING (default)
 */
int RSA_init(
    PRSA_CTXT ctxt,
    uint32_t padding
);

/**
 * Import RSA public key from file.
 * Remember to close.
 */
int RSA_importPubKeyFromFile(
    PRSA_CTXT ctxt,
    const char* path
);

int RSA_exportPubKeyToDER(
    PRSA_CTXT ctxt,
    const char* path
);

/**
 * Import RSA private key from.
 * Remember to close.
 */
int RSA_importPrivKeyFromFile(
    PRSA_CTXT ctxt,
    const char* path
);

int RSA_exportPrivKeyToDER(
    PRSA_CTXT ctxt,
    const char* path
);

int RSA_encrypt(
    PRSA_CTXT ctxt,
    uint8_t* plain,
    uint32_t plain_ln,
    uint8_t** encrypted,
    uint32_t* encrypted_ln
);

int RSA_decrypt(
    PRSA_CTXT ctxt,
    uint8_t* encrypted,
    uint32_t encrypted_ln,
    uint8_t** plain,
    uint32_t* plain_ln
);

/**
 * Sign a hash value
 *
 * @param ctxt PRSA_CTXT
 * @param hash uint8_t* The hash bytes.
 * @param hash_ln uint32_t the hash buffer size
 * @param signature uint8_t** preallocated buffer of *signature_ln, or NULL buffer to be allocated. If allocated, has to be freed with freeBuffer, aka. OPENSSL_free.
 * @param signature_ln uint32_t* Size of preallocated signature buffer or filled with newly allocated buffer size.
 * @return
 */
int RSA_signHash(
    PRSA_CTXT ctxt,
    uint8_t* hash,
    uint32_t hash_ln,
    uint8_t** signature,
    uint32_t* signature_ln
);

/**
 * Verify a hash signature.
 *
 * @param ctxt PRSA_CTXT
 * @param hash uint8_t* hash bytes
 * @param hash_ln uint32_t hash buffer size.
 * @param signature uint8_t* Signature buffer.
 * @param signature_ln uint32_t Size of signature buffer.
 * @return 0 for success
 */
int RSA_verifyHash(
    PRSA_CTXT ctxt,
    uint8_t* hash,
    uint32_t hash_ln,
    uint8_t* signature,
    uint32_t signature_ln
);

/**
 * Sign a hash value.
 * Old API.
 *
 * @param ctxt PRSA_CTXT
 * @param hash uint8_t* SHA-256 digest
 * @param hash_ln uint32_t Has to 0x20, the size of the Sha256 buffer.
 * @param signature uint8_t** preallocated buffer of *signature_ln, or NULL buffer to be allocated. If allocated, has to be freed with freeBuffer, aka. OPENSSL_free.
 * @param signature_ln uint32_t* Size of preallocated signature buffer or filled with newly allocated buffer size.
 * @return 0 for success
 */
int RSA_signHash2(
    PRSA_CTXT ctxt,
    uint8_t* hash,
    uint32_t hash_ln,
    uint8_t** signature,
    uint32_t* signature_ln
);

/**
 * Verify a hash signature.
 * Old API.
 *
 * @param ctxt PRSA_CTXT
 * @param hash uint8_t* SHA-256 digest
 * @param hash_ln uint32_t Has to 0x20, the size of the Sha256 buffer.
 * @param signature uint8_t* Signature buffer.
 * @param signature_ln uint32_t Size of signature buffer.
 * @return 0 for success
 */
int RSA_verifyHash2(
    PRSA_CTXT ctxt,
    uint8_t* hash,
    uint32_t hash_ln,
    uint8_t* signature,
    uint32_t signature_ln
);

int RSA_clean(
    PRSA_CTXT ctxt
);

void freeBuffer(
    uint8_t* buffer
);

#endif
