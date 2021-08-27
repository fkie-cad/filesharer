#ifndef SHARED_RSA_CNG_H
#define SHARED_RSA_CNG_H

#include <windows.h>
#include <bcrypt.h>

#include <stdint.h>

typedef struct _RSA_CTXT {
    BCRYPT_ALG_HANDLE alg;
    BCRYPT_KEY_HANDLE pub_key;
    BCRYPT_KEY_HANDLE priv_key;
    ULONG padding;
    PVOID padding_info;
} RSA_CTXT, * PRSA_CTXT;

typedef enum _KEY_TYPE {KEY_TYPE_NONE, KEY_TYPE_DER, KEY_TYPE_PEM, KEY_TYPE_PUB, KEY_TYPE_BLOB} KEY_TYPE;

/**
 * Open RSA provider.
 * Remember to close.
 */
int RSA_init(
    PRSA_CTXT ctxt
);

/**
 * Import RSA public key from file.
 * Remember to close.
 */
int RSA_importPubKeyFromFile(
    PRSA_CTXT ctxt,
    const CHAR* path, 
    KEY_TYPE type
);

int RSA_exportPubKeyToDER(
    PRSA_CTXT ctxt,
    const CHAR* path
);

/**
 * Import RSA private key from.
 * Remember to close.
 */
int RSA_importPrivKeyFromFile(
    PRSA_CTXT ctxt,
    const CHAR* path, 
    KEY_TYPE type
);

int RSA_exportPrivKeyToDER(
    PRSA_CTXT ctxt,
    const CHAR* path
);

int RSA_encrypt(
    PRSA_CTXT ctxt,
    PUCHAR plain,
    ULONG plain_ln,
    PUCHAR* encrypted,
    PULONG encrypted_ln
);

int RSA_decrypt(
    PRSA_CTXT ctxt,
    PUCHAR encrypted,
    ULONG encrypted_ln,
    PUCHAR* plain,
    PULONG plain_ln
);

int RSA_signHash(
    PRSA_CTXT ctxt,
    PUCHAR hash,
    ULONG hash_ln,
    PUCHAR* signature,
    PULONG signature_ln
);

int RSA_signHash2(
    PRSA_CTXT ctxt,
    PUCHAR plain,
    ULONG plain_ln,
    PUCHAR* encrypted,
    PULONG encrypted_ln
);

int RSA_verifyHash(
    PRSA_CTXT ctxt,
    PUCHAR hash,
    ULONG hash_ln,
    PUCHAR* signature,
    ULONG* signature_ln
);

int RSA_verifyHash2(
    PRSA_CTXT ctxt,
    PUCHAR signature,
    ULONG signature_ln,
    PUCHAR* hash,
    PULONG hash_ln
);

int RSA_clean(
    PRSA_CTXT ctxt
);

#endif
