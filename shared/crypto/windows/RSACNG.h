#ifndef SHARED_RSA_CNG_H
#define SHARED_RSA_CNG_H

#include <windows.h>
#include <bcrypt.h>

#include <stdint.h>

// bcrypt can be called at irql PASSIVE_LEVEL and/or DISPATCH_LEVEL 
// if running at dispatch level, 
// special care has to be taken for allocated buffers and opening the algorithmic provider
#define RUNNING_AT PASSIVE_LEVEL 

#if RUNNING_AT == PASSIVE_LEVEL
    #define ALLOC_POOL_TYPE PagedPool
    #define PROVIDER_FLAGS 0
#elif RUNNING_AT == DISPATCH_LEVEL
    #define ALLOC_POOL_TYPE NonPagedPool
    #define PROVIDER_FLAGS BCRYPT_PROV_DISPATCH
#endif


typedef struct _RSA_CTXT {
    BCRYPT_ALG_HANDLE alg;
    BCRYPT_KEY_HANDLE pub_key;
    BCRYPT_KEY_HANDLE priv_key;
    ULONG padding;
    PVOID padding_info;
} RSA_CTXT, * PRSA_CTXT;

typedef enum _KEY_TYPE {
    KEY_TYPE_NONE, 
    KEY_TYPE_DER, 
    //KEY_TYPE_PEM, 
    //KEY_TYPE_PUB, 
    //KEY_TYPE_WCBLOB,
    KEY_TYPE_BCBLOB
} KEY_TYPE;

/**
 * Open RSA provider.
 * Remember to close.
 * 
 * Fills a RSA_CTXT object
 * - set the alg to RSA
 * - set the padding 
 * 
 * @param ctxt PRSA_CTXT Context object to be filled
 * @param padding ULONG A padding scheme: BCRYPT_PAD_PKCS1 or BCRYPT_PAD_OAEP (default). BCRYPT_PAD_OAEP introduces an overhead of 2+2*hlen, i.e. reduces the possible message size. BCRYPT_PAD_PKCS1 just pads a possible rest with random numbers, i.e. no overhead.
 */
NTSTATUS RSA_init(
    _Out_ PRSA_CTXT ctxt,
    _In_ ULONG padding
);

/**
 * Import RSA public key from file and fill the ctxt object with it.
 * 
 * @param ctxt PRSA_CTXT Initialized context object to be filled.
 * @param path CHAR* Path to the key file
 * @param type KEY_TYPE Type of the key. 
 */
NTSTATUS RSA_importPubKeyFromFile(
    _Inout_ PRSA_CTXT ctxt,
    _In_ const CHAR* path, 
    _In_ KEY_TYPE type
);

#ifdef RING3
/**
 * Export RSA public key to .der file.
 * 
 * @param PubKey BCRYPT_KEY_HANDLE The pub key.
 * @param path CHAR* Path to the exported key file.
 */
NTSTATUS RSA_exportPubKeyToDER(
    _In_ BCRYPT_KEY_HANDLE pubKey,
    _In_ const CHAR* path
);
#endif

/**
 * Export RSA public key to .blob file.
 * 
 * @param PubKey BCRYPT_KEY_HANDLE The pub key.
 * @param path CHAR* Path to the exported key file.
 */
NTSTATUS RSA_exportPubKeyToBLOB(
    _In_ BCRYPT_KEY_HANDLE pubKey,
    _In_ const CHAR* path
);

/**
 * Import RSA private key from file and fill the ctxt object with it.
 * 
 * @param ctxt PRSA_CTXT Initialized context object to be filled.
 * @param path CHAR* Path to the key file
 * @param type KEY_TYPE Type of the key. 
 */
NTSTATUS RSA_importPrivKeyFromFile(
    _Inout_ PRSA_CTXT ctxt,
    _In_ const CHAR* path, 
    _In_ KEY_TYPE type
);

#ifdef RING3
/**
 * Export RSA private key to .der file.
 * !! Not implemented yet !!
 * 
 * @param key BCRYPT_KEY_HANDLE The pub key.
 * @param path CHAR* Path to the exported key file.
 */
NTSTATUS RSA_exportPrivKeyToDER(
    _In_ BCRYPT_KEY_HANDLE privKey,
    _In_ const CHAR* path
);
#endif

/**
 * Export RSA private key to .blob file.
 * 
 * @param PubKey BCRYPT_KEY_HANDLE The priv key.
 * @param path CHAR* Path to the exported key file.
 */
NTSTATUS RSA_exportPrivKeyToBLOB(
    _In_ BCRYPT_KEY_HANDLE privKey,
    _In_ const CHAR* path
);

/**
 * Encrypt a buffer with RSA using the public key.
 * 
 * @param pubKey BCRYPT_KEY_HANDLE The public key used for encryption.
 * @param plain PUCHAR Plain input buffer.
 * @param plain_ln ULONG Plain input buffer size in bytes.
 * @param encrypted PUCHAR Output buffer filled with the encrypted bytes. If NULL, it will be allocated internally and has to be freed when not needed anymore.
 * @param encrypted_ln PULONG Size of the encrypted output buffer in bytes. If the buffer is preallocated, it should tell its size.
 */
NTSTATUS RSA_encrypt(
    _In_ PRSA_CTXT ctxt,
    _In_ PUCHAR plain,
    _In_ ULONG plain_ln,
    _Inout_ PUCHAR* encrypted,
    _Inout_ PULONG encrypted_ln
);

/**
 * Decrypt an RSA encrypted buffer using the private key.
 * 
 * @param privKey BCRYPT_KEY_HANDLE The private key used for decryption.
 * @param encrypted PUCHAR Encrypted input buffer.
 * @param encrypted_ln ULONG Encrypted input buffer size in bytes.
 * @param plain PUCHAR Output buffer filled with the decrypted bytes. If NULL, it will be allocated internally and has to be freed when not needed anymore.
 * @param plain_ln PULONG Size of the decrypted output buffer in bytes. If the buffer is preallocated, it should tell its size.
 */
NTSTATUS RSA_decrypt(
    _In_ PRSA_CTXT ctxt,
    _In_ PUCHAR encrypted,
    _In_ ULONG encrypted_ln,
    _Inout_ PUCHAR* plain,
    _Inout_ PULONG plain_ln
);

/**
 * Sign a hash with RSA using the private key.
 * 
 * @param privKey BCRYPT_KEY_HANDLE The private key used for the signature.
 * @param algId LPCWSTR Hash algorithm used for padding. Has to match the input hash algorithm. E.g. BCRYPT_SHA256_ALGORITHM
 * @param hash PUCHAR Hash value input buffer.
 * @param hash_ln ULONG Hash value input buffer size in bytes.
 * @param signature PUCHAR Output buffer filled with the signature bytes. If NULL, it will be allocated internally and has to be freed when not needed anymore.
 * @param signature_ln PULONG Size of the signature bytes output buffer in bytes. If the buffer is preallocated, it should tell its size.
 */
NTSTATUS RSA_signHash(
    _In_ BCRYPT_KEY_HANDLE privKey,
    _In_ LPCWSTR algId,
    _In_ PUCHAR hash,
    _In_ ULONG hash_ln,
    _Inout_ PUCHAR* signature,
    _Inout_ PULONG signature_ln
);

/**
 * Verify a signature with RSA using the public key.
 * 
 * @param privKey BCRYPT_KEY_HANDLE The public key used for the verification.
 * @param algId LPCWSTR Hash algorithm used for padding. Has to match the input hash algorithm. E.g. BCRYPT_SHA256_ALGORITHM
 * @param hash PUCHAR Expected hash value to be verified.
 * @param hash_ln ULONG Expected hash value buffer size in bytes.
 * @param signature PUCHAR The signature to verify.
 * @param signature_ln ULONG Size of the signature to verify in bytes.
 */
NTSTATUS RSA_verifyHash(
    _In_ BCRYPT_KEY_HANDLE pubKey,
    _In_ LPCWSTR algId,
    _In_ PUCHAR hash,
    _In_ ULONG hash_ln,
    _In_ PUCHAR signature,
    _In_ ULONG signature_ln
);

/**
 * Clean up RSA provider and keys.
 * 
 * - Closes rsa provider
 * - Destroys public key
 * - Destroys private key
 * [- Frees padding info]
 * - zeros the context object's memory
 * 
 * @param ctxt PRSA_CTXT Context object to be used.
 */
NTSTATUS RSA_clean(
    _Inout_ PRSA_CTXT ctxt
);


#endif
