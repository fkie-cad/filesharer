#ifndef SHARED_CRYPTO_H
#define SHARED_CRYPTO_H

#include "env.h"

#ifdef _WIN32
#include "windows/AESCNG.h"
#include "windows/RSACNG.h"
#elif defined(_LINUX)
#include "linux/AESOpenSSL.h"
#include "linux/RSAOpenSSL.h"
#endif

#include <stdint.h>




#define INIT_PUB_KEY (0x1)
#define INIT_PRIV_KEY (0x2)

int c_init(
    char* path,
    int type
);

int init_AES();

int clean_AES();

int delete_AESKey();

int generateSecret(
    uint8_t* secret,
    uint32_t secret_ln
);

int generateIV(
        uint8_t* iv,
        uint32_t iv_ln
);

int generateRand(
        uint8_t* rand,
        uint32_t rand_ln
);

int importPubKeyFromFile(
    const char* path
);

int importPrivKeyFromFile(
    const char* path
);

int generateAESKey(
    uint8_t* secret,
    uint32_t secret_ln
);

/**
 * Encrypt AES secret and IV.
 */
int encryptKey(
    uint8_t* plain,
    uint32_t plain_ln,
    uint8_t** encrypted,
    uint32_t* encrypted_ln
);

/**
 * Decrypt AES secret and IV.
 */
int decryptKey(
    uint8_t* encrypted,
    uint32_t encrypted_ln,
    uint8_t** plain,
    uint32_t* plain_ln
);

int encryptData(
    uint8_t* plain,
    uint32_t plain_ln,
    uint8_t** encrypted,
    uint32_t* encrypted_ln,
    uint8_t* iv,
    uint32_t iv_ln
);

int decryptData(
    uint8_t* encrypted,
    uint32_t encrypted_ln,
    uint8_t** plain,
    uint32_t* plain_ln,
    uint8_t* iv,
    uint32_t iv_ln
);

int c_clean();


int rotate64Iv(
    uint8_t* iv, 
    uint32_t id
);

#endif
