#include "../crypto.h"

#include <stdio.h>
#include <stdlib.h>

#include "../../../src/FsHeader.h"

static RSA_CTXT rsa_ctxt;
static AES_CTXT aes_ctxt;

/**
 * Init crypto
 */
int c_init(
    char* path,
    int type
)
{
    int s = 0;

    s = RSA_init(&rsa_ctxt, RSA_PADDING);
    if ( s < 0 )
    {
#ifdef ERROR_PRINT
        printf("ERROR: RSA_init failed\n");
#endif
        return s;
    }

    if ( type == INIT_PUB_KEY )
    {
        s = importPubKeyFromFile(path);
        if ( s != 0 )
            return s;
    }
    else if ( type == INIT_PRIV_KEY )
    {
        s = importPrivKeyFromFile(path);
        if ( s != 0 )
            return s;
    }
    else
    {
#ifdef ERROR_PRINT
        printf("ERROR: unknown key type to import!\n");
#endif
        return -1;
    }
    
    s = init_AES();
    //if ( s != 0 )
    //    return s;

    return s;
}

int init_AES()
{
    int s = AES_init(&aes_ctxt);
    if ( s < 0 )
    {
#ifdef ERROR_PRINT
        printf("ERROR: AES_init failed\n");
#endif
        return -1;
    }

    if ( AES_STD_BLOCK_SIZE != aes_ctxt.block_size )
    {
#ifdef ERROR_PRINT
        printf("ERROR: static BLOCK_SIZE != calculated block size\n");
#endif
        return -1;
    }

    return s;
}

int generateSecret(
    uint8_t* secret,
    uint32_t secret_ln
)
{
    return generateRand(secret, secret_ln);
}

int generateIV(
    uint8_t* iv,
    uint32_t iv_ln
)
{
    return generateRand(iv, iv_ln);
}

int generateRand(
    uint8_t* rand,
    uint32_t rand_ln
)
{
    int s;
    RtlZeroMemory(rand, rand_ln);
    s = BCryptGenRandom(
        NULL,
        rand,
        rand_ln,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    if ( s != 0 )
    {
#ifdef ERROR_PRINT
        printf("ERROR: BCryptGenRandom failed\n");
#endif
        return s;
    }

    return 0;
}

int importPubKeyFromFile(
    const char* path
)
{
    int s = RSA_importPubKeyFromFile(&rsa_ctxt, path, KEY_TYPE_DER);
    if ( s != 0 )
    {
#ifdef ERROR_PRINT
        printf("ERROR (0x%x): RSA import public key failed\n", s);
#endif
        return s;
    }

    return 0;
}

int importPrivKeyFromFile(
    const char* path
)
{
    int s = RSA_importPrivKeyFromFile(&rsa_ctxt, path, KEY_TYPE_DER);
    if ( s != 0 )
    {
#ifdef ERROR_PRINT
        printf("ERROR (0x%x): RSA import private key failed\n", s);
#endif
        return s;
    }

    return 0;
}

int generateAESKey(
    uint8_t* secret,
    uint32_t secret_ln
)
{
    int s = 0;

    if ( aes_ctxt.key != NULL )
    {
        AES_deleteKey(&aes_ctxt);
    }

    s = AES_generateKey(
        &aes_ctxt,
        secret,
        secret_ln
    );
    if ( s < 0 )
    {
#ifdef ERROR_PRINT
        printf("ERROR: AES_generateKey failed (0x%x)\n", s);
#endif
        return s;
    }
    return 0;
}

int encryptKey(
    uint8_t* plain,
    uint32_t plain_ln,
    uint8_t** encrypted,
    uint32_t* encrypted_ln
)
{
    int s = 0;

//    if ( plain_ln < FS_KEY_HEADER_SIZE )
//    {
//#ifdef ERROR_PRINT
//        printf("Header buffer too small\n");
//#endif
//        return s;
//    }

    s = RSA_encrypt(
        &rsa_ctxt, 
        plain, 
        plain_ln, 
        encrypted, 
        (PULONG)encrypted_ln
    );
    if ( s != 0 )
    {
#ifdef ERROR_PRINT
        printf("ERROR: RSA_encrypt failed\n");
#endif
        return s;
    }

    return 0;
}

int decryptKey(
    uint8_t* encrypted,
    uint32_t encrypted_ln,
    uint8_t** plain,
    uint32_t* plain_ln
)
{
    int s = 0;

    s = RSA_decrypt(
        &rsa_ctxt, 
        encrypted, 
        encrypted_ln, 
        plain, 
        (PULONG)plain_ln
    );
    if ( s != 0 )
    {
#ifdef ERROR_PRINT
        printf("ERROR: RSA_decrypt failed\n");
#endif 
        return s;
    }

    return 0;
}

int encryptData(
    uint8_t* plain,
    uint32_t plain_ln,
    uint8_t** encrypted,
    uint32_t* encrypted_ln,
    uint8_t* iv,
    uint32_t iv_ln
)
{
    int s = 0;
    
    s = AES_encrypt(
        &aes_ctxt,
        plain,
        plain_ln,
        encrypted,
        (PULONG)encrypted_ln,
        iv,
        iv_ln
    );
    if ( s < 0 )
    {
#ifdef ERROR_PRINT
        printf("ERROR: AES_encrypt failed\n");
#endif
        return s;
    }

    return 0;
}

int decryptData(
    uint8_t* encrypted,
    uint32_t encrypted_ln,
    uint8_t** plain,
    uint32_t* plain_ln,
    uint8_t* iv,
    uint32_t iv_ln
)
{
    int s = 0;

    s = AES_decrypt(
        &aes_ctxt,
        encrypted,
        encrypted_ln,
        plain,
        (PULONG)plain_ln,
        iv,
        iv_ln
    );
    if ( s < 0 )
    {
#ifdef ERROR_PRINT
        printf("ERROR: AES_decrypt failed\n");
#endif
        return s;
    }

    return 0;
}

int c_clean()
{
    clean_AES();
    RSA_clean(&rsa_ctxt);

    return 0;
}

int clean_AES()
{
    AES_clean(&aes_ctxt);
    return 0;
}

int delete_AESKey()
{
    return AES_deleteKey(&aes_ctxt);
}

#include <intrin.h>
// # : 8^16  2^48
int rotate64Iv(uint8_t* iv, uint32_t id)
{
    int s = 0;

    uint32_t i;
    uint8_t rot;

    for ( i = 0; i < 0x10; i++ )
    {
        rot = id % 0x8;
        iv[i] = _rotl8(iv[i], rot);
    
        id = id >> 0x3;
    }

    return s;
}
