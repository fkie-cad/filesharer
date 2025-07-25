#include "RSACNG.h"

#include <winternl.h>
#include <wincrypt.h> // old
#include <strsafe.h>

#include <stdio.h>
#include <stdlib.h>

#include "../../winDefs.h"
#include "../../print.h"


#ifdef RING3
#define ExAllocatePoolWithTag(_pt_, _n_, _t_) malloc(_n_)
#define ExFreePoolWithTag(_p_, _t_) free(_p_)
#define ExFreePool(_p_) free(_p_)
#define RtlStringCchPrintfW StringCchPrintfW
#endif


NTSTATUS loadFileBytes(
    _In_ const CHAR* path, 
    _Out_ PUCHAR* buffer, 
    _Out_ PULONG buffer_ln
);

NTSTATUS writeFileBytes(
    _In_ const CHAR* path, 
    _In_ PUCHAR buffer, 
    _In_ ULONG buffer_ln
);


//
// debug blob print functions
//
#ifdef DEBUG_PRINT
__forceinline
void printWcPubBlob(PUBLICKEYSTRUC* wc_blob, ULONG wc_blob_ln)
{
    RSAPUBKEY* wc_blob_pk = (RSAPUBKEY*)(wc_blob + 1);

    printf("wc blob\n");
    printf(" bType: 0x%x\n", wc_blob->bType);
    printf(" bVersion: 0x%x\n", wc_blob->bVersion);
    printf(" aiKeyAlg: 0x%x\n", wc_blob->aiKeyAlg);
    printf("wc pk\n");
    printf(" Magic: 0x%x (%.4s)\n", wc_blob_pk->magic, (CHAR*)&wc_blob_pk->magic);
    printf(" BitLength: 0x%x\n", wc_blob_pk->bitlen);
    printf(" cbPublicExp: 0x%x\n", wc_blob_pk->pubexp);
}

__forceinline
void printWcPrivBlob(PUBLICKEYSTRUC* wc_blob, ULONG wc_blob_ln)
{
    RSAPUBKEY* wc_blob_pk = (RSAPUBKEY*)(wc_blob + 1);
    UINT8* wcb_ptr;

    printf("wc blob\n");
    printf(" bType: 0x%x\n", wc_blob->bType);
    printf(" bVersion: 0x%x\n", wc_blob->bVersion);
    printf(" aiKeyAlg: 0x%x\n", wc_blob->aiKeyAlg);
    printf("wc pk\n");
    printf(" Magic: 0x%x (%.4s)\n", wc_blob_pk->magic, (CHAR*)&wc_blob_pk->magic);
    printf(" BitLength: 0x%x\n", wc_blob_pk->bitlen);
    printf(" cbPublicExp: 0x%x\n", wc_blob_pk->pubexp);
    
    ULONG modulus_bytes = wc_blob_pk->bitlen >> 3;
    ULONG prime_bytes = modulus_bytes >> 1;
    
    wcb_ptr = (PUINT8)(wc_blob_pk+1);

    printf("modulus (0x%x):\n", modulus_bytes);
    DPrintMemCol8(wcb_ptr, modulus_bytes, wcb_ptr);

    wcb_ptr += modulus_bytes;
    printf("prime1 (0x%x):\n", modulus_bytes);
    DPrintMemCol8(wcb_ptr, prime_bytes, wcb_ptr);
    
    wcb_ptr += prime_bytes;
    printf("prime2 (0x%x):\n", prime_bytes);
    DPrintMemCol8(wcb_ptr, prime_bytes, wcb_ptr);
}

__forceinline
void printBcPubBlob(BCRYPT_RSAKEY_BLOB* blob, ULONG blob_ln)
{
    PUINT8 ptr = NULL;
    
    printf("bc blob\n");
    printf(" Magic: 0x%x (%.4s)\n", blob->Magic, (CHAR*)&blob->Magic);
    printf(" BitLength: 0x%x\n", blob->BitLength);
    printf(" cbPublicExp: 0x%x\n", blob->cbPublicExp);
    printf(" cbModulus: 0x%x\n", blob->cbModulus);
    printf(" cbPrime1: 0x%x\n", blob->cbPrime1);
    printf(" cbPrime2: 0x%x\n", blob->cbPrime2);
    //PublicExponent[cbPublicExp] // Big-endian.
    //Modulus[cbModulus] // Big-endian.
    
    //printf("bc blob raw bytes (0x%x):\n", blob_ln);
    //DPrintMemCol8(buffer, blob_ln, 0);
    ptr = ((PUINT8)(blob + 1));
    printf("bc blob exponent (0x%x):\n", blob->cbPublicExp);
    DPrintMemCol8(ptr, blob->cbPublicExp, 0);
    ptr += blob->cbPublicExp;
    printf("blob data (0x%x):\n", blob->cbModulus);
    DPrintMemCol8(ptr, blob->cbModulus, 0);
}

__forceinline
void printBcPrivBlob(BCRYPT_RSAKEY_BLOB* blob, ULONG blob_ln)
{
    PUINT8 ptr = NULL;

    printf("bc blob\n");
    printf(" Magic: 0x%x (%.4s)\n", blob->Magic, (CHAR*)&blob->Magic);
    printf(" BitLength: 0x%x\n", blob->BitLength);
    printf(" cbPublicExp: 0x%x\n", blob->cbPublicExp);
    printf(" cbModulus: 0x%x\n", blob->cbModulus);
    printf(" cbPrime1: 0x%x\n", blob->cbPrime1);
    printf(" cbPrime2: 0x%x\n", blob->cbPrime2);
    ptr = ((PUINT8)(blob + 1));
    printf("  exponent (0x%x):\n", blob->cbPublicExp);
    DPrintMemCol8(ptr, blob->cbPublicExp, 0);
    ptr += blob->cbPublicExp;
    printf("  modulus (0x%x):\n", blob->cbModulus);
    DPrintMemCol8(ptr, blob->cbModulus, 0);
    ptr += blob->cbModulus;
    printf("  prime1 (0x%x):\n", blob->cbPrime1);
    DPrintMemCol8(ptr, blob->cbPrime1, 0);
    ptr += blob->cbPrime1;
    printf("  prime2 (0x%x):\n", blob->cbPrime2);
    DPrintMemCol8(ptr, blob->cbPrime2, 0);
}
#endif



#define ZeroLocalFree(_b_, _n_) { \
    RtlSecureZeroMemory(_b_, _n_); \
    LocalFree(_b_);  \
}
#define ZeroFree(_b_, _n_) { \
    RtlSecureZeroMemory(_b_, _n_); \
    free(_b_); \
}

NTSTATUS RSA_init(
    _Out_ PRSA_CTXT ctxt,
    _In_ ULONG padding
)
{
    NTSTATUS status = STATUS_SUCCESS;

    RtlZeroMemory(ctxt, sizeof(RSA_CTXT));

    status = BCryptOpenAlgorithmProvider(
        &ctxt->alg,
        BCRYPT_RSA_ALGORITHM,
        NULL,
        PROVIDER_FLAGS
    );
    if ( status != 0 )
    {
        //EPrint("BCryptOpenAlgorithmProvider failed! (0x%x)\n", status);
        return status;
    }

    if ( padding == BCRYPT_PAD_PKCS1 )
    {
        // The data will be padded with a random number to round out the block size. 
        // The pPaddingInfo parameter is not used.
        ctxt->padding = BCRYPT_PAD_PKCS1; 
        ctxt->padding_info = NULL;
    }
    else 
    {
        // Use the Optimal Asymmetric Encryption Padding (OAEP) scheme. 
        // The pPaddingInfo parameter is a pointer to a BCRYPT_OAEP_PADDING_INFO structure.
        // https://stackoverflow.com/a/51335963
        // https://www.ietf.org/rfc/rfc3447.txt
        // https://www.rfc-editor.org/rfc/rfc3447#section-7.1.1

        ctxt->padding = BCRYPT_PAD_OAEP; // fill and pass pad_info
        BCRYPT_OAEP_PADDING_INFO* pad_info = (BCRYPT_OAEP_PADDING_INFO*)ExAllocatePoolWithTag(ALLOC_POOL_TYPE, sizeof(BCRYPT_OAEP_PADDING_INFO), 'idap');
        if ( !pad_info )
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto clean;
        }
        RtlZeroMemory(pad_info, sizeof(BCRYPT_OAEP_PADDING_INFO));
        // greater hash algorithms don't introduce more security on OAEP but shorten the possible message size
        pad_info->pszAlgId = BCRYPT_SHA1_ALGORITHM;
        pad_info->pbLabel = NULL; // optional label to be associated with the message; the default value for L, if L is not provided, is the empty string
        pad_info->cbLabel = 0;
        ctxt->padding_info = pad_info;
    }
    
clean:

    return status;
}

/**
 * Copy bytes in reversed order.
 * Does not support copying to the same or overlapping buffers.
 * 
 * @param pbDest UINT8* The destination buffer.
 * @param pbSource UINT8* The source buffer.
 * @param cb ULONG Number of bytes to copy.
 */
void ReverseMemCopy(UINT8 *pbDest, UINT8 const *pbSource, ULONG cb)
{
    for ( ULONG i = 0; i < cb; i++ )
    {
        pbDest[cb - 1 - i] = pbSource[i];
    }
}

#ifdef RING3
/**
 * Allocates wc_blob, has to be freed by caller.
 */
NTSTATUS RSA_pub_pemBlobToWcBlob(
    _In_ PVOID key_file_bytes, 
    _In_ ULONG key_file_bytes_ln,
    _Out_ PUBLICKEYSTRUC** wc_blob,
    _Out_ PULONG wc_blob_ln
)
{
    NTSTATUS status = STATUS_SUCCESS;
    BOOL b;

    *wc_blob = NULL;
    *wc_blob_ln = 0;

//#ifdef DEBUG_PRINT
//        printf("convert pem\n");
//#endif
//    b = CryptStringToBinaryA(
//        (CHAR*)&key_buffer[offset],
//        key_buffer_ln-cut,
//        CRYPT_STRING_ANY,
//        NULL,
//        &key_bytes_ln,
//        NULL,
//        NULL
//    );
//    if ( !b )
//    {
//        status = STATUS_UNSUCCESSFUL;
//#ifdef ERROR_PRINT
//        printf("CryptStringToBinaryA.\n");
//#endif
//        goto clean;
//    }
//#ifdef DEBUG_PRINT
//    printf("Need 0x%x bytes for key\n", key_bytes_ln);
//#endif
//    key_bytes = (UCHAR*) LocalAlloc(0, key_bytes_ln);
//    if (key_bytes == NULL) 
//    {
//        status = STATUS_NO_MEMORY;
//#ifdef ERROR_PRINT
//        printf("LocalAlloc.\n");
//#endif
//        goto clean;
//    }
//    b = CryptStringToBinaryA(
//        (CHAR*)&key_buffer[offset],
//        key_buffer_ln-cut,
//        CRYPT_STRING_ANY,
//        key_bytes,
//        &key_bytes_ln,
//        NULL,
//        NULL
//    );
//    if ( !b )
//    {
//        status = STATUS_UNSUCCESSFUL;
//#ifdef ERROR_PRINT
//        printf("CryptStringToBinaryA.\n");
//#endif
//        goto clean;
//    }

    return status;
}

/**
 * Allocates wc_blob, has to be freed by caller.
 */
NTSTATUS RSA_pub_derBlobToWcBlob(
    _In_ PVOID key_file_bytes, 
    _In_ ULONG key_file_bytes_ln,
    _Out_ PUBLICKEYSTRUC** wc_blob,
    _Out_ PULONG wc_blob_ln
)
{
    NTSTATUS status = STATUS_SUCCESS;
    BOOL b;

    UCHAR* key_bytes = NULL;
    ULONG key_bytes_ln = 0;

    *wc_blob = NULL;
    *wc_blob_ln = 0;
    
    // der = big endian
    // wc.blob = little endian
    DPrint("Convert DER file bytes\n");
    key_bytes_ln = key_file_bytes_ln;
    CERT_PUBLIC_KEY_INFO *publicKeyInfo = NULL;
    ULONG publicKeyInfoLen = 0;

    // Decode from DER format to CERT_PUBLIC_KEY_INFO. 
    // This has the public key in ASN.1 encoded format 
    // called "SubjectPublicKeyInfo" ... szOID_RSA_RSA
    b = CryptDecodeObjectEx(
        X509_ASN_ENCODING, 
        X509_PUBLIC_KEY_INFO, 
        key_file_bytes,
        key_file_bytes_ln, 
        CRYPT_ENCODE_ALLOC_FLAG, 
        NULL, 
        &publicKeyInfo, 
        &publicKeyInfoLen
    );
    if ( !b )
    {
        //status = STATUS_UNSUCCESSFUL;
        status = GetLastError();
        //EPrint("CryptDecodeObjectEx failed 1! (0x%x)\n", status);
        goto clean;
    }
    
#ifdef DEBUG_PRINT
    printf("publicKeyInfo : %p\n", publicKeyInfo);
    printf("publicKeyInfo bytes (0x%x):\n", publicKeyInfoLen);
    DPrintMemCol8(publicKeyInfo, publicKeyInfoLen, 0);
    printf(" Algorithm\n");
    printf("  pszObjId: %s (%p)\n", publicKeyInfo->Algorithm.pszObjId, publicKeyInfo->Algorithm.pszObjId);
    printf("  Parameters (0x%x) (%p)\n    ", publicKeyInfo->Algorithm.Parameters.cbData, publicKeyInfo->Algorithm.Parameters.pbData);
    for ( ULONG i = 0; i < publicKeyInfo->Algorithm.Parameters.cbData; i++ )
        printf("%02x ", publicKeyInfo->Algorithm.Parameters.pbData[i]);
    printf("\n");
    printf(" PublicKey (0x%x) (%p)\n  ", publicKeyInfo->PublicKey.cbData, publicKeyInfo->PublicKey.pbData);
    for ( ULONG i = 0; i < publicKeyInfo->PublicKey.cbData; i++ )
        printf("%02x ", publicKeyInfo->PublicKey.pbData[i]);
    printf("\n");
    printf(" unused: 0x%x\n", publicKeyInfo->PublicKey.cUnusedBits);
#endif

    // Decode the RSA Public key itself to a PUBLICKEYBLOB
    b = CryptDecodeObjectEx(
        X509_ASN_ENCODING, 
        RSA_CSP_PUBLICKEYBLOB,
        publicKeyInfo->PublicKey.pbData, 
        publicKeyInfo->PublicKey.cbData,
        CRYPT_ENCODE_ALLOC_FLAG, // use LocalFree to free
        NULL, 
        &key_bytes, 
        &key_bytes_ln
    );
    if ( !b )
    {
        status = GetLastError();
        //EPrint("CryptDecodeObjectEx failed 2! (0x%x)\n", status);
        goto clean;
    }
#ifdef DEBUG_PRINT
    printf("key bytes (0x%x):\n", key_bytes_ln);
    DPrintMemCol8(key_bytes, key_bytes_ln, 0);
#endif
    
    RSAPUBKEY* wc_blob_pk = (RSAPUBKEY*)(key_bytes + sizeof(BLOBHEADER));
    if ( wc_blob_pk->magic != BCRYPT_RSAPUBLIC_MAGIC )
    {
        status = STATUS_UNSUCCESSFUL;
        //EPrint("Not a RSA public key! (0x%x)\n", status);
        goto clean;
    }

    *wc_blob = (PUBLICKEYSTRUC*)(&key_bytes[0]);
    *wc_blob_ln = key_bytes_ln - 0;
    

clean:
    if ( publicKeyInfo != NULL )
        LocalFree(publicKeyInfo);

    return status;
}

/**
 * Allocates blob, has to be freed by caller.
 */
NTSTATUS RSA_pub_wcBlobToBcBlob(
    _In_ RSAPUBKEY* wc_blob_pk,
    _Out_ BCRYPT_RSAKEY_BLOB** bc_blob,
    _Out_ PULONG bc_blob_ln
)
{
    NTSTATUS status = STATUS_SUCCESS;
    
    PUINT8 blobBuffer = NULL;
    BCRYPT_RSAKEY_BLOB* blob = NULL;
    ULONG blob_ln = 0;

    *bc_blob = NULL;
    *bc_blob_ln = 0;
    
    if ( wc_blob_pk->magic != BCRYPT_RSAPUBLIC_MAGIC )
    {
        status = STATUS_UNSUCCESSFUL;
        printf("Not an RSA public key. (0x%x)\n", status);
        goto clean;
    }

    // Fill header
    //
    // This structure is used as a header for a larger buffer. 
    // An RSA public key BLOB (BCRYPT_RSAPUBLIC_BLOB) has the following format in contiguous memory. 
    // All of the numbers following the structure are in big-endian format.
    // 
    // BCRYPT_RSAKEY_BLOB
    // PublicExponent[cbPublicExp] // Big-endian.
    // Modulus[cbModulus] // Big-endian.
    
    // ->BCRYPT_RSAKEY_BLOB
    ULONG modulus_bytes = wc_blob_pk->bitlen >> 3;
    blob_ln = sizeof(BCRYPT_RSAKEY_BLOB) + sizeof(wc_blob_pk->pubexp) + modulus_bytes;
    blobBuffer = (PUINT8)malloc(blob_ln);
    if ( blobBuffer == NULL )
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        //EPrint("LocalAlloc failed! (0x%x)\n", status);
        goto clean;
    }
    RtlZeroMemory(blobBuffer, blob_ln);
    UINT8* ptr = NULL;
    blob = (BCRYPT_RSAKEY_BLOB*)blobBuffer;
    blob->Magic = wc_blob_pk->magic;
    blob->BitLength = wc_blob_pk->bitlen;
    blob->cbPublicExp = sizeof(wc_blob_pk->pubexp);
    blob->cbModulus = modulus_bytes;
    blob->cbPrime1 = 0; // not used for public key
    blob->cbPrime2 = 0; // not used for public key

    // Copy pubExp Big Endian 
    //
    // BCRYPT_RSAKEY_BLOB
    // ->PublicExponent[cbPublicExp] // Big-endian.
    // Modulus[cbModulus] // Big-endian.
    ptr = (PUINT8)(blob + 1);
    ReverseMemCopy(ptr, (PUINT8)&wc_blob_pk->pubexp, blob->cbPublicExp);
    DPrint(" exp: 0x%08x 0x%08x\n", (ULONG)*(ULONG*)ptr, wc_blob_pk->pubexp);

    // Copy Modulus Big Endian 
    //
    // BCRYPT_RSAKEY_BLOB
    // PublicExponent[cbPublicExp] // Big-endian.
    // ->Modulus[cbModulus] // Big-endian.
    
    ptr += blob->cbPublicExp;
    ReverseMemCopy(ptr, (PUINT8)(wc_blob_pk+1), blob->cbModulus);
#ifdef DEBUG_PRINT
    printf(" mod: 0x%08x 0x%08x\n", (ULONG)*(ULONG*)ptr, (ULONG)*(ULONG*)(wc_blob_pk+1));
    
    printf("bc blob raw bytes (0x%x):\n", blob_ln);
    DPrintMemCol8(blob, blob_ln, 0);
    printBcPubBlob(blob, blob_ln);
#endif
    
    *bc_blob = blob;
    *bc_blob_ln = blob_ln;

clean:
    if ( status != 0 )
    {
        if ( blobBuffer )
            free(blobBuffer);
    }

    return status;
}

/**
 * Allocates wc_blob, has to be freed by caller.
 */
NTSTATUS RSA_priv_derBlobToWcBlob(
    _In_ PVOID key_file_bytes, 
    _In_ ULONG key_file_bytes_ln,
    _Out_ PUBLICKEYSTRUC** wc_blob,
    _Out_ PULONG wc_blob_ln
)
{
    NTSTATUS status = STATUS_SUCCESS;
    BOOL b;

    UCHAR* key_bytes = NULL;
    ULONG key_bytes_ln = 0;
        
    *wc_blob = NULL;
    *wc_blob_ln = 0;

    // Decode from DER format to wincrypt blob
    b = CryptDecodeObjectEx(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
        PKCS_RSA_PRIVATE_KEY, 
        key_file_bytes, 
        key_file_bytes_ln, 
        CRYPT_ENCODE_ALLOC_FLAG, 
        NULL, 
        &key_bytes, 
        &key_bytes_ln
    );
    if ( !b )
    {
        status = GetLastError();
        //status = STATUS_UNSUCCESSFUL;
        //EPrint("CryptDecodeObjectEx failed 1! (0x%x)\n", status);
        goto clean;
    }
#ifdef DEBUG_PRINT
    printf("key bytes (0x%x):\n", key_bytes_ln);
    DPrintMemCol8(key_bytes, key_bytes_ln, 0);
#endif
    
    RSAPUBKEY* wc_blob_pk = (RSAPUBKEY*)(key_bytes + sizeof(BLOBHEADER));
    DPrint("wc_blob_pk: %p\n", wc_blob_pk);
    DPrint("wc_blob_pk->magic: 0x%x\n", wc_blob_pk->magic);
    if ( wc_blob_pk->magic != BCRYPT_RSAPRIVATE_MAGIC )
    {
        status = STATUS_UNSUCCESSFUL;
        //EPrint("Not a RSA private key! (0x%x)\n", status);
        goto clean;
    }

    *wc_blob = (BLOBHEADER*)(&key_bytes[0]);
    *wc_blob_ln = key_bytes_ln - 0;


clean:
    if ( status != 0 )
    {
        if ( key_bytes != NULL )
            LocalFree(key_bytes);
    }

    return status;
}

/**
 * Allocates blob, has to be freed by caller.
 */
NTSTATUS RSA_priv_wcBlobToBcBlob(
    _In_ RSAPUBKEY* wc_blob_pk,
    _Out_ BCRYPT_RSAKEY_BLOB** bc_blob,
    _Out_ PULONG bc_blob_ln
)
{
    NTSTATUS status = STATUS_SUCCESS;
    
    PUINT8 blobBuffer = NULL;

    *bc_blob = NULL;
    *bc_blob_ln = 0;
    
    if ( wc_blob_pk->magic != BCRYPT_RSAPRIVATE_MAGIC )
    {
        status = STATUS_UNSUCCESSFUL;
        printf("Not an RSA private key. (0x%x)\n", status);
        goto clean;
    }

    // Fill header
    // An RSA private key BLOB (BCRYPT_RSAPRIVATE_BLOB) has the following format in contiguous memory. All of the numbers following the structure are in big-endian format.
    //
    // BCRYPT_RSAKEY_BLOB
    // PublicExponent[cbPublicExp] // Big-endian.
    // Modulus[cbModulus] // Big-endian.
    // Prime1[cbPrime1] // Big-endian.
    // Prime2[cbPrime2] // Big-endian.
    //
    // modulus = p1 * p2
    // 
    // ->BCRYPT_RSAKEY_BLOB: Magic, BitLength, cbPublicExp, cbModulus, cbPrime1, cbPrime2
    // PublicExponent[cbPublicExp] // Big-endian.
    // Modulus[cbModulus] // Big-endian.
    // Prime1[cbPrime1] // Big-endian.
    // Prime2[cbPrime2] // Big-endian.
    // [ Exponent1[cbPrime1] // Big-endian.
    // Exponent2[cbPrime2] // Big-endian.
    // Coefficient[cbPrime1] // Big-endian.
    // PrivateExponent[cbModulus] // Big-endian. ] Full Key
    // wc blob contains full key , maybe it increases performance to import a full key ??
    
    ULONG modulus_bytes = wc_blob_pk->bitlen >> 3;
    ULONG prime_bytes = modulus_bytes >> 1;
    ULONG blob_ln = (ULONG)sizeof(BCRYPT_RSAKEY_BLOB) + (ULONG)sizeof(wc_blob_pk->pubexp) + (modulus_bytes << 1); // modulus_bytes + 2*prime_bytes == 2 * modulus_bytes
    blobBuffer = (PUINT8)malloc(blob_ln);
    if ( blobBuffer == NULL )
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        //EPrint("LocalAlloc failed! (0x%x)\n", status);
        goto clean;
    }
    RtlZeroMemory(blobBuffer, blob_ln);
    UINT8* bcb_ptr = NULL;
    UINT8* wcb_ptr = NULL;
    BCRYPT_RSAKEY_BLOB* blob = (BCRYPT_RSAKEY_BLOB*)blobBuffer;
    blob->Magic = wc_blob_pk->magic;
    blob->BitLength = wc_blob_pk->bitlen;
    blob->cbPublicExp = sizeof(wc_blob_pk->pubexp);
    blob->cbModulus = modulus_bytes;
    blob->cbPrime1 = prime_bytes;
    blob->cbPrime2 = prime_bytes;

    
    //
    // Copy pubExp Big Endian 
    //
    // ->PublicExponent[cbPublicExp] // Big-endian.
    // Modulus[cbModulus] // Big-endian.
    // Prime1[cbPrime1] // Big-endian.
    // Prime2[cbPrime2] // Big-endian.
    bcb_ptr = (PUINT8)(blob + 1);
    ReverseMemCopy(bcb_ptr, (PUINT8)&wc_blob_pk->pubexp, blob->cbPublicExp);
    DPrint(" exp: 0x%08x 0x%08x\n", (ULONG)*(ULONG*)bcb_ptr, wc_blob_pk->pubexp);

    // Copy Modulus Big Endian 
    //
    // ->Modulus[cbModulus] // Big-endian.
    // Prime1[cbPrime1] // Big-endian.
    // Prime2[cbPrime2] // Big-endian.
    
    bcb_ptr += blob->cbPublicExp;
    wcb_ptr = (PUINT8)(wc_blob_pk+1);
    ReverseMemCopy(bcb_ptr, wcb_ptr, blob->cbModulus);
    
    // Copy prime1 
    // 
    // ->Prime1[cbPrime1] // Big-endian.
    // Prime2[cbPrime2] // Big-endian.
    bcb_ptr += blob->cbModulus;
    wcb_ptr += blob->cbModulus;
    ReverseMemCopy(bcb_ptr, wcb_ptr, blob->cbPrime1);
    
    // Copy prime2
    // 
    // ->Prime2[cbPrime2] // Big-endian.
    bcb_ptr += blob->cbPrime1;
    wcb_ptr += blob->cbPrime1;
    ReverseMemCopy(bcb_ptr, wcb_ptr, blob->cbPrime2);
    
    //bcb_ptr += blob->cbPrime2;

    
#ifdef DEBUG_PRINT
    printf("blob raw bytes (0x%x):\n", blob_ln);
    DPrintMemCol8(blobBuffer, blob_ln, 0);

    printBcPrivBlob(blob, blob_ln);
#endif
    
    *bc_blob = blob;
    *bc_blob_ln = blob_ln;

clean:
    if ( status != 0 )
    {
        if ( blobBuffer )
            free(blobBuffer);
    }

    return status;
}
#endif

#ifdef RING3
NTSTATUS RSA_importPubKeyFromFile(
    _Inout_ PRSA_CTXT ctxt,
    _In_ const CHAR* path, 
    _In_ KEY_TYPE type
)
{
    NTSTATUS status = STATUS_SUCCESS;

    UCHAR* key_file_bytes = NULL;
    ULONG key_file_bytes_ln = 0;
    PUBLICKEYSTRUC* wc_blob = NULL;
    ULONG wc_blob_ln = 0;
    BCRYPT_RSAKEY_BLOB* blob = NULL;
    ULONG blob_ln = 0;

    if ( type == KEY_TYPE_NONE )
    {
        status = STATUS_INVALID_PARAMETER;
        //EPrint("Unknown key type! (0x%x)\n", status);
        return status;
    }

    status = loadFileBytes(path, &key_file_bytes, &key_file_bytes_ln);
    if ( status != 0 )
    {
        goto clean;
    }

#ifdef DEBUG_PRINT
    printf("file bytes (0x%x):\n", (key_file_bytes_ln));
    DPrintMemCol8(key_file_bytes, key_file_bytes_ln, 0);
#endif

//    if ( type == KEY_TYPE_PUB || type == KEY_TYPE_PEM )
//    {
//        status = RSA_pub_pemBlobToWcBlob(key_file_bytes, key_file_bytes_ln, &wc_blob, &wc_blob_ln);
//    }
//    else 
    if ( type == KEY_TYPE_DER )
    {
        status = RSA_pub_derBlobToWcBlob(key_file_bytes, key_file_bytes_ln, &wc_blob, &wc_blob_ln);
        if ( status != 0 )
        {
            //EPrint("RSA_pub_derBlobToWcBlob failed! (0x%x)\n", status);
            goto clean;
        }
#ifdef DEBUG_PRINT
        printf("wc blob bytes:\n");
        DPrintMemCol8(wc_blob, wc_blob_ln, 0);
        printWcPubBlob(wc_blob, wc_blob_ln);
#endif
        RSAPUBKEY* wc_blob_pk = NULL;
        wc_blob_pk = (RSAPUBKEY*)(wc_blob + 1); // right after the struct

        status = RSA_pub_wcBlobToBcBlob(wc_blob_pk, &blob, &blob_ln);
        if ( status != 0 )
        {
            //EPrint("RSA_pub_wcBlobToBcBlob failed! (0x%x)\n", status);
            goto clean;
        }
    }
    else if ( type == KEY_TYPE_BCBLOB )
    {
        DPrint("Importing BC blob bytes\n");
        // data is already the required bcrypt blob, just import
#ifdef DEBUG_PRINT
        DPrintMemCol8(key_file_bytes, key_file_bytes_ln, 0);
#endif
        blob = (BCRYPT_RSAKEY_BLOB*)key_file_bytes;
        blob_ln = key_file_bytes_ln;
        
        if ( blob->Magic != BCRYPT_RSAPUBLIC_MAGIC )
        {
            status = STATUS_UNSUCCESSFUL;
            //EPrint("Not an RSA public key. (0x%x)\n", status);
            goto clean;
        }

#ifdef DEBUG_PRINT
        printBcPubBlob(blob, blob_ln);
#endif
    }
    else
    {
        status = STATUS_UNSUCCESSFUL;
        //EPrint("Unknown key type! (0x%x)\n", status);
        goto clean;
    }

    status = BCryptImportKeyPair(
        ctxt->alg,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        &ctxt->pub_key,
        (PUCHAR)blob,
        blob_ln,
        0
    );
    if ( status != 0 )
    {
        //EPrint("BCryptImportKeyPair failed! (0x%x)\n", status);
        goto clean;
    }
    DPrint("key: %p\n", ctxt->pub_key);

clean:
    if ( wc_blob != NULL )
        LocalFree(wc_blob);
    if ( blob != NULL && (PVOID)blob != (PVOID)key_file_bytes )
        free(blob);
    if ( key_file_bytes )
        free(key_file_bytes);

    return status;
}
#else
NTSTATUS RSA_importPubKeyFromFile(
    _Inout_ PRSA_CTXT ctxt,
    _In_ const CHAR* path, 
    _In_ KEY_TYPE type
)
{
    NTSTATUS status = STATUS_SUCCESS;

    UCHAR* key_file_bytes = NULL;
    ULONG key_file_bytes_ln = 0;
    BCRYPT_RSAKEY_BLOB* blob = NULL;
    ULONG blob_ln = 0;

    if ( type != KEY_TYPE_BCBLOB )
    {
        status = STATUS_INVALID_PARAMETER;
        //EPrint("Unsupported key type! (0x%x)\n", status);
        return status;
    }

    status = loadFileBytes(path, &key_file_bytes, &key_file_bytes_ln);
    if ( status != 0 )
    {
        goto clean;
    }

    blob = (BCRYPT_RSAKEY_BLOB*)key_file_bytes;
    blob_ln = key_file_bytes_ln;
        
    if ( blob->Magic != BCRYPT_RSAPUBLIC_MAGIC )
    {
        status = STATUS_UNSUCCESSFUL;
        //EPrint("Not an RSA public key. (0x%x)\n", status);
        goto clean;
    }

    status = BCryptImportKeyPair(
        ctxt->alg,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        &ctxt->pub_key,
        (PUCHAR)blob,
        blob_ln,
        0
    );
    if ( status != 0 )
    {
        //EPrint("BCryptImportKeyPair failed! (0x%x)\n", status);
        goto clean;
    }

clean:
    if ( key_file_bytes )
        ExFreePool(key_file_bytes);

    return status;
}
#endif

#ifdef RING3
NTSTATUS RSA_exportPubKeyToDER(
    _In_ BCRYPT_KEY_HANDLE pubKey,
    _In_ const CHAR* path
)
{
    NTSTATUS status = STATUS_SUCCESS;
    BOOL b;

    PUINT8 buffer = NULL;
    PUINT8 wc_buffer = NULL;
    PUINT8 ptr = NULL;
    ULONG blob_ln = 0;
    ULONG blob_ln_res = 0;
    BCRYPT_RSAKEY_BLOB* blob = NULL;
    ULONG wc_blob_ln;
    RSAPUBKEY* wc_blob_pubk = NULL;
    
    UCHAR *der_buffer= NULL;
    ULONG der_buffer_ln = 0;

    CERT_PUBLIC_KEY_INFO *publicKeyInfo = NULL;
    ULONG publicKeyInfoLen = 0;
    CERT_PUBLIC_KEY_INFO *publicKeyInfo_t = NULL;

    status = BCryptExportKey(
        pubKey,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        NULL,
        0,
        &blob_ln_res,
        0
    );
    if ( status != 0 || blob_ln_res == 0 )
    {
        //EPrint("BCryptExportKey failed! (0x%x)\n", status);
        goto clean;
    }
    
    blob_ln = blob_ln_res;
    buffer = (PUINT8)malloc(blob_ln);
    if ( buffer == NULL )
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        //EPrint("LocalAlloc failed! (0x%x)\n", status);
        goto clean;
    }
    RtlZeroMemory(buffer, blob_ln);
    blob = (BCRYPT_RSAKEY_BLOB*)buffer;
    DPrint("blob_ln: 0x%x\n", blob_ln);
    
    status = BCryptExportKey(
        pubKey,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        buffer,
        blob_ln,
        &blob_ln_res,
        0
    );
    if ( status != 0 || blob_ln_res == 0 )
    {
        //EPrint("BCryptExportKey failed! (0x%x)\n", status);
        goto clean;
    }
    
#ifdef DEBUG_PRINT
    printf("bc blob raw bytes (0x%x):\n", blob_ln);
    DPrintMemCol8(blob, blob_ln, 0);
    printBcPubBlob(blob, blob_ln);
#endif

    //typedef struct _PUBLICKEYSTRUC {
    //  UINT8   bType;
    //  UINT8   bVersion;
    //  WORD   reserved;
    //  ALG_ID aiKeyAlg;
    //} BLOBHEADER, PUBLICKEYSTRUC;
    // blob {
    //  ULONG magic
    //  ULONG bitln
    //  ULONG exp (little end)
    //  ULONG modulus (little end)
    //}
    wc_blob_ln = sizeof(PUBLICKEYSTRUC) + 3 * sizeof(ULONG) + blob->cbModulus;
    wc_buffer = (PUINT8)malloc(wc_blob_ln);
    if ( wc_buffer == NULL )
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        //EPrint("LocalAlloc failed! (0x%x)\n", status);
        goto clean;
    }
    RtlZeroMemory(wc_buffer, wc_blob_ln);
    BLOBHEADER* wc_bh = (BLOBHEADER*)wc_buffer;
    wc_bh->bType = PUBLICKEYBLOB;
    wc_bh->bVersion = CUR_BLOB_VERSION;
    wc_bh->reserved = 0;
    wc_bh->aiKeyAlg = CALG_RSA_KEYX;
    
    wc_blob_pubk = (RSAPUBKEY*)(wc_bh + 1);
    wc_blob_pubk->magic = blob->Magic;
    wc_blob_pubk->bitlen = blob->BitLength;
    ReverseMemCopy((UINT8*)&wc_blob_pubk->pubexp, &buffer[24], blob->cbPublicExp);
    ptr = (PUINT8)wc_blob_pubk;
    //(ULONG)*(ULONG*)&ptr[0] = blob->Magic;
    //(ULONG)*(ULONG*)&ptr[4] = blob->BitLength;
    //ReverseMemCopy(&ptr[8], &buffer[24], blob->cbPublicExp);
    ReverseMemCopy(&ptr[12], &buffer[24+blob->cbPublicExp], blob->cbModulus);
    
#ifdef DEBUG_PRINT
    printf("wc blob raw bytes (0x%x):\n", wc_blob_ln);
    DPrintMemCol8(wc_buffer, wc_blob_ln, 0);

    printf("convert to pubkey info\n");
#endif
    // Decode the wc blob to a intermediate CERT_PUBLIC_KEY_INFO format
    b = CryptEncodeObjectEx(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
        RSA_CSP_PUBLICKEYBLOB, // szOID_RSA_RSA
        wc_bh, 
        CRYPT_ENCODE_ALLOC_FLAG, 
        NULL, 
        &publicKeyInfo, 
        &publicKeyInfoLen
    );
    if ( !b )
    {
        status = GetLastError();
        //EPrint("CryptEncodeObjectEx failed 1! (0x%x)\n", status);
        status = STATUS_UNSUCCESSFUL;
        goto clean;
    }
#ifdef DEBUG_PRINT
    printf("publicKeyInfo bytes (0x%x):\n", publicKeyInfoLen);
    DPrintMemCol8((PUINT8)publicKeyInfo, publicKeyInfoLen, 0);
#endif
    publicKeyInfo_t = (CERT_PUBLIC_KEY_INFO*)malloc(publicKeyInfoLen+0x50);
    if ( !publicKeyInfo_t )
    {
        printf("malloc failed\n");
        goto clean;
    }
    RtlZeroMemory(publicKeyInfo_t, publicKeyInfoLen+0x50);
    ULONG api_blob_data = 0x0005;
    ULONG api_cb_blob_data = 2;
    ULONG pub_key_cbData = publicKeyInfoLen;
    publicKeyInfo_t->Algorithm.pszObjId = (LPSTR)&((PUINT8)publicKeyInfo_t)[0x30];
    publicKeyInfo_t->Algorithm.Parameters.cbData = api_cb_blob_data;
    publicKeyInfo_t->Algorithm.Parameters.pbData = &((PUINT8)publicKeyInfo_t)[0x48];
    publicKeyInfo_t->PublicKey.cbData = pub_key_cbData;
    publicKeyInfo_t->PublicKey.pbData = &((PUINT8)publicKeyInfo_t)[0x50];
    publicKeyInfo_t->PublicKey.cUnusedBits = 0;
    memcpy(&((PUINT8)publicKeyInfo_t)[0x30], szOID_RSA_RSA, strlen(szOID_RSA_RSA));
    memcpy(&((PUINT8)publicKeyInfo_t)[0x48], &api_blob_data, sizeof(api_blob_data));
    memcpy(&((PUINT8)publicKeyInfo_t)[0x50], publicKeyInfo, publicKeyInfoLen);
    publicKeyInfoLen += 0x50;

#ifdef DEBUG_PRINT
    printf("publicKeyInfo_t : %p\n", publicKeyInfo_t);
    printf("publicKeyInfo bytes (0x%x):\n", publicKeyInfoLen);
    DPrintMemCol8(publicKeyInfo_t, publicKeyInfoLen, 0);
    printf(" Algorithm\n");
    printf("  pszObjId: %s (%p)\n", publicKeyInfo_t->Algorithm.pszObjId, publicKeyInfo_t->Algorithm.pszObjId);
    printf("  Parameters (0x%x) (%p)\n    ", publicKeyInfo_t->Algorithm.Parameters.cbData, publicKeyInfo_t->Algorithm.Parameters.pbData);
    for ( ULONG i = 0; i < publicKeyInfo_t->Algorithm.Parameters.cbData; i++ )
        printf("%02x ", publicKeyInfo_t->Algorithm.Parameters.pbData[i]);
    printf("\n");
    printf(" PublicKey (0x%x) (%p)\n  ", publicKeyInfo_t->PublicKey.cbData, publicKeyInfo_t->PublicKey.pbData);
    for ( ULONG i = 0; i < publicKeyInfo_t->PublicKey.cbData; i++ )
        printf("%02x ", publicKeyInfo_t->PublicKey.pbData[i]);
    printf("\n");
    printf(" unused: 0x%x\n", publicKeyInfo_t->PublicKey.cUnusedBits);
#endif

    // Encode to DER format
    b = CryptEncodeObjectEx(
        X509_ASN_ENCODING, 
        X509_PUBLIC_KEY_INFO, 
        publicKeyInfo_t, 
        CRYPT_ENCODE_ALLOC_FLAG, 
        NULL, 
        &der_buffer, 
        &der_buffer_ln
    );
    if ( !b )
    {
        status = GetLastError();
        //EPrint("CryptEncodeObjectEx failed 3! (0x%x)\n", status);
        status = STATUS_UNSUCCESSFUL;
        goto clean;
    }
    
#ifdef DEBUG_PRINT
    printf("DER bytes (0x%x):\n", der_buffer_ln);
    DPrintMemCol8(der_buffer, der_buffer_ln, 0);
#endif

    status = writeFileBytes(path, der_buffer, der_buffer_ln);
    if ( status != 0 )
    {
        //EPrint("writeFileBytes failed! (0x%x)\n", status);
        goto clean;
    }

clean:
    if ( buffer != NULL )
        free(buffer);
    if ( wc_buffer != NULL )
        free(wc_buffer);
    if ( publicKeyInfo != NULL )
        LocalFree(publicKeyInfo);
    if ( publicKeyInfo_t != NULL )
        free(publicKeyInfo_t);

    return status;
}
#endif

NTSTATUS RSA_exportPubKeyToBLOB(
    _In_ BCRYPT_KEY_HANDLE pubKey,
    _In_ const CHAR* path
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PUINT8 buffer = NULL;
    ULONG blob_ln = 0;
    ULONG blob_ln_res = 0;
    BCRYPT_RSAKEY_BLOB* blob = NULL;
    
    status = BCryptExportKey(
        pubKey,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        NULL,
        0,
        &blob_ln_res,
        0
    );
    if ( status != 0 || blob_ln_res == 0 )
    {
        //EPrint("BCryptExportKey failed! (0x%x)\n", status);
        goto clean;
    }
    
    blob_ln = blob_ln_res;
    buffer = (PUINT8)ExAllocatePoolWithTag(ALLOC_POOL_TYPE, blob_ln, 'ffub');
    if ( buffer == NULL )
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        //EPrint("LocalAlloc failed! (0x%x)\n", status);
        goto clean;
    }
    RtlZeroMemory(buffer, blob_ln);
    blob = (BCRYPT_RSAKEY_BLOB*)buffer;
    DPrint("blob_ln: 0x%x\n", blob_ln);
    
    status = BCryptExportKey(
        pubKey,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        buffer,
        blob_ln,
        &blob_ln_res,
        0
    );
    if ( status != 0 || blob_ln_res == 0 )
    {
        //EPrint("BCryptExportKey failed! (0x%x)\n", status);
        goto clean;
    }
    
#ifdef DEBUG_PRINT
    printf("bc blob raw bytes (0x%x):\n", blob_ln);
    DPrintMemCol8(blob, blob_ln, 0);
    printBcPubBlob(blob, blob_ln);
#endif

    status = writeFileBytes(path, (UCHAR*)blob, blob_ln);
    if ( status != 0 )
    {
        //EPrint("writeFileBytes failed! (0x%x)\n", status);
        goto clean;
    }

clean:
    if ( buffer != NULL )
        ExFreePool(buffer);

    return status;
}

#ifdef RING3
NTSTATUS RSA_importPrivKeyFromFile(
    _Inout_ PRSA_CTXT ctxt,
    _In_ const CHAR* path, 
    _In_ KEY_TYPE type
)
{
    NTSTATUS status = STATUS_SUCCESS;
    BOOL b;

    UCHAR* key_file_bytes = NULL;
    ULONG key_file_bytes_ln = 0;
    UCHAR* key_bytes = NULL;
    ULONG key_bytes_ln = 0;

    BLOBHEADER* wc_blob = NULL;
    RSAPUBKEY* wc_blob_pk = NULL;
    ULONG wc_blob_ln = 0;
    
    PUINT8 blobBuffer = NULL;
    ULONG blob_ln = 0;
    BCRYPT_RSAKEY_BLOB* blob;

    if ( type == KEY_TYPE_NONE )
    {
        status = STATUS_INVALID_PARAMETER;
        //EPrint("Unknown key type! (0x%x)\n", status);
        return status;
    }

    status = loadFileBytes(path, &key_file_bytes, &key_file_bytes_ln);
    if ( status != 0 )
    {
        goto clean;
    }
#ifdef DEBUG_PRINT
    printf("file bytes (0x%x):\n", (key_file_bytes_ln));
    DPrintMemCol8(key_file_bytes, key_file_bytes_ln, 0);
#endif

//    if ( type == KEY_TYPE_PUB || type == KEY_TYPE_PEM )
//    {
//        status = RSA_priv_pemBlobToWcBlob(key_file_bytes, key_file_bytes_ln, &wc_blob, &wc_blob_ln);
//    }
//    else 
    if ( type == KEY_TYPE_DER )
    {
        // der = big endian
        // wc.blob = little endian
        DPrint("Converting der\n");

        RSA_priv_derBlobToWcBlob(key_file_bytes, key_file_bytes_ln, &wc_blob, &wc_blob_ln);
        if ( status != 0 )
        {
            //EPrint("RSA_priv_derBlobToWcBlob failed! (0x%x)\n", status);
            goto clean;
        }
        wc_blob_pk = (RSAPUBKEY*)(wc_blob + 1);

        status = RSA_priv_wcBlobToBcBlob(wc_blob_pk, &blob, &blob_ln);
        if ( status != 0 )
        {
            //EPrint("RSA_priv_wcBlobToBcBlob failed! (0x%x)\n", status);
            goto clean;
        }
    }
    else if ( type == KEY_TYPE_BCBLOB )
    {
        blob = (BCRYPT_RSAKEY_BLOB*)key_file_bytes;
        blob_ln = key_file_bytes_ln;
        
        if ( blob->Magic != BCRYPT_RSAPRIVATE_MAGIC )
        {
            status = STATUS_UNSUCCESSFUL;
            //EPrint("Not an RSA public key. (0x%x)\n", status);
            goto clean;
        }
    }
    else
    {
        status = STATUS_UNSUCCESSFUL;
        //EPrint("Unknown key type! (0x%x)\n", status);
        goto clean;
    }

    status = BCryptImportKeyPair(
        ctxt->alg,
        NULL,
        BCRYPT_RSAPRIVATE_BLOB,
        &ctxt->priv_key,
        (PUCHAR)blob,
        blob_ln,
        0
    );
    if ( status != 0 )
    {
        //EPrint("BCryptImportKeyPair failed! (0x%x)\n", status);
        goto clean;
    }
    DPrint("key: %p\n", ctxt->priv_key);

clean:
    if ( key_bytes != NULL && key_bytes != key_file_bytes )
    {
        ZeroLocalFree(key_bytes, key_bytes_ln);
    }
    if ( blobBuffer != NULL )
    {
        ZeroFree(blobBuffer, blob_ln);
    }
    if ( key_file_bytes )
    {
        ZeroFree(key_file_bytes, key_file_bytes_ln);
    }

    return status;
}
#else
NTSTATUS RSA_importPrivKeyFromFile(
    _Inout_ PRSA_CTXT ctxt,
    _In_ const CHAR* path, 
    _In_ KEY_TYPE type
)
{
    NTSTATUS status = STATUS_SUCCESS;

    UCHAR* key_file_bytes = NULL;
    ULONG key_file_bytes_ln = 0;
    BCRYPT_RSAKEY_BLOB* blob = NULL;
    ULONG blob_ln = 0;

    if ( type != KEY_TYPE_BCBLOB )
    {
        status = STATUS_INVALID_PARAMETER;
        //EPrint("Unsupported key type! (0x%x)\n", status);
        return status;
    }

    status = loadFileBytes(path, &key_file_bytes, &key_file_bytes_ln);
    if ( status != 0 )
    {
        goto clean;
    }

    blob = (BCRYPT_RSAKEY_BLOB*)key_file_bytes;
    blob_ln = key_file_bytes_ln;
        
    if ( blob->Magic != BCRYPT_RSAPRIVATE_MAGIC )
    {
        status = STATUS_UNSUCCESSFUL;
        //EPrint("Not an RSA private key. (0x%x)\n", status);
        goto clean;
    }

    status = BCryptImportKeyPair(
        ctxt->alg,
        NULL,
        BCRYPT_RSAPRIVATE_BLOB,
        &ctxt->priv_key,
        (PUCHAR)blob,
        blob_ln,
        0
    );
    if ( status != 0 )
    {
        //EPrint("BCryptImportKeyPair failed! (0x%x)\n", status);
        goto clean;
    }

clean:
    if ( key_file_bytes )
        ExFreePool(key_file_bytes);

    return status;
}
#endif

#ifdef RING3
NTSTATUS RSA_exportPrivKeyToDER(
    _In_ BCRYPT_KEY_HANDLE privKey,
    _In_ const CHAR* path
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PUINT8 buffer = NULL;
    PUINT8 wc_buffer = NULL;
    ULONG blob_ln = 0;
    ULONG blob_ln_res = 0;
    BCRYPT_RSAKEY_BLOB* blob = NULL;
    ULONG wc_blob_ln = 0;
    //RSAPUBKEY* wc_blob_pubk = NULL;
    
    //UCHAR *der_buffer= NULL;
    //ULONG der_buffer_ln;

    //CERT_PUBLIC_KEY_INFO *publicKeyInfo = NULL;
    //ULONG publicKeyInfoLen;
    //CERT_PUBLIC_KEY_INFO *publicKeyInfo_t = NULL;

    status = BCryptExportKey(
        privKey,
        NULL,
        BCRYPT_RSAPRIVATE_BLOB,
        NULL,
        0,
        &blob_ln_res,
        0
    );
    if ( status != 0 || blob_ln_res == 0 )
    {
        //EPrint("BCryptExportKey failed! (0x%x)\n", status);
        goto clean;
    }
    
    blob_ln = blob_ln_res;
    buffer = (PUINT8)malloc(blob_ln);
    if ( buffer == NULL )
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        //EPrint("LocalAlloc failed! (0x%x)\n", status);
        goto clean;
    }
    RtlZeroMemory(buffer, blob_ln);
    blob = (BCRYPT_RSAKEY_BLOB*)buffer;
    DPrint("blob_ln: 0x%x\n", blob_ln);
    
    status = BCryptExportKey(
        privKey,
        NULL,
        BCRYPT_RSAPRIVATE_BLOB,
        buffer,
        blob_ln,
        &blob_ln_res,
        0
    );
    if ( status != 0 || blob_ln_res == 0 )
    {
        //EPrint("BCryptExportKey failed! (0x%x)\n", status);
        goto clean;
    }
    
#ifdef DEBUG_PRINT
    printf("bc blob raw bytes (0x%x):\n", blob_ln);
    DPrintMemCol8(buffer, blob_ln, 0);

    printBcPrivBlob(blob, blob_ln);
#endif
//
//    //typedef struct _PUBLICKEYSTRUC {
//    //  UINT8   bType;
//    //  UINT8   bVersion;
//    //  WORD   reserved;
//    //  ALG_ID aiKeyAlg;
//    //} BLOBHEADER, PUBLICKEYSTRUC;
//    // blob {
//    //  ULONG magic
//    //  ULONG bitln
//    //  ULONG exp (little end)
//    //  ULONG modulus (little end)
//    //}
//    wc_blob_ln = sizeof(PUBLICKEYSTRUC) + 3 * sizeof(ULONG) + blob->cbModulus;
//    wc_buffer = (PUINT8)malloc(wc_blob_ln);
//    RtlZeroMemory(wc_buffer, wc_blob_ln);
//    BLOBHEADER* wc_bh = (BLOBHEADER*)wc_buffer;
//    wc_bh->bType = PUBLICKEYBLOB;
//    wc_bh->bVersion = CUR_BLOB_VERSION;
//    wc_bh->reserved = 0;
//    wc_bh->aiKeyAlg = CALG_RSA_KEYX;
//    
//    wc_blob_pubk = (RSAPUBKEY*)(wc_bh + 1);
//    wc_blob_pubk->magic = blob->Magic;
//    wc_blob_pubk->bitlen = blob->BitLength;
//    ReverseMemCopy((UINT8*)&wc_blob_pubk->pubexp, &buffer[24], blob->cbPublicExp);
//    ptr = (PUINT8)wc_blob_pubk;
//    //(ULONG)*(ULONG*)&ptr[0] = blob->Magic;
//    //(ULONG)*(ULONG*)&ptr[4] = blob->BitLength;
//    //ReverseMemCopy(&ptr[8], &buffer[24], blob->cbPublicExp);
//    ReverseMemCopy(&ptr[12], &buffer[24+blob->cbPublicExp], blob->cbModulus);
//    
//#ifdef DEBUG_PRINT
//    printf("wc blob raw bytes (0x%x):\n", wc_blob_ln);
//    DPrintMemCol8(wc_buffer, wc_blob_ln, 0);
//
//    printf("convert to pubkey info\n");
//#endif
//    // Decode the wc blob to a intermediate CERT_PUBLIC_KEY_INFO format
//   b = CryptEncodeObjectEx(
//            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
//            PKCS_RSA_PRIVATE_KEY, 
//            key_buffer, 
//            key_buffer_ln, 
//            CRYPT_ENCODE_ALLOC_FLAG, 
//            NULL, 
//            &key_bytes, 
//            &key_bytes_ln
//        );
//    if ( !b )
//    {
//#ifdef ERROR_PRINT
//        printf("CryptEncodeObjectEx 1.\n", GetLastError());
//#endif
//        status = STATUS_UNSUCCESSFUL;
//        goto clean;
//    }
//#ifdef DEBUG_PRINT
//    printf("publicKeyInfo bytes (0x%x):\n", publicKeyInfoLen);
//    DPrintMemCol8((PUINT8)publicKeyInfo, publicKeyInfoLen, 0);
//#endif


//    publicKeyInfo_t = (CERT_PUBLIC_KEY_INFO*)malloc(publicKeyInfoLen+0x50);
//    if ( !publicKeyInfo_t )
//    {
//        printf("malloc failed\n");
//        goto clean;
//    }
//    RtlZeroMemory(publicKeyInfo_t, publicKeyInfoLen+0x50);
//    ULONG api_blob_data = 0x0005;
//    ULONG api_cb_blob_data = 2;
//    ULONG pub_key_cbData = publicKeyInfoLen;
//    publicKeyInfo_t->Algorithm.pszObjId = (LPSTR)&((PUINT8)publicKeyInfo_t)[0x30];
//    publicKeyInfo_t->Algorithm.Parameters.cbData = api_cb_blob_data;
//    publicKeyInfo_t->Algorithm.Parameters.pbData = &((PUINT8)publicKeyInfo_t)[0x48];
//    publicKeyInfo_t->PublicKey.cbData = pub_key_cbData;
//    publicKeyInfo_t->PublicKey.pbData = &((PUINT8)publicKeyInfo_t)[0x50];
//    publicKeyInfo_t->PublicKey.cUnusedBits = 0;
//    memcpy(&((PUINT8)publicKeyInfo_t)[0x30], szOID_RSA_RSA, strlen(szOID_RSA_RSA));
//    memcpy(&((PUINT8)publicKeyInfo_t)[0x48], &api_blob_data, sizeof(api_blob_data));
//    memcpy(&((PUINT8)publicKeyInfo_t)[0x50], publicKeyInfo, publicKeyInfoLen);
//    publicKeyInfoLen += 0x50;
//
//#ifdef ERROR_PRINT
//    printf("publicKeyInfo_t : %p\n", publicKeyInfo_t);
//    printf("publicKeyInfo bytes (0x%x):\n", publicKeyInfoLen);
//    DPrintMemCol8(publicKeyInfo_t, publicKeyInfoLen, 0x10, 1);
//    printf(" Algorithm\n");
//    printf("  pszObjId: %s (%p)\n", publicKeyInfo_t->Algorithm.pszObjId, publicKeyInfo_t->Algorithm.pszObjId);
//    printf("  Parameters (0x%x) (%p)\n    ", publicKeyInfo_t->Algorithm.Parameters.cbData, publicKeyInfo_t->Algorithm.Parameters.pbData);
//    for ( ULONG i = 0; i < publicKeyInfo_t->Algorithm.Parameters.cbData; i++ )
//        printf("%02x ", publicKeyInfo_t->Algorithm.Parameters.pbData[i]);
//    printf("\n");
//    printf(" PublicKey (0x%x) (%p)\n  ", publicKeyInfo_t->PublicKey.cbData, publicKeyInfo_t->PublicKey.pbData);
//    for ( ULONG i = 0; i < publicKeyInfo_t->PublicKey.cbData; i++ )
//        printf("%02x ", publicKeyInfo_t->PublicKey.pbData[i]);
//    printf("\n");
//    printf(" unused: 0x%x\n", publicKeyInfo_t->PublicKey.cUnusedBits);
//#endif
//
//    // Encode to DER format
//    b = CryptEncodeObjectEx(
//        X509_ASN_ENCODING, 
//        X509_PUBLIC_KEY_INFO, 
//        publicKeyInfo_t, 
//        CRYPT_ENCODE_ALLOC_FLAG, 
//        NULL, 
//        &der_buffer, 
//        &der_buffer_ln
//    );
//    if ( !b )
//    {
//#ifdef ERROR_PRINT
//        printf("CryptEncodeObjectEx 3.\n", GetLastError());
//#endif
//        status = STATUS_UNSUCCESSFUL;
//        goto clean;
//    }
//    
//#ifdef DEBUG_PRINT
//    printf("DER bytes (0x%x):\n", der_buffer_ln);
//    DPrintMemCol8(der_buffer, der_buffer_ln, 0);
//#endif

    (path);
    //status = writeFileBytes(path, der_buffer, der_buffer_ln);
    //if ( status != 0 )
    //{
    //    //status = STATUS_UNSUCCESSFUL;
    //    goto clean;
    //}

clean:
    if ( buffer != NULL )
    {
        ZeroFree(buffer, blob_ln);
    }
    if ( wc_buffer != NULL )
    {
        ZeroFree(wc_buffer, wc_blob_ln);
    }

    return status;
}
#endif

NTSTATUS RSA_exportPrivKeyToBLOB(
    _In_ BCRYPT_KEY_HANDLE privKey,
    _In_ const CHAR* path
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PUINT8 buffer = NULL;
    ULONG blob_ln = 0;
    ULONG blob_ln_res = 0;
    BCRYPT_RSAKEY_BLOB* blob = NULL;
    
    status = BCryptExportKey(
        privKey,
        NULL,
        BCRYPT_RSAPRIVATE_BLOB,
        NULL,
        0,
        &blob_ln_res,
        0
    );
    if ( status != 0 || blob_ln_res == 0 )
    {
        //EPrint("BCryptExportKey failed! (0x%x)\n", status);
        goto clean;
    }
    
    blob_ln = blob_ln_res;
    buffer = (PUINT8)ExAllocatePoolWithTag(ALLOC_POOL_TYPE, blob_ln, 'ffub');
    if ( buffer == NULL )
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        //EPrint("LocalAlloc failed! (0x%x)\n", status);
        goto clean;
    }
    RtlZeroMemory(buffer, blob_ln);
    blob = (BCRYPT_RSAKEY_BLOB*)buffer;
    DPrint("blob_ln: 0x%x\n", blob_ln);
    
    status = BCryptExportKey(
        privKey,
        NULL,
        BCRYPT_RSAPRIVATE_BLOB,
        buffer,
        blob_ln,
        &blob_ln_res,
        0
    );
    if ( status != 0 || blob_ln_res == 0 )
    {
        //EPrint("BCryptExportKey failed! (0x%x)\n", status);
        goto clean;
    }
    
#ifdef DEBUG_PRINT
    DPrint("bc blob raw bytes (0x%x):\n", blob_ln);
    DPrintMemCol8(blob, blob_ln, 0);
    printBcPubBlob(blob, blob_ln);
#endif

    status = writeFileBytes(path, (UCHAR*)blob, blob_ln);
    if ( status != 0 )
    {
        //EPrint("writeFileBytes failed! (0x%x)\n", status);
        goto clean;
    }

clean:
    if ( buffer != NULL )
        ExFreePool(buffer);

    return status;
}

NTSTATUS RSA_encrypt(
    _In_ PRSA_CTXT ctxt,
    _In_ PUCHAR plain,
    _In_ ULONG plain_ln,
    _Inout_ PUCHAR* encrypted,
    _Inout_ PULONG encrypted_ln
)
{
    FEnter();
    ULONG required_size = 0;
    NTSTATUS status = STATUS_SUCCESS;

    DPrint("ctxt->padding: 0x%x\n", ctxt->padding);

    status = BCryptEncrypt(
        ctxt->pub_key,
        plain,
        plain_ln,
        ctxt->padding_info,
        NULL,
        0,
        NULL,
        0,
        &required_size,
        ctxt->padding
    );
    if ( status != 0 )
    {
        //EPrint("BCryptEncrypt get size! (0x%x)\n", status);
        goto clean;
    }
    DPrint("required_size: 0x%x\n", required_size);

    if ( *encrypted == NULL )
    {
        *encrypted = (PUCHAR)ExAllocatePoolWithTag(ALLOC_POOL_TYPE, required_size, 'rcne');
        if ( *encrypted == NULL )
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            //EPrint("Malloc out buffer failed! (0x%x)\n", status);
            goto clean;
        }
    }
    else
    {
        if ( required_size > *encrypted_ln )
        {
            status = STATUS_BUFFER_TOO_SMALL;
            //EPrint("Provided encryption buffer[0x%x] is too small! 0x%x needed! (0x%x)\n", *encrypted_ln, required_size, status);
            goto clean;
        }
    }
    *encrypted_ln = required_size;
    
    if ( plain != *encrypted )
        RtlZeroMemory(*encrypted, *encrypted_ln);
    
    status = BCryptEncrypt(
        ctxt->pub_key,
        plain,
        plain_ln,
        ctxt->padding_info,
        NULL,
        0,
        *encrypted,
        *encrypted_ln,
        encrypted_ln,
        ctxt->padding
    );
    if ( status != 0 )
    {
        //EPrint("BCryptEncrypt failed! (0x%x)\n", status);
        goto clean;
    }

clean:
    FLeave();
    return status;
}

NTSTATUS RSA_decrypt(
    _In_ PRSA_CTXT ctxt,
    _In_ PUCHAR encrypted,
    _In_ ULONG encrypted_ln,
    _Inout_ PUCHAR* plain,
    _Inout_ PULONG plain_ln
)
{
    FEnter();

    ULONG required_size = 0;
    NTSTATUS status = STATUS_SUCCESS;

    status = BCryptDecrypt(
        ctxt->priv_key,
        encrypted,
        encrypted_ln,
        ctxt->padding_info,
        NULL,
        0,
        NULL,
        0,
        &required_size,
        ctxt->padding
    );
    if ( status != 0 )
    {
        //EPrint("BCryptDecrypt get size! (0x%x)\n", status);
        goto clean;
    }
    DPrint("required_size: 0x%x\n", required_size);
    
    if ( *plain == NULL )
    {
        *plain = (PUCHAR)ExAllocatePoolWithTag(ALLOC_POOL_TYPE, required_size, 'nalp');
        if ( *plain == NULL )
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            //EPrint("Malloc out buffer failed! (0x%x)\n", status);
            goto clean;
        }
    }
    else
    {
        if ( required_size > *plain_ln )
        {
            status = STATUS_BUFFER_TOO_SMALL;
            //EPrint("Provided plain buffer[0x%x] is too small! 0x%x needed! (0x%x)\n", *plain_ln, required_size, status);
            goto clean;
        }
    }
    *plain_ln = required_size;

    if ( encrypted != *plain )
        RtlZeroMemory(*plain, *plain_ln);

    status = BCryptDecrypt(
        ctxt->priv_key,
        encrypted,
        encrypted_ln,
        ctxt->padding_info,
        NULL,
        0,
        *plain,
        *plain_ln,
        plain_ln,
        ctxt->padding
    );
    if ( status != 0 )
    {
        //EPrint("BCryptDecrypt failed! (0x%x)\n", status);
        goto clean;
    }
    
clean:

    FLeave();
    return status;
}

NTSTATUS RSA_signHash(
    _In_ BCRYPT_KEY_HANDLE privKey,
    _In_ LPCWSTR algId,
    _In_ PUCHAR hash,
    _In_ ULONG hash_ln,
    _Inout_ PUCHAR* signature,
    _Inout_ PULONG signature_ln
)
{
    FEnter();

    NTSTATUS status = STATUS_SUCCESS;
    ULONG required_size = 0;

    // no OAEP padding possible
    ULONG flags = BCRYPT_PAD_PKCS1;
    // The BCRYPT_PKCS1_PADDING_INFO structure is used to provide options for the PKCS #1 padding scheme.
    // PKCS #1
    // The recommended standards for the implementation of public-key cryptography based on the RSA algorithm as defined in RFC 3447.
    // Must match hash algorithm.
    BCRYPT_PKCS1_PADDING_INFO pad_info = { 
        .pszAlgId = algId
    };

    status = BCryptSignHash(
        privKey,
        &pad_info,
        hash,
        hash_ln,
        NULL,
        0,
        &required_size,
        flags
    );
    if ( status != 0 )
    {
        //EPrint("BCryptSignHash get size failed! (0x%x)\n", status);
        goto clean;
    }
    DPrint("required_size: 0x%x\n", required_size);

    if ( *signature == NULL )
    {
        *signature = (PUCHAR)ExAllocatePoolWithTag(ALLOC_POOL_TYPE, required_size, 'rngs');
        if ( *signature == NULL )
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            //EPrint("malloc out buffer failed! (0x%x)\n", status);
            status = STATUS_NO_MEMORY;
            goto clean;
        }
    }
    else
    {
        if ( required_size > *signature_ln )
        {
            status = STATUS_BUFFER_TOO_SMALL;
            //EPrint("Provided plain buffer[0x%x] is too small! 0x%x needed! (0x%x)\n", *signature_ln, required_size, status);
            goto clean;
        }
    }
    *signature_ln = required_size;
    
    status = BCryptSignHash(
        privKey,
        &pad_info,
        hash,
        hash_ln,
        *signature,
        *signature_ln,
        &required_size,
        flags
    );
    if ( status != 0 )
    {
        //EPrint("BCryptSignHash failed! (0x%x)\n", status);
        goto clean;
    }

clean:

    FLeave();
    return status;
}

NTSTATUS RSA_verifyHash(
    _In_ BCRYPT_KEY_HANDLE pubKey,
    _In_ LPCWSTR algId,
    _In_ PUCHAR hash,
    _In_ ULONG hash_ln,
    _In_ PUCHAR signature,
    _In_ ULONG signature_ln
)
{
    FEnter();
    NTSTATUS status = STATUS_SUCCESS;
    
    // no OAEP padding possible
    ULONG flags = BCRYPT_PAD_PKCS1;
    // The BCRYPT_PKCS1_PADDING_INFO structure is used to provide options for the PKCS #1 padding scheme.
    // PKCS #1
    // The recommended standards for the implementation of public-key cryptography based on the RSA algorithm as defined in RFC 3447.
    // Must match hash algorithm.
    BCRYPT_PKCS1_PADDING_INFO pad_info = { 
        .pszAlgId = algId
    };

    status = BCryptVerifySignature(
        pubKey,
        &pad_info,
        hash,
        hash_ln,
        signature,
        signature_ln,
        flags
    );
    if ( status != 0 )
    {
        //EPrint("BCryptVerifySignature failed! (0x%x)\n", status);
        goto clean;
    }

clean:
    
    FLeave();
    return status;
}

NTSTATUS RSA_clean(
    _Inout_ PRSA_CTXT ctxt
)
{
    if ( ctxt->alg )
    {
        BCryptCloseAlgorithmProvider(ctxt->alg, 0);
        ctxt->alg = NULL;
    }

    if ( ctxt->pub_key )
    {
        BCryptDestroyKey(ctxt->pub_key);
        ctxt->pub_key = NULL;
    }

    if ( ctxt->priv_key )
    {
        BCryptDestroyKey(ctxt->priv_key);
        ctxt->priv_key = NULL;
    }

    if ( ctxt->padding_info != NULL )
    {
        //if ( ctxt->padding == BCRYPT_PAD_OAEP )
        //{
        //    if ( ctxt->padding_info )
        //    {
        //        BCRYPT_OAEP_PADDING_INFO* pad_info = (BCRYPT_OAEP_PADDING_INFO*)ctxt->padding_info;
        //        RtlSecureZeroMemory(pad_info->pbLabel, pad_info->cbLabel);
        //        free(pad_info->pbLabel);
        //    }
        //}

        ExFreePool(ctxt->padding_info);
        ctxt->padding_info = NULL;
    }

    RtlSecureZeroMemory(ctxt, sizeof(*ctxt));

    return 0;
}

//
// internal file io
//

NTSTATUS KGetFileSize(
    _In_ HANDLE File,
    _Out_ PUINT64 Size
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    IO_STATUS_BLOCK iosb;
    FILE_STANDARD_INFORMATION fi;
    
    *Size = 0;
    RtlZeroMemory(&iosb, sizeof(iosb));
    RtlZeroMemory(&fi, sizeof(fi));

    Status = ZwQueryInformationFile(
                File, 
                &iosb, 
                (PVOID)&fi, 
                sizeof(fi), 
                FileStandardInformation
            );
    
    if ( Status != 0 )
        return Status;

    *Size = fi.EndOfFile.QuadPart;

    return Status;
}

/**
 * Load bytes of a file into a buffer.
 * 
 * @param path PCHAR* The path to the file to be loaded.
 * @param buffer PUCHAR* The resulting buffer pointer allocated in the function. Has to be freed when not needed anymore.
 * @param buffer_ln PULONG Size of the resulting buffer in bytes.
 */
NTSTATUS loadFileBytes(
    _In_ const CHAR* path, 
    _Out_ PUCHAR* buffer, 
    _Out_ PULONG buffer_ln
)
{
    NTSTATUS status = STATUS_SUCCESS;

    HANDLE file = NULL;
    PWCHAR wpath = NULL;
    SIZE_T wpath_cb = MAX_PATH*2;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK iosb;
    UNICODE_STRING uc_path;
    
    LARGE_INTEGER file_size = {0};
    
    *buffer = NULL;
    *buffer_ln = 0;
    RtlZeroMemory(&objAttr, sizeof(objAttr));
    RtlZeroMemory(&iosb, sizeof(iosb));
    DPrint("getFileBytes\n");
    DPrint(" - path: %s\n", path);
    
    wpath = (PWCHAR)ExAllocatePoolWithTag(ALLOC_POOL_TYPE, wpath_cb, 'thap');
    if ( !wpath )
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto clean;
    }
    RtlZeroMemory(wpath, wpath_cb);

#ifdef RING3
    char full_path[MAX_PATH];
    int fpl;
    fpl = GetFullPathNameA(path, MAX_PATH, full_path, NULL);
    if (!fpl)
    {
        status = GetLastError();
        //status = STATUS_UNSUCCESSFUL;
        //EPrint("Get full path failed for \"%s\"! (0x%x)\n", path, status);
        status = STATUS_OBJECT_NAME_NOT_FOUND;
        goto clean;
    }
    
    status = RtlStringCchPrintfW(wpath, MAX_PATH, L"\\??\\%hs", full_path);
#else
    status = RtlStringCchPrintfW(wpath, MAX_PATH, L"%hs", path);
#endif
    if ( status != 0 )
    {
        //EPrint("RtlStringCchPrintfW failed! (0x%x)\n", status);
        goto clean;
    }
    wpath[MAX_PATH - 1] = 0;
    RtlInitUnicodeString(&uc_path, wpath);
    DPrint(" - uc path: %ws\n", uc_path.Buffer);

    InitializeObjectAttributes(
        &objAttr,
        &uc_path,
        0,
        NULL,
        NULL
    );

    status = NtCreateFile(
        &file,
        GENERIC_READ | SYNCHRONIZE,
        &objAttr,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );
    if ( status != 0 )
    {
        //EPrint("NtCreateFile failed! (0x%x)\n", status);
        goto clean;
    }

    status = KGetFileSize(file, (PUINT64)&file_size);
    if ( status != 0 )
    {
        //EPrint("KGetFileSize \"%s\" failed! (0x%x)\n", path, status);
        status = STATUS_OBJECT_NAME_NOT_FOUND;
        goto clean;
    }

    *buffer = (UCHAR*)ExAllocatePoolWithTag(ALLOC_POOL_TYPE, (SIZE_T)file_size.QuadPart, 'ffub');
    if ( *buffer == NULL )
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        //EPrint("Allocating buffer failed! (0x%x)\n", status);
        status = STATUS_NO_MEMORY;
        goto clean;
    }

    *buffer_ln = (ULONG)file_size.QuadPart;
    RtlZeroMemory(&iosb, sizeof(iosb));
    RtlZeroMemory(*buffer, *buffer_ln);
    status = NtReadFile(
        file,
        NULL,
        NULL,
        NULL,
        &iosb,
        *buffer,
        *buffer_ln,
        NULL,
        NULL
    );
    if ( status != 0 || iosb.Status != 0 )
    {
        //EPrint("NtReadFile failed! (0x%x)\n", status);
        goto clean;
    }
    if ( (ULONG)iosb.Information > *buffer_ln )
    {
        status = STATUS_UNSUCCESSFUL;
        *buffer_ln = 0;
        //EPrint("key_buffer to small. 0x%x needed! (0x%x)\n", (ULONG)iosb.Information, status);
        goto clean;
    }
    *buffer_ln = (ULONG)iosb.Information;

clean:
    if ( file != NULL )
        NtClose(file);
    if ( wpath != NULL )
        ExFreePool(wpath);

    return status;
}

/**
 * Create a file and writes the buffer bytes to it.
 * 
 * @param path PCHAR* The path to the file to be created.
 * @param buffer PUCHAR The bytes to be written to file.
 * @param buffer_ln ULONG Size of the buffer in bytes.
 */
NTSTATUS writeFileBytes(
    _In_ const CHAR* path, 
    _In_ PUCHAR buffer, 
    _In_ ULONG buffer_ln
)
{
    NTSTATUS status = STATUS_SUCCESS;

    HANDLE file = NULL;
    PWCHAR wpath = NULL;
    SIZE_T wpath_cb = MAX_PATH*2;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK iosb;
    UNICODE_STRING uc_path;
    
    RtlZeroMemory(&objAttr, sizeof(objAttr));
    RtlZeroMemory(&iosb, sizeof(iosb));
    DPrint("writeFileBytes\n");
    DPrint(" - path: %s\n", path);
    
    wpath = (PWCHAR)ExAllocatePoolWithTag(ALLOC_POOL_TYPE, wpath_cb, 'thap');
    if ( !wpath )
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto clean;
    }
    RtlZeroMemory(wpath, wpath_cb);

#ifdef RING3
    char full_path[MAX_PATH];
    int fpl;
    fpl = GetFullPathNameA(path, MAX_PATH, full_path, NULL);
    if (!fpl)
    {
        status = GetLastError();
        //EPrint("Get full path failed for \"%s\"! (0x%x)", path, status);
        status = STATUS_OBJECT_NAME_NOT_FOUND;
        goto clean;
    }

    status = RtlStringCchPrintfW(wpath, MAX_PATH, L"\\??\\%hs", full_path);
#else
    status = RtlStringCchPrintfW(wpath, MAX_PATH, L"%hs", path);
#endif
    if ( status != 0 )
    {
        //EPrint("RtlStringCchPrintfW failed! (0x%x)\n", status);
        goto clean;
    }
    wpath[MAX_PATH - 1] = 0;
    RtlInitUnicodeString(&uc_path, wpath);
    DPrint(" - uc path: %ws\n", uc_path.Buffer);

    InitializeObjectAttributes(
        &objAttr,
        &uc_path,
        0,
        NULL,
        NULL
    );

    status = NtCreateFile(
        &file,
        GENERIC_WRITE | SYNCHRONIZE,
        &objAttr,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OVERWRITE_IF,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );
    if ( status != 0 )
    {
        //EPrint("NtCreateFile failed! (0x%x)\n", status);
        goto clean;
    }

    RtlZeroMemory(&iosb, sizeof(iosb));
    status = NtWriteFile(
        file,
        NULL,
        NULL,
        NULL,
        &iosb,
        buffer,
        buffer_ln,
        NULL,
        NULL
    );
    if ( status != 0 || iosb.Status != 0 )
    {
        //EPrint("NtReadFile failed! (0x%x)\n", status);
        goto clean;
    }

clean:
    if ( file != NULL )
        NtClose(file);
    if ( wpath != NULL )
        ExFreePool(wpath);

    return status;
}
