#include "RSACNG.h"

#include <winternl.h>
#include <wincrypt.h> // old

#include <stdio.h>
#include <stdlib.h>

#include "../../winDefs.h"
#ifdef DEBUG_PRINT
#include "../../debug.h"
#endif



NTSTATUS loadFileBytes(
    const CHAR* path, 
    PUCHAR* buffer, 
    PULONG buffer_ln
);

NTSTATUS writeFileBytes(
    const CHAR* path, 
    PUCHAR buffer, 
    ULONG buffer_ln
);



__forceinline
void ZeroLocalFree(PVOID _b_, SIZE_T _n_) {
    ZeroMemory(_b_, _n_);
    LocalFree(_b_); 
}
__forceinline
void ZeroFree(PVOID _b_, SIZE_T _n_) {
    ZeroMemory(_b_, _n_);
    free(_b_);
}

int RSA_init(
    PRSA_CTXT ctxt
)
{
    NTSTATUS status = STATUS_SUCCESS;

    RtlZeroMemory(ctxt, sizeof(RSA_CTXT));

    status = BCryptOpenAlgorithmProvider(
        &ctxt->alg,
        BCRYPT_RSA_ALGORITHM,
        NULL,
        0
    );
    if ( !NT_SUCCESS(status) )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptOpenAlgorithmProvider\n", status);
#endif
        return -1;
    }

    ctxt->padding = BCRYPT_SUPPORTED_PAD_PKCS1_ENC; // random number padding
    ctxt->padding_info = NULL;
    //ctxt->padding = BCRYPT_SUPPORTED_PAD_OAEP; // fill and pass pad_info
    //UCHAR label[64] = {0};
    //ULONG label_ln = 64;
    //BCRYPT_OAEP_PADDING_INFO* pad_info = (BCRYPT_OAEP_PADDING_INFO*)malloc(sizeof(BCRYPT_OAEP_PADDING_INFO));
    //ZeroMemory(pad_info, sizeof(BCRYPT_OAEP_PADDING_INFO));
    //pad_info->pszAlgId = BCRYPT_SHA512_ALGORITHM;
    //pad_info->pbLabel = label;
    //pad_info->cbLabel = label_ln;
    //ctxt->padding_info = pad_info;
    return 0;
}

void ReverseMemCopy(BYTE *pbDest, BYTE const *pbSource, ULONG cb)
{
    for (ULONG i = 0; i < cb; i++) 
    {
        pbDest[cb - 1 - i] = pbSource[i];
    }
}

//BOOL 
//ReverseBytes (
//    _Inout_updates_bytes_(ByteBufferLength) PVOID   ByteBuffer_,
//    _In_ ULONG  ByteBufferLength
//)
//{
//    ULONG count = 0;
//    BYTE  TmpByteBuffer = 0;
//    PBYTE ByteBuffer = (PBYTE)(ByteBuffer_);
//    for( count=0; count < ByteBufferLength/2; count++)
//    {
//      TmpByteBuffer = *(ByteBuffer + count);
//      *(ByteBuffer + count) = *(ByteBuffer + ByteBufferLength - count -1);
//      *(ByteBuffer + ByteBufferLength - count -1) = TmpByteBuffer;
//    }
//
//    return TRUE;
//
//}

int RSA_importPubKeyFromFile(
    PRSA_CTXT ctxt,
    const CHAR* path, 
    KEY_TYPE type
)
{
    NTSTATUS status = STATUS_SUCCESS;
    UCHAR* key_buffer = NULL;
    ULONG key_buffer_ln = 0;
    UCHAR* key_bytes = NULL;
    ULONG key_bytes_ln = 0;
    PUBLICKEYSTRUC* wc_blob = NULL;
    RSAPUBKEY* wc_blob_pk = NULL;
    ULONG wc_blob_ln = 0;
    PBYTE pbC = NULL;

    if ( type == KEY_TYPE_PEM || type > KEY_TYPE_BLOB )
    {
#ifdef ERROR_PRINT
        printf("Unknown key type\n");
#endif
        return -1;
    }

    status = loadFileBytes(path, &key_buffer, &key_buffer_ln);
    if ( !NT_SUCCESS(status) )
    {
        goto clean;
    }

#ifdef DEBUG_PRINT
    if ( type == KEY_TYPE_PUB || type == KEY_TYPE_PEM )
    {
        printf("file chars (0x%x):\n", (key_buffer_ln));
        printf("'");
        for ( ULONG i = 0; i < key_buffer_ln; i++ )
            printf("%c", key_buffer[i]);
        printf("'");
        printf("\n");
    }
    printf("file bytes (0x%x):", (key_buffer_ln));
    printMemory(key_buffer, key_buffer_ln, 0x10, 0);
#endif

//    if ( type == KEY_TYPE_PUB || type == KEY_TYPE_PEM )
//    {
//#ifdef DEBUG_PRINT
//        printf("convert pem\n");
//#endif
//        status = CryptStringToBinaryA(
//            (CHAR*)&key_buffer[offset],
//            key_buffer_ln-cut,
//            CRYPT_STRING_ANY,
//            NULL,
//            &key_bytes_ln,
//            NULL,
//            NULL
//        );
//        if ( !status )
//        {
//            status = STATUS_UNSUCCESSFUL;
//#ifdef ERROR_PRINT
//            printf("Error (0x%x): CryptStringToBinaryA.\n", GetLastError());
//#endif
//            goto clean;
//        }
//#ifdef DEBUG_PRINT
//        printf("Need 0x%x bytes for key\n", key_bytes_ln);
//#endif
//        key_bytes = (UCHAR*) LocalAlloc(0, key_bytes_ln);
//        if (key_bytes == NULL) 
//        {
//            status = STATUS_NO_MEMORY;
//#ifdef ERROR_PRINT
//            printf("Error (0x%x): LocalAlloc.\n", GetLastError());
//#endif
//            goto clean;
//        }
//        status = CryptStringToBinaryA(
//            (CHAR*)&key_buffer[offset],
//            key_buffer_ln-cut,
//            CRYPT_STRING_ANY,
//            key_bytes,
//            &key_bytes_ln,
//            NULL,
//            NULL
//        );
//        if ( !status )
//        {
//            status = STATUS_UNSUCCESSFUL;
//#ifdef ERROR_PRINT
//            printf("Error (0x%x): CryptStringToBinaryA.\n", GetLastError());
//#endif
//            goto clean;
//        }
//    }
//    else 
    if ( type == KEY_TYPE_DER )
    {
        // der = big endian
        // wc.blob = little endiam
#ifdef DEBUG_PRINT
        printf("convert der\n");
#endif
        key_bytes_ln = key_buffer_ln;
        CERT_PUBLIC_KEY_INFO *publicKeyInfo = NULL;
        ULONG publicKeyInfoLen;

        // Decode from DER format to CERT_PUBLIC_KEY_INFO. This has the public key
        // in ASN.1 encoded format called "SubjectPublicKeyInfo" ... szOID_RSA_RSA
        status = CryptDecodeObjectEx(
            X509_ASN_ENCODING, 
            X509_PUBLIC_KEY_INFO, 
            key_buffer,
            key_buffer_ln, 
            CRYPT_ENCODE_ALLOC_FLAG, 
            NULL, 
            &publicKeyInfo, 
            &publicKeyInfoLen
        );
        if ( !status )
        {
#ifdef ERROR_PRINT
            printf("Error (0x%x): CryptDecodeObjectEx 1.\n", GetLastError());
            PrintCSBackupAPIErrorMessage(GetLastError());
#endif
            status = STATUS_UNSUCCESSFUL;
            goto clean;
        }
        
#ifdef DEBUG_PRINT
        printf("publicKeyInfo : %p\n", publicKeyInfo);
        printf("publicKeyInfo bytes (0x%x):", publicKeyInfoLen);
        printMemory(publicKeyInfo, publicKeyInfoLen, 0x10, 1);
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
        status = CryptDecodeObjectEx(
            X509_ASN_ENCODING, 
            RSA_CSP_PUBLICKEYBLOB,
            publicKeyInfo->PublicKey.pbData, 
            publicKeyInfo->PublicKey.cbData,
            CRYPT_ENCODE_ALLOC_FLAG, 
            NULL, 
            &key_bytes, 
            &key_bytes_ln
        );
        if ( !status )
        {
#ifdef ERROR_PRINT
            printf("Error (0x%x): CryptDecodeObjectEx 2.\n", GetLastError());
            PrintCSBackupAPIErrorMessage(GetLastError());
#endif
            status = STATUS_UNSUCCESSFUL;
            goto clean;
        }

        if ( publicKeyInfo != NULL )
            LocalFree(publicKeyInfo);
        
        wc_blob = (PUBLICKEYSTRUC*)(&key_bytes[0]);
        wc_blob_ln = key_bytes_ln - 0;
        wc_blob_pk = (RSAPUBKEY*)(wc_blob + 1);
    }
//    else if ( type == KEY_TYPE_BLOB )
//    {
//        //offset = 0;
//        //cut = 0;
//#ifdef DEBUG_PRINT
//        printf("is blob\n");
//        printf(" offset : %u\n", offset);
//        printf(" cut : %u\n", cut);
//#endif
//        key_bytes_ln = key_buffer_ln - cut;
//        key_bytes = (UCHAR*) LocalAlloc(0, key_bytes_ln);
//        //key_bytes = key_buffer;
//        memcpy(key_bytes, &key_buffer[offset], key_bytes_ln);
//        //ReverseMemCopy(key_bytes, key_buffer, key_bytes_ln);
//    }
//#ifdef DEBUG_PRINT
//    printf("wincrypt blob bytes (0x%x):", key_bytes_ln);
//    printMemory(key_bytes, key_bytes_ln, 0x10, 0);
//#endif
//
//    if ( wc_blob == NULL )
//    {
//        wc_blob = (PUBLICKEYSTRUC*)(key_bytes);
//        wc_blob_ln = key_bytes_ln;
//        wc_blob_pk = (RSAPUBKEY*)(wc_blob + 1);
//    }
//
//    if ( wc_blob_pk->magic != BCRYPT_RSAPUBLIC_MAGIC )
//    {
//        status = STATUS_UNSUCCESSFUL;
//#ifdef ERROR_PRINT
//        printf("Error (0x%x): Not a RSA public key.\n", status);
//        PrintCSBackupAPIErrorMessage(status);
//#endif
//        goto clean;
//    }

    // Fill header
    //
    // ->BCRYPT_RSAKEY_BLOB
    // PublicExponent[cbPublicExp] // Big-endian.
    // Modulus[cbModulus] // Big-endian.
    
    ULONG modulus_bytes = wc_blob_pk->bitlen >> 3;
    ULONG blob_ln = sizeof(BCRYPT_RSAKEY_BLOB) + sizeof(wc_blob_pk->pubexp) + modulus_bytes;
    pbC = (PBYTE)LocalAlloc(0, blob_ln);
    if ( pbC == NULL )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): LocalAlloc\n", GetLastError());
#endif
        goto clean;
    }
    RtlZeroMemory(pbC, blob_ln);
    BYTE* ptr;
    BCRYPT_RSAKEY_BLOB* blob = (BCRYPT_RSAKEY_BLOB*)pbC;
    blob->Magic = wc_blob_pk->magic;
    blob->BitLength = wc_blob_pk->bitlen;
    blob->cbPublicExp = sizeof(wc_blob_pk->pubexp);
    blob->cbModulus = modulus_bytes;
    blob->cbPrime1 = 0;
    blob->cbPrime2 = 0;

    // Copy pubExp Big Endian 
    //
    // BCRYPT_RSAKEY_BLOB
    // ->PublicExponent[cbPublicExp] // Big-endian.
    // Modulus[cbModulus] // Big-endian.
    ptr = (PBYTE)(blob + 1);
    ReverseMemCopy(ptr, (PBYTE)&wc_blob_pk->pubexp, blob->cbPublicExp);
#ifdef DEBUG_PRINT
    printf(" exp: 0x%08x 0x%08x\n", (ULONG)*(ULONG*)ptr, wc_blob_pk->pubexp);
#endif

    // Copy Modulus Big Endian 
    //
    // BCRYPT_RSAKEY_BLOB
    // PublicExponent[cbPublicExp] // Big-endian.
    // ->Modulus[cbModulus] // Big-endian.
    
    ptr += blob->cbPublicExp;
    ReverseMemCopy(ptr, (PBYTE)(wc_blob_pk+1), blob->cbModulus);
#ifdef DEBUG_PRINT
    printf(" mod: 0x%08x 0x%08x\n", (ULONG)*(ULONG*)ptr, (ULONG)*(ULONG*)(wc_blob_pk+1));

    
    printf("wc blob\n");
    printf(" bType: 0x%x\n", wc_blob->bType);
    printf(" bVersion: 0x%x\n", wc_blob->bVersion);
    printf(" aiKeyAlg: 0x%x\n", wc_blob->aiKeyAlg);
    printf("wc pk\n");
    printf(" Magic: 0x%x (%.4s)\n", wc_blob_pk->magic, (CHAR*)&wc_blob_pk->magic);
    printf(" BitLength: 0x%x\n", wc_blob_pk->bitlen);
    printf(" cbPublicExp: 0x%x\n", wc_blob_pk->pubexp);

    printf("bc blob\n");
    printf(" Magic: 0x%x (%.4s)\n", blob->Magic, (CHAR*)&blob->Magic);
    printf(" BitLength: 0x%x\n", blob->BitLength);
    printf(" cbPublicExp: 0x%x\n", blob->cbPublicExp);
    printf(" cbModulus: 0x%x\n", blob->cbModulus);
    printf(" cbPrime1: 0x%x\n", blob->cbPrime1);
    printf(" cbPrime2: 0x%x\n", blob->cbPrime2);
    //PublicExponent[cbPublicExp] // Big-endian.
    //Modulus[cbModulus] // Big-endian.
    
    printf("blob raw bytes (0x%x):", blob_ln);
    printMemory(pbC, blob_ln, 0x10, 0);
    
    printf("blob exp: 0x%x\n", (ULONG)*(ULONG*)&blob[1]);

    printf("bc blob bytes (0x%x):", blob->cbModulus);
    printMemory(ptr, blob->cbModulus, 0x10, 0);
#endif

    status = BCryptImportKeyPair(
        ctxt->alg,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        &ctxt->pub_key,
        (PUCHAR)blob,
        blob_ln,
        0
    );
    if ( !NT_SUCCESS(status) )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptImportKeyPair\n", status);
        PrintCSBackupAPIErrorMessage(status);
#endif
        goto clean;
    }
#ifdef DEBUG_PRINT
    printf("key: %p\n", ctxt->pub_key);
#endif

clean:
    if ( key_bytes != NULL && key_bytes != key_buffer )
        LocalFree(key_bytes);
    if ( pbC != NULL )
        LocalFree(pbC);
    if ( key_buffer )
        free(key_buffer);

    return (int)status;
}

int RSA_exportPubKeyToDER(
    PRSA_CTXT ctxt,
    const CHAR* path
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PBYTE buffer = NULL;
    PBYTE wc_buffer = NULL;
    PBYTE ptr = NULL;
    ULONG blob_ln = 0;
    ULONG blob_ln_res = 0;
    BCRYPT_RSAKEY_BLOB* blob = NULL;
    ULONG wc_blob_ln;
    RSAPUBKEY* wc_blob_pubk = NULL;
    
    UCHAR *der_buffer= NULL;
    ULONG der_buffer_ln;

    CERT_PUBLIC_KEY_INFO *publicKeyInfo = NULL;
    ULONG publicKeyInfoLen;
    CERT_PUBLIC_KEY_INFO *publicKeyInfo_t = NULL;

    status = BCryptExportKey(
        ctxt->pub_key,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        NULL,
        0,
        &blob_ln_res,
        0
    );
    if ( !NT_SUCCESS(status) || blob_ln_res == 0 )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptExportKey\n", status);
        PrintCSBackupAPIErrorMessage(status);
#endif
        goto clean;
    }
    
    blob_ln = blob_ln_res;
    buffer = (PBYTE)LocalAlloc(0, blob_ln);
    if ( buffer == NULL )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): LocalAlloc\n", GetLastError());
#endif
        goto clean;
    }
    RtlZeroMemory(buffer, blob_ln);
    blob = (BCRYPT_RSAKEY_BLOB*)buffer;
#ifdef DEBUG_PRINT
    printf("blob_ln: 0x%x\n", blob_ln);
#endif
    
    status = BCryptExportKey(
        ctxt->pub_key,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        buffer,
        blob_ln,
        &blob_ln_res,
        0
    );
    if ( !NT_SUCCESS(status) || blob_ln_res == 0 )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptExportKey\n", status);
        PrintCSBackupAPIErrorMessage(status);
#endif
        goto clean;
    }
    
#ifdef DEBUG_PRINT
    printf("bc blob\n");
    printf(" Magic: 0x%x (%.4s)\n", blob->Magic, (CHAR*)&blob->Magic);
    printf(" BitLength: 0x%x\n", blob->BitLength);
    printf(" cbPublicExp: 0x%x\n", blob->cbPublicExp);
    printf(" cbModulus: 0x%x\n", blob->cbModulus);
    printf(" cbPrime1: 0x%x\n", blob->cbPrime1);
    printf(" cbPrime2: 0x%x\n", blob->cbPrime2);
    
    printf("bc blob raw bytes (0x%x):", blob_ln);
    printMemory(buffer, blob_ln, 0x10, 0);
    ptr = ((PBYTE)(blob + 1));
    printf("bc blob exponent (0x%x):", blob->cbPublicExp);
    printMemory(ptr, blob->cbPublicExp, 0x10, 0);
    ptr += blob->cbPublicExp;
    printf("blob data (0x%x):", blob->cbModulus);
    printMemory(ptr, blob->cbModulus, 0x10, 0);
#endif

    //typedef struct _PUBLICKEYSTRUC {
    //  BYTE   bType;
    //  BYTE   bVersion;
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
    wc_buffer = (PBYTE)LocalAlloc(0, wc_blob_ln);
    if ( wc_buffer == NULL )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): LocalAlloc\n", GetLastError());
#endif
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
    ReverseMemCopy((BYTE*)&wc_blob_pubk->pubexp, &buffer[24], blob->cbPublicExp);
    ptr = (PBYTE)wc_blob_pubk;
    //(ULONG)*(ULONG*)&ptr[0] = blob->Magic;
    //(ULONG)*(ULONG*)&ptr[4] = blob->BitLength;
    //ReverseMemCopy(&ptr[8], &buffer[24], blob->cbPublicExp);
    ReverseMemCopy(&ptr[12], &buffer[24+blob->cbPublicExp], blob->cbModulus);
    
#ifdef DEBUG_PRINT
    printf("wc blob raw bytes (0x%x):", wc_blob_ln);
    printMemory(wc_buffer, wc_blob_ln, 0x10, 0);

    printf("convert to pubkey info\n");
#endif
    // Decode the wc blob to a intermediate CERT_PUBLIC_KEY_INFO format
    status = CryptEncodeObjectEx(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
        RSA_CSP_PUBLICKEYBLOB, // szOID_RSA_RSA
        wc_bh, 
        CRYPT_ENCODE_ALLOC_FLAG, 
        NULL, 
        &publicKeyInfo, 
        &publicKeyInfoLen
    );
    if ( !status )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): CryptEncodeObjectEx 1.\n", GetLastError());
        PrintCSBackupAPIErrorMessage(GetLastError());
#endif
        status = STATUS_UNSUCCESSFUL;
        goto clean;
    }
#ifdef DEBUG_PRINT
    printf("publicKeyInfo bytes (0x%x):", publicKeyInfoLen);
    printMemory((PBYTE)publicKeyInfo, publicKeyInfoLen, 0x10, 0);
#endif
    publicKeyInfo_t = (CERT_PUBLIC_KEY_INFO*)malloc(publicKeyInfoLen+0x50);
    if ( !publicKeyInfo_t )
    {
        printf("malloc failed\n");
        goto clean;
    }
    ZeroMemory(publicKeyInfo_t, publicKeyInfoLen+0x50);
    ULONG api_blob_data = 0x0005;
    ULONG api_cb_blob_data = 2;
    ULONG pub_key_cbData = publicKeyInfoLen;
    publicKeyInfo_t->Algorithm.pszObjId = (LPSTR)&((PBYTE)publicKeyInfo_t)[0x30];
    publicKeyInfo_t->Algorithm.Parameters.cbData = api_cb_blob_data;
    publicKeyInfo_t->Algorithm.Parameters.pbData = &((PBYTE)publicKeyInfo_t)[0x48];
    publicKeyInfo_t->PublicKey.cbData = pub_key_cbData;
    publicKeyInfo_t->PublicKey.pbData = &((PBYTE)publicKeyInfo_t)[0x50];
    publicKeyInfo_t->PublicKey.cUnusedBits = 0;
    memcpy(&((PBYTE)publicKeyInfo_t)[0x30], szOID_RSA_RSA, strlen(szOID_RSA_RSA));
    memcpy(&((PBYTE)publicKeyInfo_t)[0x48], &api_blob_data, sizeof(api_blob_data));
    memcpy(&((PBYTE)publicKeyInfo_t)[0x50], publicKeyInfo, publicKeyInfoLen);
    publicKeyInfoLen += 0x50;

#ifdef DEBUG_PRINT
    printf("publicKeyInfo_t : %p\n", publicKeyInfo_t);
    printf("publicKeyInfo bytes (0x%x):", publicKeyInfoLen);
    printMemory(publicKeyInfo_t, publicKeyInfoLen, 0x10, 1);
    printf(" Algorithm\n");
    printf("  pszObjId: %status (%p)\n", publicKeyInfo_t->Algorithm.pszObjId, publicKeyInfo_t->Algorithm.pszObjId);
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
    status = CryptEncodeObjectEx(
        X509_ASN_ENCODING, 
        X509_PUBLIC_KEY_INFO, 
        publicKeyInfo_t, 
        CRYPT_ENCODE_ALLOC_FLAG, 
        NULL, 
        &der_buffer, 
        &der_buffer_ln
    );
    if ( !status )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): CryptEncodeObjectEx 3.\n", GetLastError());
        PrintCSBackupAPIErrorMessage(GetLastError());
#endif
        status = STATUS_UNSUCCESSFUL;
        goto clean;
    }
    
#ifdef DEBUG_PRINT
    printf("DER bytes (0x%x):", der_buffer_ln);
    printMemory(der_buffer, der_buffer_ln, 0x10, 0);
#endif

    status = writeFileBytes(path, der_buffer, der_buffer_ln);
    if ( !status )
    {
        //status = STATUS_UNSUCCESSFUL;
        goto clean;
    }

clean:
    if ( buffer != NULL )
        LocalFree(buffer);
    if ( wc_buffer != NULL )
        LocalFree(wc_buffer);
    if ( publicKeyInfo != NULL )
        LocalFree(publicKeyInfo);
    if ( publicKeyInfo_t != NULL )
        free(publicKeyInfo_t);

    return (int)status;
}

int RSA_exportPubKeyToBLOB(
    PRSA_CTXT ctxt,
    const CHAR* path
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PBYTE buffer = NULL;
    ULONG blob_ln = 0;
    ULONG blob_ln_res = 0;
    BCRYPT_RSAKEY_BLOB* blob = NULL;
    
    status = BCryptExportKey(
        ctxt->pub_key,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        NULL,
        0,
        &blob_ln_res,
        0
    );
    if ( !NT_SUCCESS(status) || blob_ln_res == 0 )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptExportKey\n", status);
        PrintCSBackupAPIErrorMessage(status);
#endif
        goto clean;
    }
    
    blob_ln = blob_ln_res;
    buffer = (PBYTE)LocalAlloc(0, blob_ln);
    if ( buffer == NULL )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): LocalAlloc\n", GetLastError());
#endif
        goto clean;
    }
    RtlZeroMemory(buffer, blob_ln);
    blob = (BCRYPT_RSAKEY_BLOB*)buffer;
#ifdef DEBUG_PRINT
    printf("blob_ln: 0x%x\n", blob_ln);
#endif
    
    status = BCryptExportKey(
        ctxt->pub_key,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        buffer,
        blob_ln,
        &blob_ln_res,
        0
    );
    if ( !NT_SUCCESS(status) || blob_ln_res == 0 )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptExportKey\n", status);
        PrintCSBackupAPIErrorMessage(status);
#endif
        goto clean;
    }
    
#ifdef DEBUG_PRINT
    printf("bc blob\n");
    printf(" Magic: 0x%x (%.4s)\n", blob->Magic, (CHAR*)&blob->Magic);
    printf(" BitLength: 0x%x\n", blob->BitLength);
    printf(" cbPublicExp: 0x%x\n", blob->cbPublicExp);
    printf(" cbModulus: 0x%x\n", blob->cbModulus);
    printf(" cbPrime1: 0x%x\n", blob->cbPrime1);
    printf(" cbPrime2: 0x%x\n", blob->cbPrime2);
    
    PBYTE ptr = NULL;
    printf("bc blob raw bytes (0x%x):", blob_ln);
    printMemory(buffer, blob_ln, 0x10, 0);
    ptr = ((PBYTE)(blob + 1));
    printf("bc blob exponent (0x%x):", blob->cbPublicExp);
    printMemory(ptr, blob->cbPublicExp, 0x10, 0);
    ptr += blob->cbPublicExp;
    printf("blob data (0x%x):", blob->cbModulus);
    printMemory(ptr, blob->cbModulus, 0x10, 0);
#endif

    status = writeFileBytes(path, (UCHAR*)blob, blob_ln);
    if ( !status )
    {
        //status = STATUS_UNSUCCESSFUL;
        goto clean;
    }

clean:
    if ( buffer != NULL )
        LocalFree(buffer);

    return (int)status;
}

int RSA_importPrivKeyFromFile(
    PRSA_CTXT ctxt,
    const CHAR* path, 
    KEY_TYPE type
)
{
    NTSTATUS status = STATUS_SUCCESS;
    UCHAR* key_buffer = NULL;
    ULONG key_buffer_ln = 0;
    UCHAR* key_bytes = NULL;
    ULONG key_bytes_ln = 0;
    
    PBYTE pbC = NULL;
    ULONG blob_ln = 0;

    BLOBHEADER* wc_blob = NULL;
    RSAPUBKEY* wc_blob_pk = NULL;
    ULONG wc_blob_ln = 0;


    if ( type == KEY_TYPE_NONE )
    {
#ifdef DEBUG_PRINT
        printf("Unknown key type\n");
#endif
        return -1;
    }

    status = loadFileBytes(path, &key_buffer, &key_buffer_ln);
    if ( !NT_SUCCESS(status) )
    {
        goto clean;
    }
#ifdef DEBUG_PRINT
    if ( type == KEY_TYPE_PUB || type == KEY_TYPE_PEM )
    {
        printf("file chars (0x%x):\n", (key_buffer_ln));
        printf("'");
        for ( ULONG i = 0; i < key_buffer_ln; i++ )
            printf("%c", key_buffer[i]);
        printf("'");
        printf("\n");
    }
    printf("file bytes (0x%x):", (key_buffer_ln));
    printMemory(key_buffer, key_buffer_ln, 0x10, 0);
#endif

//    if ( type == KEY_TYPE_PUB || type == KEY_TYPE_PEM )
//    {
//#ifdef DEBUG_PRINT
//        printf("convert pem\n");
//#endif
//        status = CryptStringToBinaryA(
//            (CHAR*)&key_buffer[offset],
//            key_buffer_ln-cut,
//            CRYPT_STRING_ANY,
//            NULL,
//            &key_bytes_ln,
//            NULL,
//            NULL
//        );
//        if ( !status )
//        {
//            status = STATUS_UNSUCCESSFUL;
//#ifdef ERROR_PRINT
//            printf("Error (0x%x): CryptStringToBinaryA.\n", GetLastError());
//#endif
//            goto clean;
//        }
//#ifdef DEBUG_PRINT
//        printf("Need 0x%x bytes for key\n", key_bytes_ln);
//#endif
//        key_bytes = (UCHAR*) LocalAlloc(0, key_bytes_ln);
//        if (key_bytes == NULL) 
//        {
//            status = STATUS_NO_MEMORY;
//#ifdef ERROR_PRINT
//            printf("Error (0x%x): LocalAlloc.\n", GetLastError());
//#endif
//            goto clean;
//        }
//        status = CryptStringToBinaryA(
//            (CHAR*)&key_buffer[offset],
//            key_buffer_ln-cut,
//            CRYPT_STRING_ANY,
//            key_bytes,
//            &key_bytes_ln,
//            NULL,
//            NULL
//        );
//        if ( !status )
//        {
//            status = STATUS_UNSUCCESSFUL;
//#ifdef ERROR_PRINT
//            printf("Error (0x%x): CryptStringToBinaryA.\n", GetLastError());
//#endif
//            goto clean;
//        }
//    }
//    else 
        if ( type == KEY_TYPE_DER )
    {
        // der = big endian
        // wc.blob = little endiam
#ifdef DEBUG_PRINT
        printf("convert der\n");
#endif

        // Decode from DER format to wincrypt blob
        status = CryptDecodeObjectEx(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
            PKCS_RSA_PRIVATE_KEY, 
            key_buffer, 
            key_buffer_ln, 
            CRYPT_ENCODE_ALLOC_FLAG, 
            NULL, 
            &key_bytes, 
            &key_bytes_ln
        );
        if ( !status )
        {
#ifdef ERROR_PRINT
            printf("Error (0x%x): CryptDecodeObjectEx 1.\n", GetLastError());
            PrintCSBackupAPIErrorMessage(GetLastError());
#endif
            status = STATUS_UNSUCCESSFUL;
            goto clean;
        }
        
        wc_blob = (BLOBHEADER*)(&key_bytes[0]);
        wc_blob_ln = key_bytes_ln - 0;
        wc_blob_pk = (RSAPUBKEY*)(wc_blob + 1);
    }
//    else if ( type == KEY_TYPE_BLOB )
//    {
//        //offset = 0;
//        //cut = 0;
//#ifdef DEBUG_PRINT
//        printf("is blob\n");
//        printf(" offset : %u\n", offset);
//        printf(" cut : %u\n", cut);
//#endif
//        key_bytes_ln = key_buffer_ln - cut;
//        key_bytes = (UCHAR*) LocalAlloc(0, key_bytes_ln);
//        //key_bytes = key_buffer;
//        memcpy(key_bytes, &key_buffer[offset], key_bytes_ln);
//        //ReverseMemCopy(key_bytes, key_buffer, key_bytes_ln);
//    }
#ifdef DEBUG_PRINT
    printf("key bytes (0x%x):", key_bytes_ln);
    printMemory(key_bytes, key_bytes_ln, 0x10, 0);
#endif

    if ( wc_blob == NULL )
    {
        wc_blob = (BLOBHEADER*)(&key_bytes[0]);
        wc_blob_ln = key_bytes_ln - 0;
        wc_blob_pk = (RSAPUBKEY*)(wc_blob + 1);
    }
    
    if ( wc_blob_pk->magic != BCRYPT_RSAPRIVATE_MAGIC )
    {
        status = STATUS_UNSUCCESSFUL;
#ifdef ERROR_PRINT
        printf("Error (0x%x): Not a RSA public key.\n", status);
        PrintCSBackupAPIErrorMessage(status);
#endif
        goto clean;
    }

    //
    // Fill header
    //
    // modulus = p1 * p2
    // 
    // ->BCRYPT_RSAKEY_BLOB: Maggic, BitLength, cbPublicExp, cbModulus, cbPrime1, cbPrime2
    // PublicExponent[cbPublicExp] // Big-endian.
    // Modulus[cbModulus] // Big-endian.
    // Prime1[cbPrime1] // Big-endian.
    // Prime2[cbPrime2] // Big-endian.
    // [ Exponent1[cbPrime1] // Big-endian.
    // Exponent2[cbPrime2] // Big-endian.
    // Coefficient[cbPrime1] // Big-endian.
    // PrivateExponent[cbModulus] // Big-endian. ] Full Key
    // wc blob contains full key , maybe it increass performance to import a full key ??
    
    ULONG modulus_bytes = wc_blob_pk->bitlen >> 3;
    ULONG prime_bytes = modulus_bytes >> 1;
    blob_ln = sizeof(BCRYPT_RSAKEY_BLOB) + sizeof(wc_blob_pk->pubexp) + (modulus_bytes << 1); // modulus_bytes + 2*prime_bytes == 2 * modulus_bytes
    pbC = (PBYTE)LocalAlloc(0, blob_ln);
    if ( pbC == NULL )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): LocalAlloc\n", GetLastError());
#endif
        goto clean;
    }
    RtlZeroMemory(pbC, blob_ln);
    BYTE* bcb_ptr;
    BYTE* wcb_ptr;
    BCRYPT_RSAKEY_BLOB* blob = (BCRYPT_RSAKEY_BLOB*)pbC;
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
    bcb_ptr = (PBYTE)(blob + 1);
    ReverseMemCopy(bcb_ptr, (PBYTE)&wc_blob_pk->pubexp, blob->cbPublicExp);
#ifdef DEBUG_PRINT
    printf(" exp: 0x%08x 0x%08x\n", (ULONG)*(ULONG*)bcb_ptr, wc_blob_pk->pubexp);
#endif

    // Copy Modulus Big Endian 
    //
    // ->Modulus[cbModulus] // Big-endian.
    // Prime1[cbPrime1] // Big-endian.
    // Prime2[cbPrime2] // Big-endian.
    
    bcb_ptr += blob->cbPublicExp;
    wcb_ptr = (PBYTE)(wc_blob_pk+1);
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
    printf("blob raw bytes (0x%x):", blob_ln);
    printMemory(pbC, blob_ln, 0x10, 0);

    printf("wc blob\n");
    printf(" bType: 0x%x\n", wc_blob->bType);
    printf(" bVersion: 0x%x\n", wc_blob->bVersion);
    printf(" aiKeyAlg: 0x%x\n", wc_blob->aiKeyAlg);
    printf("wc pk\n");
    printf(" Magic: 0x%x (%.4s)\n", wc_blob_pk->magic, (CHAR*)&wc_blob_pk->magic);
    printf(" BitLength: 0x%x\n", wc_blob_pk->bitlen);
    printf(" cbPublicExp: 0x%x\n", wc_blob_pk->pubexp);

    printf("blob\n");
    printf(" Magic: 0x%x (%.4s)\n", blob->Magic, (CHAR*)&blob->Magic);
    printf(" BitLength: 0x%x\n", blob->BitLength);
    printf(" cbPublicExp: 0x%x\n", blob->cbPublicExp);
    printf(" cbModulus: 0x%x\n", blob->cbModulus);
    printf(" cbPrime1: 0x%x\n", blob->cbPrime1);
    printf(" cbPrime2: 0x%x\n", blob->cbPrime2);
    //PublicExponent[cbPublicExp] // Big-endian.
    //Modulus[cbModulus] // Big-endian.
    
    bcb_ptr = (PBYTE)(blob + 1);
    printf("  exponent (0x%x):", blob->cbPublicExp);
    printMemory(bcb_ptr, blob->cbPublicExp, 0x10, 0);
    
    bcb_ptr += blob->cbPublicExp;
    printf("blob modulus (0x%x):", blob->cbModulus);
    printMemory(bcb_ptr, blob->cbModulus, 0x10, 0);
    
    bcb_ptr += blob->cbModulus;
    printf("blob prime1 (0x%x):", blob->cbPrime1);
    printMemory(bcb_ptr, blob->cbPrime1, 0x10, 0);

    bcb_ptr += blob->cbPrime1;
    printf("blob prime2 (0x%x):", blob->cbPrime2);
    printMemory(bcb_ptr, blob->cbPrime2, 0x10, 0);
#endif

    status = BCryptImportKeyPair(
        ctxt->alg,
        NULL,
        BCRYPT_RSAPRIVATE_BLOB,
        &ctxt->priv_key,
        (PUCHAR)blob,
        blob_ln,
        0
    );
    if ( !NT_SUCCESS(status) )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptImportKeyPair\n", status);
        PrintCSBackupAPIErrorMessage(status);
#endif
        goto clean;
    }
#ifdef DEBUG_PRINT
    printf("key: %p\n", ctxt->priv_key);
#endif

clean:
    if ( key_bytes != NULL && key_bytes != key_buffer )
    {
        ZeroLocalFree(key_bytes, key_bytes_ln);
    }
    if ( pbC != NULL )
        ZeroLocalFree(pbC, blob_ln);
    if ( key_buffer )
        ZeroFree(key_buffer, key_buffer_ln);

    return (int)status;
}

int RSA_exportPrivKeyToDER(
    PRSA_CTXT ctxt,
    const CHAR* path
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PBYTE buffer = NULL;
    PBYTE wc_buffer = NULL;
#ifdef DEBUG_PRINT
    PBYTE ptr = NULL;
#endif
    ULONG blob_ln = 0;
    ULONG blob_ln_res = 0;
    BCRYPT_RSAKEY_BLOB* blob = NULL;
    //ULONG wc_blob_ln;
    //RSAPUBKEY* wc_blob_pubk = NULL;
    
    //UCHAR *der_buffer= NULL;
    //ULONG der_buffer_ln;

    //CERT_PUBLIC_KEY_INFO *publicKeyInfo = NULL;
    //ULONG publicKeyInfoLen;
    //CERT_PUBLIC_KEY_INFO *publicKeyInfo_t = NULL;


    status = BCryptExportKey(
        ctxt->priv_key,
        NULL,
        BCRYPT_RSAPRIVATE_BLOB,
        NULL,
        0,
        &blob_ln_res,
        0
    );
    if ( !NT_SUCCESS(status) || blob_ln_res == 0 )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptExportKey\n", status);
        PrintCSBackupAPIErrorMessage(status);
#endif
        goto clean;
    }
    
    blob_ln = blob_ln_res;
    buffer = (PBYTE)LocalAlloc(0, blob_ln);
    if ( buffer == NULL )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): LocalAlloc\n", GetLastError());
#endif
        goto clean;
    }
    RtlZeroMemory(buffer, blob_ln);
    blob = (BCRYPT_RSAKEY_BLOB*)buffer;
#ifdef DEBUG_PRINT
    printf("blob_ln: 0x%x\n", blob_ln);
#endif
    
    status = BCryptExportKey(
        ctxt->priv_key,
        NULL,
        BCRYPT_RSAPRIVATE_BLOB,
        buffer,
        blob_ln,
        &blob_ln_res,
        0
    );
    if ( !NT_SUCCESS(status) || blob_ln_res == 0 )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptExportKey\n", status);
        PrintCSBackupAPIErrorMessage(status);
#endif
        goto clean;
    }
    
#ifdef DEBUG_PRINT
    printf("bc blob raw bytes (0x%x):", blob_ln);
    printMemory(buffer, blob_ln, 0x10, 0);

    printf("bc blob\n");
    printf(" Magic: 0x%x (%.4s)\n", blob->Magic, (CHAR*)&blob->Magic);
    printf(" BitLength: 0x%x\n", blob->BitLength);
    printf(" cbPublicExp: 0x%x\n", blob->cbPublicExp);
    printf(" cbModulus: 0x%x\n", blob->cbModulus);
    printf(" cbPrime1: 0x%x\n", blob->cbPrime1);
    printf(" cbPrime2: 0x%x\n", blob->cbPrime2);
    ptr = ((PBYTE)(blob + 1));
    printf("  exponent (0x%x):", blob->cbPublicExp);
    printMemory(ptr, blob->cbPublicExp, 0x10, 0);
    ptr += blob->cbPublicExp;
    printf("  modulus (0x%x):", blob->cbModulus);
    printMemory(ptr, blob->cbModulus, 0x10, 0);
    ptr += blob->cbModulus;
    printf("  prime1 (0x%x):", blob->cbPrime1);
    printMemory(ptr, blob->cbPrime1, 0x10, 0);
    ptr += blob->cbPrime1;
    printf("  prime2 (0x%x):", blob->cbPrime2);
    printMemory(ptr, blob->cbPrime2, 0x10, 0);
#endif
//
//    //typedef struct _PUBLICKEYSTRUC {
//    //  BYTE   bType;
//    //  BYTE   bVersion;
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
//    wc_buffer = (PBYTE)LocalAlloc(0, wc_blob_ln);
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
//    ReverseMemCopy((BYTE*)&wc_blob_pubk->pubexp, &buffer[24], blob->cbPublicExp);
//    ptr = (PBYTE)wc_blob_pubk;
//    //(ULONG)*(ULONG*)&ptr[0] = blob->Magic;
//    //(ULONG)*(ULONG*)&ptr[4] = blob->BitLength;
//    //ReverseMemCopy(&ptr[8], &buffer[24], blob->cbPublicExp);
//    ReverseMemCopy(&ptr[12], &buffer[24+blob->cbPublicExp], blob->cbModulus);
//    
//#ifdef DEBUG_PRINT
//    printf("wc blob raw bytes (0x%x):", wc_blob_ln);
//    printMemory(wc_buffer, wc_blob_ln, 0x10, 0);
//
//    printf("convert to pubkey info\n");
//#endif
//    // Decode the wc blob to a intermediate CERT_PUBLIC_KEY_INFO format
//   status = CryptEncodeObjectEx(
//            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
//            PKCS_RSA_PRIVATE_KEY, 
//            key_buffer, 
//            key_buffer_ln, 
//            CRYPT_ENCODE_ALLOC_FLAG, 
//            NULL, 
//            &key_bytes, 
//            &key_bytes_ln
//        );
//    if ( !status )
//    {
//#ifdef ERROR_PRINT
//        printf("Error (0x%x): CryptEncodeObjectEx 1.\n", GetLastError());
//        PrintCSBackupAPIErrorMessage(GetLastError());
//#endif
//        status = STATUS_UNSUCCESSFUL;
//        goto clean;
//    }
//#ifdef DEBUG_PRINT
//    printf("publicKeyInfo bytes (0x%x):", publicKeyInfoLen);
//    printMemory((PBYTE)publicKeyInfo, publicKeyInfoLen, 0x10, 0);
//#endif


//    publicKeyInfo_t = (CERT_PUBLIC_KEY_INFO*)malloc(publicKeyInfoLen+0x50);
//    if ( !publicKeyInfo_t )
//    {
//        printf("malloc failed\n");
//        goto clean;
//    }
//    ZeroMemory(publicKeyInfo_t, publicKeyInfoLen+0x50);
//    ULONG api_blob_data = 0x0005;
//    ULONG api_cb_blob_data = 2;
//    ULONG pub_key_cbData = publicKeyInfoLen;
//    publicKeyInfo_t->Algorithm.pszObjId = (LPSTR)&((PBYTE)publicKeyInfo_t)[0x30];
//    publicKeyInfo_t->Algorithm.Parameters.cbData = api_cb_blob_data;
//    publicKeyInfo_t->Algorithm.Parameters.pbData = &((PBYTE)publicKeyInfo_t)[0x48];
//    publicKeyInfo_t->PublicKey.cbData = pub_key_cbData;
//    publicKeyInfo_t->PublicKey.pbData = &((PBYTE)publicKeyInfo_t)[0x50];
//    publicKeyInfo_t->PublicKey.cUnusedBits = 0;
//    memcpy(&((PBYTE)publicKeyInfo_t)[0x30], szOID_RSA_RSA, strlen(szOID_RSA_RSA));
//    memcpy(&((PBYTE)publicKeyInfo_t)[0x48], &api_blob_data, sizeof(api_blob_data));
//    memcpy(&((PBYTE)publicKeyInfo_t)[0x50], publicKeyInfo, publicKeyInfoLen);
//    publicKeyInfoLen += 0x50;
//
//#ifdef ERROR_PRINT
//    printf("publicKeyInfo_t : %p\n", publicKeyInfo_t);
//    printf("publicKeyInfo bytes (0x%x):", publicKeyInfoLen);
//    printMemory(publicKeyInfo_t, publicKeyInfoLen, 0x10, 1);
//    printf(" Algorithm\n");
//    printf("  pszObjId: %status (%p)\n", publicKeyInfo_t->Algorithm.pszObjId, publicKeyInfo_t->Algorithm.pszObjId);
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
//    status = CryptEncodeObjectEx(
//        X509_ASN_ENCODING, 
//        X509_PUBLIC_KEY_INFO, 
//        publicKeyInfo_t, 
//        CRYPT_ENCODE_ALLOC_FLAG, 
//        NULL, 
//        &der_buffer, 
//        &der_buffer_ln
//    );
//    if ( !status )
//    {
//#ifdef ERROR_PRINT
//        printf("Error (0x%x): CryptEncodeObjectEx 3.\n", GetLastError());
//        PrintCSBackupAPIErrorMessage(GetLastError());
//#endif
//        status = STATUS_UNSUCCESSFUL;
//        goto clean;
//    }
//    
//#ifdef DEBUG_PRINT
//    printf("DER bytes (0x%x):", der_buffer_ln);
//    printMemory(der_buffer, der_buffer_ln, 0x10, 0);
//#endif

    (path);
    //status = writeFileBytes(path, der_buffer, der_buffer_ln);
    //if ( !status )
    //{
    //    //status = STATUS_UNSUCCESSFUL;
    //    goto clean;
    //}

clean:
    if ( buffer != NULL )
        LocalFree(buffer);
    if ( wc_buffer != NULL )
        LocalFree(wc_buffer);

    return (int)status;
}

int RSA_encrypt(
    PRSA_CTXT ctxt,
    PUCHAR plain,
    ULONG plain_ln,
    PUCHAR* encrypted,
    PULONG encrypted_ln
)
{
    ULONG required_size = 0;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG padding = BCRYPT_SUPPORTED_PAD_PKCS1_ENC; // random number padding
    //ULONG padding = BCRYPT_SUPPORTED_PAD_OAEP; // fill and pass pad_info
    //UCHAR label[64] = {0};
    //ULONG label_ln = 64;
    //BCRYPT_OAEP_PADDING_INFO pad_info;
    //ZeroMemory(&pad_info, sizeof(pad_info));
    //pad_info.pszAlgId = BCRYPT_SHA512_ALGORITHM;
    //pad_info.pbLabel = label;
    //pad_info.cbLabel = label_ln;

    status = BCryptEncrypt(
        ctxt->pub_key,
        plain,
        plain_ln,
        NULL,
        NULL,
        0,
        NULL,
        0,
        &required_size,
        padding
    );
    if ( !NT_SUCCESS(status) )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptEncrypt get size\n", status);
#endif
        goto clean;
    }
#ifdef DEBUG_PRINT
    printf("required_size: 0x%x\n", required_size);
#endif

    if ( *encrypted == NULL )
    {
        *encrypted = (PUCHAR)malloc(required_size);
        if ( *encrypted == NULL )
        {
#ifdef ERROR_PRINT
            printf("Error (0x%x): malloc out buffer\n", GetLastError());
            PrintCSBackupAPIErrorMessage(GetLastError());
#endif
            status = STATUS_NO_MEMORY;
            goto clean;
        }
    }
    else
    {
        if ( required_size > *encrypted_ln )
        {
#ifdef ERROR_PRINT
            printf("Error: Provided encryption buffer[0x%x] is too small! 0x%x needed.\n", *encrypted_ln, required_size);
#endif
            status = STATUS_NO_MEMORY;
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
        NULL,
        NULL,
        0,
        *encrypted,
        *encrypted_ln,
        encrypted_ln,
        padding
    );
    if ( !NT_SUCCESS(status) )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptEncrypt\n", status);
        PrintCSBackupAPIErrorMessage(status);
#endif
        goto clean;
    }

clean:
    ;

    return (int)status;
}

int RSA_decrypt(
    PRSA_CTXT ctxt,
    PUCHAR encrypted,
    ULONG encrypted_ln,
    PUCHAR* plain,
    PULONG plain_ln
)
{
    ULONG required_size = 0;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG padding = BCRYPT_SUPPORTED_PAD_PKCS1_ENC; // random number padding
    //ULONG padding = BCRYPT_SUPPORTED_PAD_OAEP; // fill and pass pad_info
    //BCRYPT_OAEP_PADDING_INFO pad_info;
    //ZeroMemory(&pad_info, sizeof(pad_info));
    //pad_info.pszAlgId = BCRYPT_SHA512_ALGORITHM;

    status = BCryptDecrypt(
        ctxt->priv_key,
        encrypted,
        encrypted_ln,
        NULL,
        NULL,
        0,
        NULL,
        0,
        &required_size,
        padding
    );
    if ( !NT_SUCCESS(status) )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptDecrypt get size\n", status);
        //PrintCSBackupAPIErrorMessage(status);
#endif
        goto clean;
    }
#ifdef DEBUG_PRINT
    printf("required_size: 0x%x\n", required_size);
#endif
    
    
    if ( *plain == NULL )
    {
        *plain = (PUCHAR)malloc(required_size);
        if ( *plain == NULL )
        {
#ifdef ERROR_PRINT
            printf("Error (0x%x): malloc out buffer\n", GetLastError());
            PrintCSBackupAPIErrorMessage(GetLastError());
#endif
            status = STATUS_NO_MEMORY;
            goto clean;
        }
    }
    else
    {
        if ( required_size > *plain_ln )
        {
#ifdef ERROR_PRINT
            printf("Error: Provided plain buffer[0x%x] is too small! 0x%x needed.\n", *plain_ln, required_size);
#endif
            status = STATUS_NO_MEMORY;
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
        NULL,
        NULL,
        0,
        *plain,
        *plain_ln,
        plain_ln,
        padding
    );
    if ( !NT_SUCCESS(status) )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptDecrypt\n", status);
        PrintCSBackupAPIErrorMessage(status);
#endif
        goto clean;
    }
    
clean:
    ;
    return (int)status;
}

ULONG padding_type = 4;
int RSA_signHash(
    PRSA_CTXT ctxt,
    PUCHAR hash,
    ULONG hash_ln,
    PUCHAR* signature,
    PULONG signature_ln
)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG required_size = 0;
    ULONG padding = 0;
    PVOID pad_info_ptr = NULL;

    if ( padding_type == 1 )
    {
        padding = BCRYPT_PAD_PKCS1; // random number padding
        BCRYPT_PKCS1_PADDING_INFO pad_info;
        ZeroMemory(&pad_info, sizeof(pad_info));
        pad_info.pszAlgId = BCRYPT_SHA512_ALGORITHM;
        pad_info_ptr = &pad_info;
    }
    else if ( padding_type == 2 )
    {
        padding = BCRYPT_PAD_PSS; // fill and pass pad_info
        BCRYPT_PSS_PADDING_INFO pad_info;
        ZeroMemory(&pad_info, sizeof(pad_info));
        pad_info.pszAlgId = BCRYPT_SHA512_ALGORITHM;
        pad_info.cbSalt = 0x12345678;
        pad_info_ptr = &pad_info;
    }
    else if ( padding_type == 3 )
    {
        padding = BCRYPT_SUPPORTED_PAD_PKCS1_ENC; // fill and pass pad_info
        pad_info_ptr = NULL;
    }
    else 
    {
        padding = 0;
        pad_info_ptr = NULL;
    }

    status = BCryptSignHash(
        ctxt->priv_key,
        pad_info_ptr,
        hash,
        hash_ln,
        NULL,
        0,
        &required_size,
        padding
    );
    if ( !NT_SUCCESS(status) )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptSignHash get size\n", status);
        //PrintCSBackupAPIErrorMessage(status);
#endif
        goto clean;
    }
#ifdef DEBUG_PRINT
    printf("required_size: 0x%x\n", required_size);
#endif

    if ( *signature == NULL )
    {
        *signature = (PUCHAR)malloc(required_size);
        if ( *signature == NULL )
        {
#ifdef ERROR_PRINT
            printf("Error (0x%x): malloc out buffer\n", GetLastError());
            PrintCSBackupAPIErrorMessage(GetLastError());
#endif
            status = STATUS_NO_MEMORY;
            goto clean;
        }
    }
    else
    {
        if ( required_size > *signature_ln )
        {
#ifdef ERROR_PRINT
            printf("Error: Provided plain buffer[0x%x] is too small! 0x%x needed.\n", *signature_ln, required_size);
#endif
            status = STATUS_NO_MEMORY;
            goto clean;
        }
    }
    *signature_ln = required_size;
    
    status = BCryptSignHash(
        ctxt->priv_key,
        pad_info_ptr,
        hash,
        hash_ln,
        *signature,
        *signature_ln,
        NULL,
        padding
    );
    if ( !NT_SUCCESS(status) )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptSignHash\n", status);
        //PrintCSBackupAPIErrorMessage(status);
#endif
        goto clean;
    }

clean:
    ;

    return (int)status;
}

int RSA_verifyHash(
    PRSA_CTXT ctxt,
    PUCHAR hash,
    ULONG hash_ln,
    PUCHAR* signature,
    ULONG* signature_ln
)
{
    NTSTATUS status = STATUS_SUCCESS;
    //ULONG required_size = 0;
    ULONG padding;
    PVOID pad_info_ptr = NULL;

    if ( padding_type == 1 )
    {
        padding = BCRYPT_PAD_PKCS1; // random number padding
        BCRYPT_PKCS1_PADDING_INFO pad_info;
        ZeroMemory(&pad_info, sizeof(pad_info));
        pad_info.pszAlgId = BCRYPT_SHA512_ALGORITHM;
        pad_info_ptr = &pad_info;
    }
    else if ( padding_type == 2 )
    {
        padding = BCRYPT_PAD_PSS; // fill and pass pad_info
        BCRYPT_PSS_PADDING_INFO pad_info;
        ZeroMemory(&pad_info, sizeof(pad_info));
        pad_info.pszAlgId = BCRYPT_SHA512_ALGORITHM;
        pad_info.cbSalt = 0x12345678;
        pad_info_ptr = NULL;
    }
    else 
    {
        padding = 0;
        pad_info_ptr = NULL;
    }

    status = BCryptVerifySignature(
        ctxt->pub_key,
        pad_info_ptr,
        hash,
        hash_ln,
        *signature,
        *signature_ln,
        padding
    );
    if ( !NT_SUCCESS(status) )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptVerifySignature\n", status);
        //PrintCSBackupAPIErrorMessage(status);
#endif
        goto clean;
    }

clean:
    ;

    return (int)status;
}

// Private key encryption
// Doesn't work, since the (in private key included) public key seems to be used,
// because decryption (RSA_verify2) doesn't work with public key (wrong params) but with private key,
// which should only give a valid result, if public key has been used for encryption
int RSA_signHash2(
    PRSA_CTXT ctxt,
    PUCHAR hash,
    ULONG hash_ln,
    PUCHAR* signature,
    PULONG signature_ln
)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG required_size = 0;
    ULONG padding = 0;
    PVOID pad_info_ptr = NULL;

    if ( padding_type == 1 )
    {
        padding = BCRYPT_PAD_PKCS1; // random number padding
        BCRYPT_PKCS1_PADDING_INFO pad_info;
        ZeroMemory(&pad_info, sizeof(pad_info));
        pad_info.pszAlgId = BCRYPT_SHA512_ALGORITHM;
        pad_info_ptr = &pad_info;
    }
    else if ( padding_type == 2 )
    {
        padding = BCRYPT_PAD_PSS; // fill and pass pad_info
        BCRYPT_PSS_PADDING_INFO pad_info;
        ZeroMemory(&pad_info, sizeof(pad_info));
        pad_info.pszAlgId = BCRYPT_SHA512_ALGORITHM;
        pad_info.cbSalt = 0x12345678;
        pad_info_ptr = &pad_info;
    }
    else if ( padding_type == 3 )
    {
        padding = BCRYPT_SUPPORTED_PAD_PKCS1_ENC;
        pad_info_ptr = NULL;
    }
    else 
    {
        padding = 0;
        pad_info_ptr = NULL;
    }

    status = BCryptEncrypt(
        ctxt->priv_key,
        hash,
        hash_ln,
        pad_info_ptr,
        NULL,
        0,
        NULL,
        0,
        &required_size,
        padding
    );
    if ( !NT_SUCCESS(status) )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptSignHash get size\n", status);
        //PrintCSBackupAPIErrorMessage(status);
#endif
        goto clean;
    }
#ifdef DEBUG_PRINT
    printf("required_size: 0x%x\n", required_size);
#endif

    if ( *signature == NULL )
    {
        *signature = (PUCHAR)malloc(required_size);
        if ( *signature == NULL )
        {
#ifdef ERROR_PRINT
            printf("Error (0x%x): malloc out buffer\n", GetLastError());
            PrintCSBackupAPIErrorMessage(GetLastError());
#endif
            status = STATUS_NO_MEMORY;
            goto clean;
        }
    }
    else
    {
        if ( required_size > *signature_ln )
        {
#ifdef ERROR_PRINT
            printf("Error: Provided plain buffer[0x%x] is too small! 0x%x needed.\n", *signature_ln, required_size);
#endif
            status = STATUS_NO_MEMORY;
            goto clean;
        }
    }
    *signature_ln = required_size;
#ifdef DEBUG_PRINT
    printf("required_size: 0x%x\n", required_size);
#endif
    
    status = BCryptEncrypt(
        ctxt->priv_key,
        hash,
        hash_ln,
        pad_info_ptr,
        NULL,
        0,
        *signature,
        *signature_ln,
        signature_ln,
        padding
    );
    if ( !NT_SUCCESS(status) )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptSignHash\n", status);
        //PrintCSBackupAPIErrorMessage(status);
#endif
        goto clean;
    }

clean:
    ;

    return (int)status;
}

// Public key decryption
// Doesn't work (wrong parameter)
// The wrong parameter seems to be the public key.
// See notation to RSA_sign2
int RSA_verifyHash2(
    PRSA_CTXT ctxt,
    PUCHAR signature,
    ULONG signature_ln,
    PUCHAR* hash,
    PULONG hash_ln
)
{
    ULONG required_size = 0;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG padding;
    PVOID pad_info_ptr = NULL;

    if ( padding_type == 1 )
    {
        padding = BCRYPT_PAD_PKCS1; // random number padding
        BCRYPT_PKCS1_PADDING_INFO pad_info;
        ZeroMemory(&pad_info, sizeof(pad_info));
        pad_info.pszAlgId = BCRYPT_SHA512_ALGORITHM;
        pad_info_ptr = &pad_info;
    }
    else if ( padding_type == 2 )
    {
        padding = BCRYPT_PAD_PSS; // fill and pass pad_info
        BCRYPT_PSS_PADDING_INFO pad_info;
        ZeroMemory(&pad_info, sizeof(pad_info));
        pad_info.pszAlgId = BCRYPT_SHA512_ALGORITHM;
        pad_info.cbSalt = 0x12345678;
        pad_info_ptr = NULL;
    }
    else 
    {
        padding = 0;
        pad_info_ptr = NULL;
    }

    status = BCryptDecrypt(
        ctxt->pub_key,
        signature,
        signature_ln,
        pad_info_ptr,
        NULL,
        0,
        NULL,
        0,
        &required_size,
        padding
    );
    if ( !NT_SUCCESS(status) )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptDecrypt get size\n", status);
        //PrintCSBackupAPIErrorMessage(status);
#endif
        goto clean;
    }
#ifdef DEBUG_PRINT
    printf("required_size: 0x%x\n", required_size);
#endif
    
    
    if ( *hash == NULL )
    {
        *hash = (PUCHAR)malloc(required_size);
        if ( *hash == NULL )
        {
#ifdef ERROR_PRINT
            printf("Error (0x%x): malloc out buffer\n", GetLastError());
            PrintCSBackupAPIErrorMessage(GetLastError());
#endif
            status = STATUS_NO_MEMORY;
            goto clean;
        }
    }
    else
    {
        if ( required_size > *hash_ln )
        {
#ifdef ERROR_PRINT
            printf("Error: Provided plain buffer[0x%x] is too small! 0x%x needed.\n", *hash_ln, required_size);
#endif
            status = STATUS_NO_MEMORY;
            goto clean;
        }
    }
    *hash_ln = required_size;

    if ( signature != *hash )
        RtlZeroMemory(*hash, *hash_ln);

    status = BCryptDecrypt(
        ctxt->pub_key,
        signature,
        signature_ln,
        pad_info_ptr,
        NULL,
        0,
        *hash,
        *hash_ln,
        &required_size,
        padding
    );
    if ( !NT_SUCCESS(status) )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptDecrypt\n", status);
        PrintCSBackupAPIErrorMessage(status);
#endif
        goto clean;
    }
    
clean:
    ;
    return (int)status;
}

int RSA_clean(PRSA_CTXT ctxt)
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
        free(ctxt->padding_info);
        ctxt->padding_info = NULL;
    }

    memset(ctxt, 0, sizeof(*ctxt));

    return 0;
}

NTSTATUS loadFileBytes(
    const CHAR* path, 
    PUCHAR* buffer, 
    PULONG buffer_ln
)
{
    NTSTATUS status = STATUS_SUCCESS;

    HANDLE file = NULL;
    WCHAR wpath[MAX_PATH];
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK iosb;
    UNICODE_STRING uc_path;
    
    char full_path[MAX_PATH];
    int fpl;
    LARGE_INTEGER file_size = {0};

    RtlZeroMemory(&objAttr, sizeof(objAttr));
    RtlZeroMemory(&iosb, sizeof(iosb));
    RtlZeroMemory(wpath, sizeof(wpath));
#ifdef DEBUG_PRINT
    printf("getFileBytes\n");
    printf(" - path: %s\n", path);
#endif
    
    fpl = GetFullPathNameA(path, MAX_PATH, full_path, NULL);
    if (!fpl)
    {
        printf("ERROR (0x%lx): Get full path failed for \"%s\".", GetLastError(), path);
        status = STATUS_OBJECT_NAME_NOT_FOUND;
        goto clean;
    }
#ifdef DEBUG_PRINT
    printf(" - full_path: %s\n", full_path);
#endif

    status = swprintf(wpath, MAX_PATH, L"\\??\\%hs", full_path);
    if ( !NT_SUCCESS(status) )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): RtlStringCchPrintfW\n", status);
#endif
        goto clean;
    }
    wpath[MAX_PATH - 1] = 0;
    RtlInitUnicodeString(&uc_path, wpath);
#ifdef DEBUG_PRINT
    printf(" - uc path: %ws\n", uc_path.Buffer);
#endif

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
    if ( !NT_SUCCESS(status) )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): NtCreateFile\n", status);
#endif
        goto clean;
    }

    fpl = GetFileSizeEx(file, &file_size);
    if (!fpl)
    {
#ifdef ERROR_PRINT
        printf("ERROR (0x%lx): GetFileSizeEx \"%s\".", GetLastError(), path);
#endif
        status = STATUS_OBJECT_NAME_NOT_FOUND;
        goto clean;
    }

    *buffer = (UCHAR*)malloc((SIZE_T)file_size.QuadPart);
    if ( *buffer == NULL )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): malloc key_buffer\n", GetLastError());
        PrintCSBackupAPIErrorMessage(GetLastError());
#endif
        status = STATUS_NO_MEMORY;
        goto clean;
    }

    *buffer_ln = (ULONG)file_size.QuadPart;
    RtlZeroMemory(&iosb, sizeof(iosb));
    ZeroMemory(*buffer, *buffer_ln);
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
    if ( !NT_SUCCESS(status) || !NT_SUCCESS(iosb.Status) )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): NtReadFile\n", status);
#endif
        goto clean;
    }
    if ( (ULONG)iosb.Information > *buffer_ln )
    {
        status = STATUS_UNSUCCESSFUL;
        *buffer_ln = 0;
#ifdef ERROR_PRINT
        printf("Error (0x%x): key_buffer to small. 0x%x needed.\n", status, (ULONG)iosb.Information);
#endif
        goto clean;
    }
    *buffer_ln = (ULONG)iosb.Information;

clean:
    if ( file != NULL )
        NtClose(file);

    return status;
}

NTSTATUS writeFileBytes(
    const CHAR* path, 
    PUCHAR buffer, 
    ULONG buffer_ln
)
{
    NTSTATUS status = STATUS_SUCCESS;

    HANDLE file = NULL;
    WCHAR wpath[MAX_PATH];
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK iosb;
    UNICODE_STRING uc_path;
    
    char full_path[MAX_PATH];
    int fpl;

    RtlZeroMemory(&objAttr, sizeof(objAttr));
    RtlZeroMemory(&iosb, sizeof(iosb));
    RtlZeroMemory(wpath, sizeof(wpath));
#ifdef DEBUG_PRINT
    printf("writeFileBytes\n");
    printf(" - path: %s\n", path);
#endif
    
    fpl = GetFullPathNameA(path, MAX_PATH, full_path, NULL);
    if (!fpl)
    {
        printf("ERROR (0x%lx): Get full path failed for \"%s\".", GetLastError(), path);
        status = STATUS_OBJECT_NAME_NOT_FOUND;
        goto clean;
    }
#ifdef DEBUG_PRINT
    printf(" - full_path: %s\n", full_path);
#endif

    status = swprintf(wpath, MAX_PATH, L"\\??\\%hs", full_path);
    if ( !NT_SUCCESS(status) )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): RtlStringCchPrintfW\n", status);
#endif
        goto clean;
    }
    wpath[MAX_PATH - 1] = 0;
    RtlInitUnicodeString(&uc_path, wpath);
#ifdef DEBUG_PRINT
    printf(" - uc path: %ws\n", uc_path.Buffer);
#endif

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
        FILE_OPEN_IF,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );
    if ( !NT_SUCCESS(status) )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): NtCreateFile\n", status);
#endif
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
    if ( !NT_SUCCESS(status) || !NT_SUCCESS(iosb.Status) )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): NtReadFile\n", status);
#endif
        goto clean;
    }

clean:
    if ( file != NULL )
        NtClose(file);

    return status;
}
