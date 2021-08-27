#ifndef SHARED_HASHER_CNG_H
#define SHARED_HASHER_CNG_H

#include <windows.h>
#include <bcrypt.h>

#include <stdint.h>

//#define MD5_STRING_LN 32
//#define MD5_STRING_BUFFER_LN 33
//#define SHA1_STRING_LN 40
//#define SHA1_STRING_BUFFER_LN 41
#define SHA256_BYTES_LN 32
#define SHA256_STRING_LN 64
#define SHA256_STRING_BUFFER_LN 65


typedef struct Sha256Ctxt {
    BCRYPT_ALG_HANDLE alg;
    BCRYPT_HASH_HANDLE hash;
    NTSTATUS status;
    DWORD data_size;
    DWORD hash_size;
    DWORD hash_object_size;
    PBYTE hash_object;
} Sha256Ctxt, * PSha256Ctxt;


int initSha256(PSha256Ctxt ctxt);

int cleanSha256(PSha256Ctxt ctxt);


/**
 * Create sha256 hash of a given file.
 * Using a FILE* to open the file.
 *
 * @param   path char* the input file path
 * @param   hash_bytes unsigned char* The input hash bytes
 * @param   hash_size DWORD Size of the hash_bytes.
 * @return  int the success state
 */
int sha256File(
    const char* path, 
    unsigned char* hash_bytes, 
    uint16_t hash_bytes_size
);


/**
 * Create sha256 hash of a given file.
 * Using a FILE* to open the file.
 *
 * @param   path char* the input file path
 * @param   hash_bytes unsigned char* The input hash bytes
 * @param   hash_size DWORD Size of the hash_bytes.
 * @return  ctxt PSha256Ctxt initialized Sha256Ctxt
 * @return  int the success state
 */
int sha256FileC(
    const char* path, 
    unsigned char* hash_bytes, 
    uint16_t hash_bytes_size, 
    PSha256Ctxt ctxt
);

/**
 * Create sha256 hash of a given buffer.
 *
 * @param   buffer uint8_t* the input buffer
 * @param   buffer_ln uint32_t size of buffer
 * @param   unsigned char* hash_bytes, 
 * @param   hash_bytes_size DWORD Size of the hash_bytes.
 * @return  int the success state
 */
int sha256Buffer(
    uint8_t* buffer, 
    uint32_t buffer_ln, 
    unsigned char* hash_bytes, 
    uint16_t hash_bytes_size
);

/**
 * Create sha256 hash of a given buffer.
 *
 * @param   buffer uint8_t* the input buffer
 * @param   buffer_ln uint32_t size of buffer
 * @param   unsigned char* hash_bytes, 
 * @param   hash_bytes_size DWORD Size of the hash_bytes.
 * @return  ctxt PSha256Ctxt initialized Sha256Ctxt
 * @return  int the success state
 */
int sha256BufferC(
    uint8_t* buffer, 
    uint32_t buffer_ln, 
    unsigned char* hash_bytes, 
    uint16_t hash_bytes_size, 
    PSha256Ctxt ctxt
);

/**
 * Convert hash bytes to ascii string.
 *
 * @param   hash unsigned char* The input hash bytes
 * @param   hash_size uint16_t Size of the hash_bytes.
 * @param   output char* The output hash string
 * @param   output_size uint16_t The outout buffer size. Should be at least hash_size*2 + 1.
 */
void hashToString(
    const unsigned char* hash, 
    uint16_t hash_size, 
    char* output, 
    uint16_t output_size
);

/**
 * Print the hash to stdout.
 *
 * @param   hash unsigned char* The input hash bytes
 * @param   hash_size uint16_t Size of the hash_bytes.
 * @param   prefix char* A Prefix.
 * @param   postfix char* A Postfix.
 */
void printHash(
    const unsigned char* hash, 
    uint16_t hash_size, 
    const char* prefix, 
    const char* postfix
);

///**
// * Create sha256 hash of a given file.
// *
// * @param   file FILE* the input file
// * @param   output char[65] the output hash string
// * @return  int the success state
// */
//int sha256(FILE* fp, char* output);
//
///**
// * Create sha256 hash of a given string.
// *
// * @param   string char* the input string
// * @param   output char[65] the output hash string
// */
//static void sha256String(const char* string, char* output);

///**
// * Create sha1 hash of a given file.
// * Using a FILE* to open the file.
// *
// * @param   path char* the input file path
// * @param   output char[41] theallocated o output hash string
// * @return  int the success state
// */
//int sha1File(const char* path, char* output);
//
///**
// * Create sha1 hash of a given file.
// *
// * @param   file FILE* the input file
// * @param   output char[41] theallocated o output hash string
// * @return  int the success state
// */
//int sha1(FILE* fp, char* output);
//
///**
// * Create sha1 hash of a given string.
// *
// * @param   string char* the input string
// * @param   output char[41] the allocated output hash string
// */
//static void sha1String(const char* string, char* output);
//
///**
// * Create md5 hash of a given file.
// * Using a FILE* to open the file.
// *
// * @param   path char* the input file path
// * @param   output char[33] the output hash string
// * @return  int the success state
// */
//int md5File(const char* path, char* output);
//
///**
// * Create md5 hash of a given file.
// *
// * @param   file FILE* the input file
// * @param   output char[33] the output hash string
// * @return  int the success state
// */
//int md5(FILE* fp, char* output);
//
///**
// * Create md5 hash of a given string.
// *
// * @param   string char* the input string
// * @param   output char[33] the output hash string
// */
//static void md5String(const char* string, char* output);

#endif
