#ifndef SHARED_HASHER_OEPN_SSL_H
#define SHARED_HASHER_OEPN_SSL_H

#include <stdio.h>
#include <stdint.h>
#include <openssl/sha.h>



#define MD5_STRING_LN 32
#define MD5_STRING_BUFFER_LN 33
#define SHA1_STRING_LN 40
#define SHA1_STRING_BUFFER_LN 41

#define SHA256_BYTES_LN SHA256_DIGEST_LENGTH
#define SHA256_STRING_LN 64
#define SHA256_STRING_BUFFER_LN 65

/**
 * Create sha256 hash of a given file.
 * Using a FILE* to open the file.
 *
 * @param   path char* the input file path
 * @param   hash_bytes unsigned char* The hash buffer of size min SHA256_BYTES_LN (0x20).
 * @param   hash_bytes_size uint16_t Size of the hash buffer. Min. SHA256_BYTES_LN.
 * @return  int the success state
 */
int sha256File(
    const char* path, 
    unsigned char* hash_bytes, 
    uint16_t hash_bytes_size
);

/**
 * Create sha256 hash of a given file.
 *
 * @param   file FILE* the input file
 * @param   hash_bytes unsigned char* The hash buffer of size min SHA256_BYTES_LN (0x20).
 * @param   hash_bytes_size uint16_t Size of the hash buffer. Min. SHA256_BYTES_LN.
 * @return  int the success state
 */
int sha256(
    FILE* fp, 
    unsigned char* hash_bytes, 
    uint16_t hash_bytes_size
);

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

/**
 * Create sha1 hash of a given file.
 *
 * @param   file FILE* the input file
 * @param   output char[41] theallocated o output hash string
 * @return  int the success state
 */
int sha1(
    FILE* fp, 
	unsigned char* hash_bytes,
	uint16_t hash_bytes_size
);

///**
// * Create sha1 hash of a given string.
// *
// * @param   string char* the input string
// * @param   output char[41] the allocated output hash string
// */
//static void sha1String(const char* string, char* output);

/**
 * Create md5 hash of a given file.
 * Using a FILE* to open the file.
 *
 * @param   path char* the input file path
 * @param   output char[33] the output hash string
 * @return  int the success state
 */
int md5File(
    const char* path, 
	unsigned char* hash_bytes,
	uint16_t hash_bytes_size
);

/**
 * Create md5 hash of a given file.
 *
 * @param   file FILE* the input file
 * @param   output char[33] the output hash string
 * @return  int the success state
 */
int md5(
    FILE* fp, 
	unsigned char* hash_bytes,
	uint16_t hash_bytes_size
);

///**
// * Create md5 hash of a given string.
// *
// * @param   string char* the input string
// * @param   output char[33] the output hash string
// */
//static void md5String(const char* string, char* output);

/**
 * Convert hash bytes to ascii string.
 *
 * @param   hash unsigned char* The input hash bytes.
 * @param   hash_size uint16_t Size of the hash_bytes.
 * @param   output char* The output hash string.
 * @param   output_size uint16_t Size of the output buffer. Should be at least hash_size*2+1.
 */
void hashToString(
    const unsigned char* hash_bytes, 
    uint16_t hash_size, 
    char* output, 
    uint16_t output_size
);

/**
 * Print hash bytes.
 *
 * @param hash unsigned char* The input hash bytes.
 * @param hash_size uint16_t Size of the hash_bytes.
 * @param prefix char* The prefix.
 * @param post char* The postfix.
 */
void printHash(
    const unsigned char* hash_bytes, 
    uint16_t hash_size, 
    const char* prefix, 
    const char* postfix
);


#endif
