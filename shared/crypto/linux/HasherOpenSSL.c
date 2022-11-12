#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <openssl/md5.h>
#include <openssl/types.h>
#include <openssl/evp.h>

#include "HasherOpenSSL.h"

static void sha256HashString(
	unsigned char hash[SHA256_DIGEST_LENGTH], 
	char output[SHA256_STRING_BUFFER_LN]
);

static void sha1HashString(
	unsigned char hash[SHA_DIGEST_LENGTH], 
	char output[SHA1_STRING_BUFFER_LN]
);

static void md5HashString(
	unsigned char hash[MD5_DIGEST_LENGTH], 
	char output[MD5_STRING_BUFFER_LN]
);


//void hashString(
//	const char* string,
//	char* output,
//    size_t outputSize,
//    uint16_t digestLength,
//    const EVP_MD *mo
//)
//{
//    int b;
//	unsigned char hash[0x40];
//    uint size = digestLength;
//    EVP_MD_CTX *mdctx;
//    mdctx = EVP_MD_CTX_new();
//    if ( mdctx == NULL )
//		return;
//
//    b = EVP_DigestInit_ex(mdctx, mo, NULL);
//	if ( b != 1 )
//    {
//        goto clean;
//    }
//
//    b = EVP_DigestUpdate(mdctx, string, strlen(string));
//    if ( b != 1 )
//    {
//        goto clean;
//    }
//
//    b = EVP_DigestFinal_ex(mdctx, hash, &size);
//	if ( b != 1 )
//    {
//        goto clean;
//    }
//
//	md5HashString(hash, output);
//
//clean:
//    if ( mdctx )
//	    EVP_MD_CTX_free(mdctx);
//}

//static const int CHUNK_SIZE = getpagesize() << 2;
static const int CHUNK_SIZE = 0x1000;


int sha256File(
	const char* path, 
	unsigned char* hash_bytes, 
	uint16_t hash_bytes_size
)
{
	errno = 0;
	FILE* file = fopen(path, "rb");
	if ( !file )
		return 1;

	int s = sha256(file, hash_bytes, hash_bytes_size);

	fclose(file);

	return s;
}

int sha256(
	FILE* file, 
	unsigned char* hash_bytes, 
	uint16_t hash_bytes_size
)
{
    int b;
    int s = 0;
    EVP_MD_CTX *mdctx;
    uint size = hash_bytes_size;
	size_t bytes_read;
	const size_t buf_size = CHUNK_SIZE;
    char* buffer = NULL;

    mdctx = EVP_MD_CTX_new();
    if ( mdctx == NULL )
		return -1;

    b = EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
	if ( b != 1 )
    {
        s = -1;
        goto clean;
    }

	buffer = (char*) malloc(buf_size);
	if ( !buffer ) return -1;

	while ((bytes_read = fread(buffer, 1, buf_size, file)))
	{
        b = EVP_DigestUpdate(mdctx, buffer, bytes_read);
        if ( b != 1 )
        {
            s = -1;
            goto clean;
        }
	}

    b = EVP_DigestFinal_ex(mdctx, hash_bytes, &size);
	if ( b != 1 )
    {
        s = -1;
        goto clean;
    }

clean:
    if ( buffer )
        free(buffer);
    if ( mdctx )
	    EVP_MD_CTX_free(mdctx);

	return s;
}

void sha256String(
	const char* string, 
	char output[SHA256_STRING_BUFFER_LN]
)
{
    int b;
    uint size = SHA256_DIGEST_LENGTH;
	unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *mdctx;

    mdctx = EVP_MD_CTX_new();
    if ( mdctx == NULL )
		return;

    b = EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
	if ( b != 1 )
    {
        goto clean;
    }

    b = EVP_DigestUpdate(mdctx, string, strlen(string));
    if ( b != 1 )
    {
        goto clean;
    }

    b = EVP_DigestFinal_ex(mdctx, hash, &size);
	if ( b != 1 )
    {
        goto clean;
    }

	sha256HashString(hash, output);

clean:
    if ( mdctx )
	    EVP_MD_CTX_free(mdctx);
}


/**
 * Create sha256 hash string from the openssl binary output hash. (e.g., 0xa1 becomes "a1", which uses two characters.)
 *
 * @param   hash unsigned char[SHA256_DIGEST_LENGTH] binary hash from openssl.
 * @param   output char[65] the output hash string, as printable ascii
 */
void sha256HashString(
	unsigned char hash[SHA256_DIGEST_LENGTH], 
	char output[SHA256_STRING_BUFFER_LN]
)
{
	int i;

	for ( i = 0; i < SHA256_DIGEST_LENGTH; i++ )
	{
		sprintf(output + (i * 2), "%02x", hash[i]);
	}

	output[SHA256_STRING_LN] = 0;
}

int sha1File(
	const char* path, 
	unsigned char* hash_bytes,
	uint16_t hash_bytes_size
)
{
	errno = 0;
	FILE* file = fopen(path, "rb");
	if ( !file )
		return 1;

	int s = sha1(file, hash_bytes, hash_bytes_size);

	fclose(file);

	return s;
}

int sha1(
	FILE* file, 
	unsigned char* hash_bytes,
	uint16_t hash_bytes_size
)
{
    int b;
    int s = 0;
    EVP_MD_CTX *mdctx;
    uint size = hash_bytes_size;
	size_t bytes_read;
	const size_t buf_size = CHUNK_SIZE;
    char* buffer = NULL;

    mdctx = EVP_MD_CTX_new();
    if ( mdctx == NULL )
		return -1;

    b = EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL);
	if ( b != 1 )
    {
        s = -1;
        goto clean;
    }

	buffer = (char*) malloc(buf_size);
	if ( !buffer ) return -1;

	while ((bytes_read = fread(buffer, 1, buf_size, file)))
	{
        b = EVP_DigestUpdate(mdctx, buffer, bytes_read);
        if ( b != 1 )
        {
            s = -1;
            goto clean;
        }
	}

    b = EVP_DigestFinal_ex(mdctx, hash_bytes, &size);
	if ( b != 1 )
    {
        s = -1;
        goto clean;
    }

clean:
    if ( buffer )
        free(buffer);
    if ( mdctx )
	    EVP_MD_CTX_free(mdctx);

	return s;
}

void sha1String(
	const char* string, 
	char output[SHA1_STRING_BUFFER_LN]
)
{
    int b;
	unsigned char hash[SHA_DIGEST_LENGTH];
    uint size = SHA256_DIGEST_LENGTH;
    EVP_MD_CTX *mdctx;
    mdctx = EVP_MD_CTX_new();
    if ( mdctx == NULL )
		return;

    b = EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL);
	if ( b != 1 )
    {
        goto clean;
    }

    b = EVP_DigestUpdate(mdctx, string, strlen(string));
    if ( b != 1 )
    {
        goto clean;
    }

    b = EVP_DigestFinal_ex(mdctx, hash, &size);
	if ( b != 1 )
    {
        goto clean;
    }

	sha1HashString(hash, output);

clean:
    if ( mdctx )
	    EVP_MD_CTX_free(mdctx);
}


/**
 * Create sha1 hash string from the openssl binary output hash. (e.g., 0xa1 becomes "a1", which uses two characters.)
 *
 * @param   unsigned char[SHA_DIGEST_LENGTH] binary hash from openssl
 * @param   char[41] the output hash string, as printable ascii, zero-terminated
 */
void sha1HashString(
	unsigned char hash[SHA_DIGEST_LENGTH], 
	char output[SHA1_STRING_BUFFER_LN]
)
{
	int i;

	for ( i = 0; i < SHA_DIGEST_LENGTH; i++ )
	{
		sprintf(output + (i * 2), "%02x", hash[i]);
	}

	output[SHA1_STRING_LN] = 0;
}


int md5File(
	const char* path,
	unsigned char* hash_bytes,
	uint16_t hash_bytes_size
)
{
	errno = 0;
	FILE* file = fopen(path, "rb");
	if ( !file )
		return 1;

	int s = md5(file, hash_bytes, hash_bytes_size);

	fclose(file);

	return s;
}

int md5(
	FILE* file, 
	unsigned char* hash_bytes,
	uint16_t hash_bytes_size
)
{
    int b;
    int s = 0;
    EVP_MD_CTX *mdctx;
    uint size = hash_bytes_size;
	size_t bytes_read;
	const size_t buf_size = CHUNK_SIZE;
    char* buffer = NULL;

    mdctx = EVP_MD_CTX_new();
    if ( mdctx == NULL )
		return -1;

    b = EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
	if ( b != 1 )
    {
        s = -1;
        goto clean;
    }

	buffer = (char*) malloc(buf_size);
	if ( !buffer ) return -1;

	while ((bytes_read = fread(buffer, 1, buf_size, file)))
	{
        b = EVP_DigestUpdate(mdctx, buffer, bytes_read);
        if ( b != 1 )
        {
            s = -1;
            goto clean;
        }
	}

    b = EVP_DigestFinal_ex(mdctx, hash_bytes, &size);
	if ( b != 1 )
    {
        s = -1;
        goto clean;
    }

clean:
    if ( buffer )
        free(buffer);
    if ( mdctx )
	    EVP_MD_CTX_free(mdctx);

	return s;
}


void md5String(
	const char* string, 
	char output[MD5_STRING_BUFFER_LN]
)
{
    int b;
    uint size = MD5_DIGEST_LENGTH;
	unsigned char hash[MD5_DIGEST_LENGTH];
    EVP_MD_CTX *mdctx;
    mdctx = EVP_MD_CTX_new();
    if ( mdctx == NULL )
		return;

    b = EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
	if ( b != 1 )
    {
        goto clean;
    }

    b = EVP_DigestUpdate(mdctx, string, strlen(string));
    if ( b != 1 )
    {
        goto clean;
    }

    b = EVP_DigestFinal_ex(mdctx, hash, &size);
	if ( b != 1 )
    {
        goto clean;
    }

	md5HashString(hash, output);

clean:
    if ( mdctx )
	    EVP_MD_CTX_free(mdctx);
}

/**
 * Create md5 hash string from the openssl binary output hash. (e.g., 0xa1 becomes "a1", which uses two characters.)
 *
 * @param   unsigned char[MD5_DIGEST_LENGTH] binary hash from openssl
 * @param   char[33] the output hash string, as printable ascii, zero-terminated
 */
void md5HashString(
	unsigned char hash[MD5_DIGEST_LENGTH], 
	char output[MD5_STRING_BUFFER_LN]
)
{
	int i;

	for ( i = 0; i < MD5_DIGEST_LENGTH; i++ )
	{
		sprintf(output + (i * 2), "%02x", hash[i]);
	}

	output[MD5_STRING_LN] = 0;
}

void hashToString(
	const unsigned char* hash_bytes, 
	uint16_t hash_size, char* output, 
	uint16_t output_size
)
{
	uint16_t i;

	for ( i = 0; i < hash_size; i++ )
	{
		sprintf(output + (i * 2), "%02x", hash_bytes[i]);
	}

	output[output_size-1] = 0;

}

void printHash(
	const unsigned char* hash_bytes, 
	uint16_t hash_size, 
	const char* prefix, 
	const char* postfix
)
{
	uint16_t i;

	printf("%s", prefix);
	for ( i = 0; i < hash_size; i++ )
	{
		printf("%02x", hash_bytes[i]);
	}
	printf("%s", postfix);
}
