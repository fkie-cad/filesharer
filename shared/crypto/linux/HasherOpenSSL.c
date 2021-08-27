#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <openssl/md5.h>

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
	SHA256_CTX sha256;
	SHA256_Init(&sha256);

	size_t bytes_read;
	const size_t buf_size = CHUNK_SIZE;
	char* buffer = (char*) malloc(buf_size);
	if ( !buffer ) return -1;

	while ((bytes_read = fread(buffer, 1, buf_size, file)))
	{
		SHA256_Update(&sha256, buffer, bytes_read);
	}

	SHA256_Final(hash_bytes, &sha256);

	free(buffer);

	return 0;
}

void sha256String(
	const char* string, 
	char output[SHA256_STRING_BUFFER_LN]
)
{
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, string, strlen(string));
	SHA256_Final(hash, &sha256);

	sha256HashString(hash, output);
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
	char output[SHA1_STRING_BUFFER_LN]
)
{
	errno = 0;
	FILE* file = fopen(path, "rb");
	if ( !file )
		return 1;

	int s = sha1(file, output);

	fclose(file);

	return s;
}

int sha1(
	FILE* file, 
	char* output
)
{
	unsigned char hash[SHA_DIGEST_LENGTH];
	SHA_CTX sha1;
	SHA1_Init(&sha1);

	size_t bytes_read;
	char* buffer = (char*) malloc(CHUNK_SIZE);
	if ( !buffer ) return -1;

	while ((bytes_read = fread(buffer, 1, CHUNK_SIZE, file)))
	{
		SHA1_Update(&sha1, buffer, bytes_read);
	}

	SHA1_Final(hash, &sha1);
	sha1HashString(hash, output);

	free(buffer);

	return 0;
}

void sha1String(
	const char* string, 
	char output[SHA1_STRING_BUFFER_LN]
)
{
	unsigned char hash[SHA_DIGEST_LENGTH];
	SHA_CTX sha1;
	SHA1_Init(&sha1);
	SHA1_Update(&sha1, string, strlen(string));
	SHA1_Final(hash, &sha1);

	sha1HashString(hash, output);
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
	char* output
)
{
	errno = 0;
	FILE* file = fopen(path, "rb");
	if ( !file )
		return 1;

	int s = md5(file, output);

	fclose(file);

	return s;
}

int md5(
	FILE* file, 
	char* output
)
{
	unsigned char hash[MD5_DIGEST_LENGTH];
	MD5_CTX md5;
	MD5_Init(&md5);

	size_t bytes_read;
	const int buf_size = CHUNK_SIZE;
	char* buffer = (char*) malloc(buf_size);
	if ( !buffer ) return -1;

	while ((bytes_read = fread(buffer, 1, buf_size, file)))
	{
		MD5_Update(&md5, buffer, bytes_read);
	}

	MD5_Final(hash, &md5);
	md5HashString(hash, output);

	free(buffer);

	return 0;
}


void md5String(
	const char* string, 
	char output[MD5_STRING_BUFFER_LN]
)
{
	unsigned char hash[MD5_DIGEST_LENGTH];
	MD5_CTX md5;
	MD5_Init(&md5);
	MD5_Update(&md5, string, strlen(string));
	MD5_Final(hash, &md5);

	md5HashString(hash, output);
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
