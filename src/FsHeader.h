#ifndef SHARED_FS_HEADER_H
#define SHARED_FS_HEADER_H

#include "env.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "types.h"
#include "values.h"
#if defined(_WIN32)
#include "crypto/windows/HasherCNG.h"
#elif defined(_LINUX)
#include "crypto/linux/HasherOpenSSL.h"
#endif
#include "crypto/crypto.h"

//#define FS_KEY_HEADER_BUFFER_SIZE (AES_SECRET_SIZE + AES_IV_SIZE)
#define FS_KEY_HEADER_SIZE (AES_SECRET_SIZE + AES_IV_SIZE + 0x8)

#define FS_TYPE_KEY_HEADER (0x000056492B59454B)
#define FS_TYPE_FILE_HEADER (0x4F464E49454C4946)
#define FS_TYPE_SIG_HEADER (0x525554414E474953)
#define FS_TYPE_ANSWER (0x0000524557534E41)


// prevent padding
#if defined(_WIN32)
#pragma pack(1)
#endif
typedef struct FsKeyHeader {
    uint64_t type;
    uint8_t secret[AES_SECRET_SIZE];
    uint8_t iv[AES_IV_SIZE];
}
#ifdef _LINUX
__attribute__ ((__packed__))
#endif
FsKeyHeader, * PFsKeyHeader
;
#if defined(_WIN32)
#pragma pack()
#endif

typedef struct FsKeyHeaderOffsets {
    uint16_t secret;
    uint16_t iv;
    uint16_t type;
} FsKeyHeaderOffsets, * PFsKeyHeaderOffsets;
extern FsKeyHeaderOffsets fs_key_header_offsets;

// add initial random garbage to reuse IV
// could be sha256 and then checked
typedef struct FsFileHeader {
    uint8_t garbage[AES_IV_SIZE];
    uint64_t type;
    size_t file_size;
    uint32_t parts_block_size;
    uint32_t parts_count;
    uint32_t parts_rest;
    uint16_t base_name_ln;
    uint16_t sub_dir_ln;
    uint16_t hash_ln;
    const char* sub_dir;
    const char* base_name;
    uint8_t* hash;
} FsFileHeader, * PFsFileHeader;

typedef struct FsFileHeaderOffsets {
    uint16_t garbage;
    uint16_t type;
    uint16_t file_size;
    uint16_t parts_block_size;
    uint16_t parts_count;
    uint32_t parts_rest;
    uint16_t base_name_ln;
    uint16_t sub_dir_ln;
    uint16_t hash_ln;
    uint16_t sub_dir;
    uint16_t base_name;
    uint16_t hash;
} FsFileHeaderOffsets, * PFsHeaderOffsets;

typedef struct FsSigHeader {
    uint8_t garbage[AES_IV_SIZE];
    uint64_t type;
    uint8_t* sig;
} FsSigHeader, * PFsSigHeader;

typedef struct FsSigHeaderOffsets {
    uint8_t garbage;
    uint16_t type;
    uint8_t sig;
} FsSigHeaderOffsets, * PFsSigHeaderOffsets;



//extern FsHeaderOffsets fs_header_offsets;

int saveFsKeyHeader(
    PFsKeyHeader h
);

void printFsKeyHeader(
    PFsKeyHeader h, 
    char* prefix
);

size_t saveFsFileHeader(
    uint8_t* buffer, 
    PFsFileHeader h
);

void loadFsFileHeader(
    uint8_t* buffer, 
    PFsFileHeader h, 
    char* base_name, 
    uint16_t base_name_size, 
    char* sub_dir, 
    uint16_t sub_dir_size, 
    uint8_t* hash, 
    uint16_t hash_size
);

void printFsFileHeader(
    PFsFileHeader h, 
    char* prefix
);





// add initial random garbage to reuse IV
// could be sha256 and the checked
typedef struct FsAnswer {
    uint8_t garbage[AES_IV_SIZE]; // random garbage
    uint64_t type;
    size_t info;
    uint32_t code;
    uint8_t state;
} FsAnswer, * PFsAnswer;

typedef struct FsAnswerOffsets {
    uint8_t garbage;
    uint16_t type;
    uint8_t info;
    uint8_t code;
    uint8_t state;
} FsAnswerOffsets, *PFsAnswerOffsets;

#if defined(_WIN64) || defined(_LINUX)
#define FS_ANSWER_SEND_SIZE (10)
#elif defined(_WIN32)
#define FS_ANSWER_SEND_SIZE (6)
#endif



//extern FsAnswerOffsets fs_answer_offsets;



size_t saveFsAnswer(
    uint8_t* buffer, 
    PFsAnswer h
);

int loadFsAnswer(
    uint8_t* buffer, 
    uint32_t buffer_size, 
    PFsAnswer h
);

void printFsAnswer(
    PFsAnswer h, 
    char* prefix
);

#endif
