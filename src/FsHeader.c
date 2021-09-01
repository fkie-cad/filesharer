#include "string.h"

#include "FsHeader.h"
#include "debug.h"

FsKeyHeaderOffsets fs_key_header_offsets = {
    .type = 0,
    .secret = 0x8,
    .iv = AES_SECRET_SIZE + 0x8
};

int saveFsKeyHeader(
    PFsKeyHeader h
)
{
//    uint64_t type = FS_TYPE_KEY_HEADER;
//    uint8_t* buffer = (uint8_t*)h;
    int s;
//    memset(buffer, 0, BUFFER_SIZE);

    h->type = FS_TYPE_KEY_HEADER;

    s = generateSecret(h->secret, AES_SECRET_SIZE);
    if ( s != 0 )
    {
        printf("ERROR (0x%x): Generating secret failed!\n", s);
        return s;
    }
//#ifdef DEBUG_PRINT
//    printf("secret                 ");
//    printMemory(h->secret, AES_SECRET_SIZE, 0x10, 0);
//#endif

    s = generateIV(h->iv, AES_IV_SIZE);
    if ( s != 0 )
    {
        printf("ERROR (0x%x): Generating IV failed!\n", s);
        return s;
    }
//#ifdef DEBUG_PRINT
//    printf("iv:");
//    printMemory(h->iv, AES_IV_SIZE, 0x10, 0);
//#endif

    return 0;
}

void printFsKeyHeader(
    PFsKeyHeader h,
    char* prefix
)
{
    uint16_t i;
    printf("%ssecret: ", prefix);
    for ( i = 0; i < AES_SECRET_SIZE; i++ )
        printf("%02x ", h->secret[i]);
    printf("\n");
    printf("%s    iv: ", prefix);
    for ( i = 0; i < AES_IV_SIZE; i++ )
        printf("%02x ", h->iv[i]);
    printf("\n");
}


#if defined(_64BIT)
FsFileHeaderOffsets fs_f_header_offsets = {
    .garbage = 0,
    .type = AES_IV_SIZE,
    .file_size = AES_IV_SIZE + 8,
    .base_name_ln = AES_IV_SIZE + 16,
    .sub_dir_ln = AES_IV_SIZE + 18,
    .hash_ln = AES_IV_SIZE + 20,
    .sub_dir = AES_IV_SIZE + 22,
    .base_name = AES_IV_SIZE + 22, // + sub_dir_ln
    .hash = AES_IV_SIZE + 22
};
#elif defined(_32BIT)
FsFileHeaderOffsets fs_f_header_offsets = {
    .garbage = 0,
    .type = AES_IV_SIZE + 0,
    .file_size = AES_IV_SIZE + 8,
    .base_name_ln = AES_IV_SIZE + 12,
    .sub_dir_ln = AES_IV_SIZE + 14,
    .hash_ln = AES_IV_SIZE + 16,
    .sub_dir = AES_IV_SIZE + 18,
    .base_name = AES_IV_SIZE + 18, // + sub_dir_ln
    .hash = AES_IV_SIZE + 18
};
#endif


size_t saveFsFileHeader(
    uint8_t* buffer,
    PFsFileHeader h
)
{
    uint64_t type = FS_TYPE_FILE_HEADER;
    size_t offset = 0;
    memset(buffer, 0, BUFFER_SIZE);

    if ( fs_f_header_offsets.sub_dir + h->sub_dir_ln + h->base_name_ln + h->hash_ln > BUFFER_SIZE )
    {
#ifdef ERROR_PRINT
        printf("ERROR: Header to big for predefined buffer!\n");
#endif
        return 0;
    }

    memcpy(&buffer[fs_f_header_offsets.garbage], &(h->garbage), AES_IV_SIZE);
    memcpy(&buffer[fs_f_header_offsets.type], &type, sizeof(h->type));
    memcpy(&buffer[fs_f_header_offsets.file_size], &(h->file_size), sizeof(h->file_size));
    memcpy(&buffer[fs_f_header_offsets.base_name_ln], &(h->base_name_ln), sizeof(h->base_name_ln));
    memcpy(&buffer[fs_f_header_offsets.sub_dir_ln], &(h->sub_dir_ln), sizeof(h->sub_dir_ln));
    memcpy(&buffer[fs_f_header_offsets.hash_ln], &(h->hash_ln), sizeof(h->hash_ln));
    memcpy(&buffer[fs_f_header_offsets.sub_dir], h->sub_dir, h->sub_dir_ln);
    offset = fs_f_header_offsets.sub_dir+h->sub_dir_ln;
    memcpy(&buffer[offset], h->base_name, h->base_name_ln);
    offset += h->base_name_ln;
    memcpy(&buffer[offset], h->hash, h->hash_ln);

    return offset + h->hash_ln;
}

/*
 * Load buffer into header. 
 * 
 */
void loadFsFileHeader(
    uint8_t* buffer,
    PFsFileHeader h,
    char* base_name,
    uint16_t base_name_size,
    char* sub_dir,
    uint16_t sub_dir_size,
    uint8_t* hash,
    uint16_t hash_size
)
{
    size_t offset = 0;

    memset(base_name, 0, base_name_size);
    memset(sub_dir, 0, sub_dir_size);
    memset(hash, 0, hash_size);

    //memcpy(&(h->garbage), &buffer[fs_f_header_offsets.garbage], AES_IV_SIZE);
    memcpy(&(h->type), &buffer[fs_f_header_offsets.type], sizeof(h->type));
    memcpy(&(h->file_size), &buffer[fs_f_header_offsets.file_size], sizeof(h->file_size));
    memcpy(&(h->base_name_ln), &buffer[fs_f_header_offsets.base_name_ln], sizeof(h->base_name_ln));
    if (h->base_name_ln >= base_name_size)
        h->base_name_ln = base_name_size - 1;
    memcpy(&(h->sub_dir_ln), &buffer[fs_f_header_offsets.sub_dir_ln], sizeof(h->sub_dir_ln));
    if (h->sub_dir_ln >= sub_dir_size)
        h->sub_dir_ln = sub_dir_size - 1;
    memcpy(&(h->hash_ln), &buffer[fs_f_header_offsets.hash_ln], sizeof(h->hash_ln));
    if (h->hash_ln > hash_size)
        h->hash_ln = hash_size;
    memcpy(sub_dir, (char*)&buffer[fs_f_header_offsets.sub_dir], h->sub_dir_ln);
    offset = fs_f_header_offsets.sub_dir+h->sub_dir_ln;
    memcpy(base_name, (char*)&buffer[offset], h->base_name_ln);
    offset += h->base_name_ln;
    memcpy(hash, &buffer[offset], h->hash_ln);
    h->sub_dir= sub_dir;
    h->base_name = base_name;
    h->hash = hash;
}

void printFsFileHeader(
    PFsFileHeader h,
    char* prefix
)
{
    printf("%sfile_size: 0x%zx\n", prefix, h->file_size);
    printf("%ssub_dir: %.*s (0x%x)\n", prefix, h->sub_dir_ln, h->sub_dir, h->sub_dir_ln);
    printf("%sbase_name: %s (0x%x)\n", prefix, h->base_name, h->base_name_ln);
    if ( h->hash_ln > 0 )
        printHash(h->hash, h->hash_ln, " - hash: ", "\n");
    else
        printf("%scheck_hash: %s\n", prefix, "disabled");
}


FsSigHeaderOffsets fs_sig_header_offsets = {
    .garbage = 0,
    .type = AES_IV_SIZE + 0,
    .sig = AES_IV_SIZE + 8
};


#if defined(_64BIT)
FsAnswerOffsets fs_answer_offsets = {
    .garbage = 0,
    .type = AES_IV_SIZE + 0,
    .info = AES_IV_SIZE + 8,
    .code = AES_IV_SIZE + 16,
    .state = AES_IV_SIZE + 20
};
#elif defined(_32BIT)
FsAnswerOffsets fs_answer_offsets = {
    .garbage = 0,
    .type = AES_IV_SIZE + 0,
    .info = AES_IV_SIZE + 2,
    .code = AES_IV_SIZE + 6,
    .state = AES_IV_SIZE + 10
};
#endif



size_t saveFsAnswer(uint8_t* buffer, PFsAnswer a)
{
    uint64_t type = FS_TYPE_ANSWER;

    memset(buffer, 0, BUFFER_SIZE);
    memcpy(&buffer[fs_answer_offsets.garbage], &(a->garbage), AES_IV_SIZE);
    memcpy(&buffer[fs_answer_offsets.type], &type, sizeof(a->type));
    memcpy(&buffer[fs_answer_offsets.info], &(a->info), sizeof(a->info));
    memcpy(&buffer[fs_answer_offsets.code], &(a->code), sizeof(a->code));
    memcpy(&buffer[fs_answer_offsets.state], &(a->state), sizeof(a->state));

    return fs_answer_offsets.state + sizeof(a->state);
}

int loadFsAnswer(uint8_t* buffer, uint32_t buffer_size, PFsAnswer a)
{
    if ( buffer_size < fs_answer_offsets.state+sizeof(a->state) )
    {
        debug_info("loadFsAnswer::buffer size too small: 0x%x < 0x%x\n", buffer_size, (uint32_t)(fs_answer_offsets.state+sizeof(a->state)));
        return -1;
    }
    //memcpy(&(a->garbage), &buffer[fs_answer_offsets.garbage], AES_IV_SIZE);
    memcpy(&(a->type), &buffer[fs_answer_offsets.type], sizeof(a->type));
    memcpy(&(a->info), &buffer[fs_answer_offsets.info], sizeof(a->info));
    memcpy(&(a->code), &buffer[fs_answer_offsets.code], sizeof(a->code));
    memcpy(&(a->state), &buffer[fs_answer_offsets.state], sizeof(a->state));

    return 0;
}

void printFsAnswer(PFsAnswer a, char* prefix)
{
    printf("%sstate: %u\n", prefix, a->state);
    printf("%scode: %u\n", prefix, a->code);
    printf("%sinfo: 0x%zx\n", prefix, a->info);
}
