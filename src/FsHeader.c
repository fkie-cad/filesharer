#include "string.h"

#include "FsHeader.h"
#include "../shared/print.h"

FsKeyHeaderOffsets fs_key_header_offsets = {
    .type = 0,
    .secret = 8
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
}


#if defined(_64BIT)
FsFileHeaderOffsets fs_f_header_offsets = {
    .type = 0,
    .file_size = 8,
    .parts_block_size = 16,
    .parts_count = 20,
    .parts_rest = 24,
    .base_name_ln = 28,
    .sub_dir_ln = 30,
    .hash_ln = 32,
    .sub_dir = 34,
    .base_name = 34, // + sub_dir_ln
    .hash = 34
};
#elif defined(_32BIT)
FsFileHeaderOffsets fs_f_header_offsets = {
    .type = 0,
    .file_size = 8,
    .parts_block_size = 12,
    .parts_count = 16,
    .parts_rest = 20,
    .base_name_ln = 24,
    .sub_dir_ln = 26,
    .hash_ln = 28,
    .sub_dir = 30,
    .base_name = 30, // + sub_dir_ln
    .hash = 30
};
#endif


size_t saveFsFileHeader(
    uint8_t* buffer,
    uint32_t buffer_size,
    PFsFileHeader h
)
{
    uint64_t type = FS_TYPE_FILE_HEADER;
    size_t offset = 0;
    memset(buffer, 0, BUFFER_SIZE);

    if ( fs_f_header_offsets.sub_dir + h->sub_dir_ln + h->base_name_ln + h->hash_ln > buffer_size )
    {
#ifdef ERROR_PRINT
        printf("ERROR: Header to big for predefined buffer!\n");
#endif
        return 0;
    }

    memcpy(&buffer[fs_f_header_offsets.type], &type, sizeof(h->type));
    memcpy(&buffer[fs_f_header_offsets.file_size], &(h->file_size), sizeof(h->file_size));
    memcpy(&buffer[fs_f_header_offsets.parts_block_size], &(h->parts_block_size), sizeof(h->parts_block_size));
    memcpy(&buffer[fs_f_header_offsets.parts_count], &(h->parts_count), sizeof(h->parts_count));
    memcpy(&buffer[fs_f_header_offsets.parts_rest], &(h->parts_rest), sizeof(h->parts_rest));
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
int loadFsFileHeader(
    uint8_t* buffer,
    size_t buffer_size,
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


    DPrint("buffer_size: 0x%zx\n", buffer_size);
    DPrint("minsize1: 0x%x\n", (fs_f_header_offsets.sub_dir));
    if ( buffer_size < fs_f_header_offsets.sub_dir )
        return -1;
    DPrint("minsize2: 0x%x\n", (fs_f_header_offsets.sub_dir + *(uint16_t*)&buffer[fs_f_header_offsets.sub_dir_ln] + *(uint16_t*)&buffer[fs_f_header_offsets.base_name_ln] + *(uint16_t*)&buffer[fs_f_header_offsets.hash_ln]));
    if ( buffer_size < fs_f_header_offsets.sub_dir + *(uint16_t*)&buffer[fs_f_header_offsets.sub_dir_ln] + *(uint16_t*)&buffer[fs_f_header_offsets.base_name_ln] + *(uint16_t*)&buffer[fs_f_header_offsets.hash_ln] )
        return -1;

    memcpy(&(h->type), &buffer[fs_f_header_offsets.type], sizeof(h->type));
    memcpy(&(h->file_size), &buffer[fs_f_header_offsets.file_size], sizeof(h->file_size));
    memcpy(&(h->parts_block_size), &buffer[fs_f_header_offsets.parts_block_size], sizeof(h->parts_block_size));
    memcpy(&(h->parts_count), &buffer[fs_f_header_offsets.parts_count], sizeof(h->parts_count));
    memcpy(&(h->parts_rest), &buffer[fs_f_header_offsets.parts_rest], sizeof(h->parts_rest));
    memcpy(&(h->base_name_ln), &buffer[fs_f_header_offsets.base_name_ln], sizeof(h->base_name_ln));
    if ( h->base_name_ln >= base_name_size )
        h->base_name_ln = base_name_size - 1;
    memcpy(&(h->sub_dir_ln), &buffer[fs_f_header_offsets.sub_dir_ln], sizeof(h->sub_dir_ln));
    if ( h->sub_dir_ln >= sub_dir_size )
        h->sub_dir_ln = sub_dir_size - 1;
    memcpy(&(h->hash_ln), &buffer[fs_f_header_offsets.hash_ln], sizeof(h->hash_ln));
    if ( h->hash_ln > hash_size )
        h->hash_ln = hash_size;
    memcpy(sub_dir, (char*)&buffer[fs_f_header_offsets.sub_dir], h->sub_dir_ln);
    offset = fs_f_header_offsets.sub_dir + h->sub_dir_ln;
    memcpy(base_name, (char*)&buffer[offset], h->base_name_ln);
    offset += h->base_name_ln;
    memcpy(hash, &buffer[offset], h->hash_ln);
    h->sub_dir= sub_dir;
    h->base_name = base_name;
    h->hash = hash;

    return 0;
}

void printFsFileHeader(
    PFsFileHeader h,
    char* prefix
)
{
    printf("%sfile_size: 0x%zx\n", prefix, h->file_size);
    printf("%spartsBlockSize: 0x%x\n", prefix, h->parts_block_size);
    printf("%spartsNr: 0x%x\n", prefix, h->parts_count);
    printf("%spartsRest: 0x%x\n", prefix, h->parts_rest);
    printf("%ssub_dir: %.*s (0x%x)\n", prefix, h->sub_dir_ln, h->sub_dir, h->sub_dir_ln);
    printf("%sbase_name: %s (0x%x)\n", prefix, h->base_name, h->base_name_ln);
    if ( h->hash_ln > 0 )
        printHash(h->hash, h->hash_ln, " - hash: ", "\n");
    else
        printf("%scheck_hash: %s\n", prefix, "disabled");
}


FsSigHeaderOffsets fs_sig_header_offsets = {
    .type = 0,
    .sig = 8
};


#if defined(_64BIT)
FsAnswerOffsets fs_answer_offsets = {
    .type = 0,
    .info = 8,
    .code = 16,
    .state = 20
};
#elif defined(_32BIT)
FsAnswerOffsets fs_answer_offsets = {
    .type = 0,
    .info = 2,
    .code = 6,
    .state = 10
};
#endif



size_t saveFsAnswer(uint8_t* buffer, PFsAnswer a)
{
    uint64_t type = FS_TYPE_ANSWER;

    memset(buffer, 0, BUFFER_SIZE);
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
        DPrint("loadFsAnswer::buffer size too small: 0x%x < 0x%x\n", buffer_size, (uint32_t)(fs_answer_offsets.state+sizeof(a->state)));
        return -1;
    }
    memcpy(&(a->type), &buffer[fs_answer_offsets.type], sizeof(a->type));
    memcpy(&(a->info), &buffer[fs_answer_offsets.info], sizeof(a->info));
    memcpy(&(a->code), &buffer[fs_answer_offsets.code], sizeof(a->code));
    memcpy(&(a->state), &buffer[fs_answer_offsets.state], sizeof(a->state));

    return 0;
}

void printFsAnswer(PFsAnswer a, char* prefix)
{
    printf("%sstate: %u\n", prefix, a->state);
    printf("%scode: 0x%x\n", prefix, a->code);
    printf("%sinfo: 0x%zx\n", prefix, a->info);
}
