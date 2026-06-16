#include "env.h"

#if defined(_WIN32)
    #include "warnings.h"
    #include "net/winSock.h"
#elif defined(_LINUX)
    #include "net/linSock.h"
#endif
#include "net/sock.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#if defined(_LINUX)
#include <errno.h>
#endif



#include "types.h"
#include "../shared/print.h"
#if defined(_WIN32)
#include "files/filesW.h"
#include "crypto/windows/HasherCNG.h"
#elif defined(_LINUX)
#include "files/FilesL.h"
#include "crypto/linux/HasherOpenSSL.h"
#endif
#include "crypto/crypto.h"
#include "FsHeader.h"
#include "flags.h"

// callback params struct for directory sharing
typedef struct _FCBParams {
    SOCKET sock;
    const char* start_dir;
    uint16_t flags;
    bool killed;
} FCBParams, *PFCBParams;


#define APP_NAME "FsClient"


static uint8_t gBuffer[BUFFER_SIZE];
static uint32_t enc_block_buffer_size = STD_BLOCK_SIZE; // has to be \in [PAGE_SIZE, ULONG_MAX]



int sendFile(
    const char* file_path, 
    const char* base_name, 
    uint16_t sd_id, 
    uint16_t sd_ln, 
    SOCKET s, 
    uint16_t flags
);

int sendBytes(
    SOCKET sock, 
    uint8_t* buffer, 
    size_t* data_bytes_sent, 
    uint32_t bytes_size, 
    size_t data_full_size
);

int loadBlockIntoBuffer(
    FILE* file, 
    size_t offset, 
    uint8_t* buffer, 
    uint32_t read_size, 
    uint32_t buffer_size, 
    bool is_encrypted
);

int sendDir(
    const char* dir_path, 
    SOCKET s, 
    uint16_t flags
);

void fileCB(
    char* file, 
    char* base_name, 
    void* p
);

bool receiveAnswer(
    PFsAnswer answer, 
    SOCKET sock, 
    bool is_encrypted
);



int runClient(
    int argc,
    char** argv,
    int start_i,
    uint32_t block_size,
    SOCKET sock,
    PADDRINFOA addr_info,
    uint16_t flags
)
{
    FEnter();
    
    bool s = 0;
    size_t cb = 0;

    int nr_of_files;
    int i;
    int j;

    char path[MAX_PATH];
    char* base_name = NULL;
    
    if ( start_i >= argc )
        return -1;

    nr_of_files = argc - start_i;
    enc_block_buffer_size = block_size;



    //
    // check block size

    if ( enc_block_buffer_size < BUFFER_SIZE )
    {
        enc_block_buffer_size = BUFFER_SIZE;
        printf("Block size too small! Setting to 0x%x!\n", enc_block_buffer_size);
    }

    //if ( enc_block_buffer_size > UINT32_MAX )
    //{
    //    enc_block_buffer_size = STD_BLOCK_SIZE;
    //    printf("Block size too big! Setting to 0x%x!\n", enc_block_buffer_size);
    //}

    printf("\n");


    //
    // connect

    s = connectSock(sock, addr_info);
    if ( s != 0 )
    {
        goto clean;
    }



    //
    // file loop

    for ( i = start_i, j=1; i < argc; i++, j++ )
    {
        DPrint("argv[%d]: %s\n", i, argv[i]);
        printf("Path %d / %d : %s\n", j, nr_of_files, argv[i]);

        if ( strnlen(argv[i], MAX_PATH) >= MAX_PATH )
            argv[i][MAX_PATH - 1] = 0;
        
        memset(path, 0, MAX_PATH);
        cb = getFullPathName(argv[i], MAX_PATH, path, &base_name);
        if ( !cb )
        {
            s = getLastError();
            EPrintP("Get full path failed! (0x%x)\n", s);
            break;
        }
        cropTrailingSlash(path);
        DPrint(" - path: %s\n", path);
        DPrint(" - base_name: %s\n", base_name);

        if ( fileExists(path) )
            sendFile(path, base_name, 0, 0, sock, flags);
        else if ( dirExists(path) )
            sendDir(path, sock, flags);
        else {
            EPrintP("Path \"%s\" does not exist! (0x%x)\n", path, -1); }
//        if ( !s )
//            break;
    }

    printf("Bye.\n");

clean:
    shutdown(sock, SD_BOTH);

    FLeave();
    return s;
}

int sendFile(const char* file_path, const char* base_name, uint16_t sd_id, uint16_t sd_ln, SOCKET sock, uint16_t flags)
{
    sendlen_t bytes_sent;
    size_t file_bytes_sent;

    FsKeyHeader key_header;
    FsFileHeader file_header;
    FsAnswer answer;
    uint8_t* buffer_ptr = NULL;

    bool is_encrypted = IS_ENCRYPTED(flags);
    uint32_t header_size;
    size_t buffer_size;
    size_t send_size;
    int errsv;
    int s;

    uint32_t send_part_i;
    uint32_t send_parts_count;
    uint32_t send_parts_rest;

    size_t enc_file_size = 0;
    uint32_t enc_part_i;
    uint32_t enc_parts;
    uint32_t enc_rest;
    uint32_t enc_data_max_size = 0;
    
    FILE* file = NULL;
    uint8_t* file_buffer = NULL;
    size_t file_offset;
    uint32_t sb_offset;

    uint8_t hash[SHA256_BYTES_LN];
    uint8_t iv[AES_IV_SIZE];

    uint32_t gBuffer_file_header_offset = 0;
    uint8_t* gBuffer_file_header_ptr = NULL;
    uint32_t gBuffer_rest_size = BUFFER_SIZE;

    printf("send: %s\n", file_path);
    
    memset(&key_header, 0, sizeof(key_header));
    memset(&file_header, 0, sizeof(file_header));

    if ( flags&FLAG_CHECK_FILE_HASH )
    {
        memset(hash, 0, SHA256_BYTES_LN);
        printf("Calculating hash...");
        s = sha256File(file_path, hash, SHA256_BYTES_LN);
        if ( s != 0 )
        {
            EPrintP("Calculating hash failed! (0x%x)\n", s);
            goto exit;
        }
        printf("\r");
    }
    
    

    // 
    // file and block size calculations

    s = getFileSize(file_path, &file_header.file_size);
    if ( s != 0 || file_header.file_size == 0 )
    {
        printf("INFO: File size is 0!\n");
        if ( s == 0 ) s = -1;
        goto exit;
    }


    //
    // send RSA encrypted key header (AES secret)

    if ( is_encrypted )
    {
        s = saveFsKeyHeader(&key_header);
        if ( s != 0 )
        {
            EPrintP("saveFsKeyHeader failed! (0x%x)\n", s);
            goto exit;
        }

        s = generateAESKey(key_header.secret, AES_SECRET_SIZE);
        if ( s != 0 )
        {
            EPrintP("Generating AES key failed! (0x%x)\n", s);
            goto exit;
        }

#ifdef DEBUG_PRINT
        DPrint("key header:\n");
        printFsKeyHeader(&key_header, " - ");
#endif

        buffer_size = BUFFER_SIZE;
        buffer_ptr = (uint8_t*)gBuffer;
        s = encryptKey(
            (uint8_t*)&key_header, 
            FS_KEY_HEADER_SIZE,
            &buffer_ptr, 
            (uint32_t*)&buffer_size
        );
        if ( s != 0 )
        {
            EPrintP("Encrypting key header failed! (0x%x)\n", s);
            goto exit;
        }
        DPrint("encrypted key header\n");
        DPrintMemCol8(gBuffer, buffer_size,  0);

        bytes_sent = send(sock, (char*)gBuffer, (int)buffer_size, 0);
        if ( bytes_sent < 0 )
        {
            errsv = getLastSError();
            EPrintP("Send header failed! (0x%x)\n", errsv);
            s = -1;
            goto exit;
        }
        DPrint("Bytes sent 0x%x\n", (int)bytes_sent);
        DPrint("Waiting for answer.\n");

        // Wait for key-header-received answer from server to keep it separated
        s = receiveAnswer(&answer, sock, is_encrypted);
        if ( s != 0 )
        {
            goto exit;
        }
        DPrint("Answer OK.\n");
        DPrint("Sending file header.\n");
    }
    
    if ( is_encrypted )
    {
        enc_data_max_size = enc_block_buffer_size - AES_STD_BLOCK_SIZE - AES_IV_SIZE; // -AES_STD_BLOCK_SIZE for padding
        enc_parts = (uint32_t)(file_header.file_size / enc_data_max_size);
        enc_rest = (uint32_t)(file_header.file_size % enc_data_max_size);
        enc_file_size = ( enc_parts * (size_t)enc_block_buffer_size ) + GET_ENC_AES_SIZE(enc_rest) + AES_IV_SIZE;

        gBuffer_file_header_offset = AES_IV_SIZE;
        gBuffer_file_header_ptr = &gBuffer[gBuffer_file_header_offset];
        gBuffer_rest_size -= AES_IV_SIZE;
    }
    else
    {
        enc_data_max_size = enc_block_buffer_size;
        enc_parts = (uint32_t)(file_header.file_size / enc_data_max_size);
        enc_rest = (uint32_t)(file_header.file_size % enc_data_max_size);
        enc_file_size = file_header.file_size;
        
        gBuffer_file_header_ptr = &gBuffer[0];
        //gBuffer_file_header_offset = 0;
        //gBuffer_rest_size = BUFFER_SIZE;
    }

    DPrint("enc_data_max_size: 0x%x\n", enc_data_max_size);
    DPrint("enc_file_size: 0x%zx\n", enc_file_size);
    DPrint("enc_parts: 0x%x\n", enc_parts);
    DPrint("enc_rest: 0x%x\n", enc_rest);
    DPrint("gBuffer_rest_size: 0x%x\n", gBuffer_rest_size);
    DPrint("gBuffer_file_header_offset: 0x%x\n", gBuffer_file_header_offset);
    DPrint("gBuffer_file_header_ptr: %p\n", gBuffer_file_header_ptr);

    //
    // send file header

    if ( is_encrypted )
    {
        //
        // generate iv for file header

        s = generateIV(iv, AES_IV_SIZE);
        if ( s != 0 )
        {
            EPrintP("Generating IV failed! (0x%x)\n", s);
            goto exit;
        }
        // prefix data with iv
        memcpy(gBuffer, iv, AES_IV_SIZE);
    }
    // fill file header
    file_header.parts_block_size = enc_block_buffer_size;
    file_header.parts_count = enc_parts;
    file_header.parts_rest = ( is_encrypted ) ? GET_ENC_AES_SIZE(enc_rest) + AES_IV_SIZE : enc_rest;
    file_header.hash_ln = (flags&FLAG_CHECK_FILE_HASH) ? SHA256_BYTES_LN : 0;
    file_header.hash = (flags&FLAG_CHECK_FILE_HASH) ? hash : NULL;
    file_header.base_name_ln = (uint16_t)strlen(base_name);
    file_header.sub_dir_ln = sd_ln;
    file_header.sub_dir = &file_path[sd_id];
    file_header.base_name = (char*)base_name;
    header_size = (uint32_t)saveFsFileHeader(gBuffer_file_header_ptr, gBuffer_rest_size, &file_header);
    printf("header (0x%x):                \n", header_size);
    printFsFileHeader(&file_header, " - ");
    
    // encrypt file header
    if ( is_encrypted )
    {
        DPrint("file header\n");
        DPrintMemCol8(gBuffer_file_header_ptr, header_size, 0);

        buffer_size = gBuffer_rest_size;
        //buffer_ptr = gBuffer_file_header_ptr;
        s = encryptData(
            gBuffer_file_header_ptr, 
            header_size, 
            &gBuffer_file_header_ptr, 
            (uint32_t*)&buffer_size, 
            iv, 
            AES_IV_SIZE
        );
        if ( s != 0 )
        {
            EPrintP("\nEncrypting file header failed! (0x%x)\n", s);
            goto exit;
        }
        DPrint("encrypted file header (0x%zx)\n", buffer_size);
        DPrintMemCol8(gBuffer_file_header_ptr, (uint32_t)buffer_size, 0);
        send_size = AES_IV_SIZE + buffer_size;
    }
    else
    {
        send_size = header_size;
    }
    
    DPrint("header_size: 0x%x\n", header_size);
    DPrint("send_size: 0x%zx\n", send_size);
    bytes_sent = send(sock, (char*)gBuffer, (int)send_size, 0);
    if ( bytes_sent < 0 )
    {
        errsv = getLastSError();
        EPrintP("Send header failed! (0x%x)\n", errsv);
        s = -1;
        goto exit;
    }
    DPrint("bytes sent: 0x%x\n", (int)bytes_sent);
    DPrint("Waiting for answer.\n");

    // Wait for header-received answer from server to keep it separated from file
    s = receiveAnswer(&answer, sock, is_encrypted);
    if ( s != 0 )
    {
        goto exit;
    }
    DPrint("Answer OK.\n");
    DPrint("Sending file.\n");



    //
    // send file parts

    // create file buffer
    buffer_size = (file_header.file_size > enc_data_max_size) 
                    ? enc_block_buffer_size 
                    : GET_ENC_AES_SIZE(file_header.file_size) + AES_IV_SIZE;
    file_buffer = (uint8_t*)malloc(buffer_size);
    if ( file_buffer == NULL )
    {
        EPrintP("malloc file_buffer failed! (0x%x)\n", getLastError());
        s = -1;
        goto exit;
    }
    DPrint("buffer of 0x%zx bytes allocated.\n", buffer_size);
    
    
    // open file
    errno = 0;
    file = fopen(file_path, "rb");
    errsv = errno;
    if ( file == NULL )
    {
        EPrintP("Can't open file \"%s\"! (0x%x)\n", file_path, errsv);
        s = -2;
        goto exit;
    }


    //SYSTEMTIME time = {0};
    //GetSystemTime(&time);
    //printf("time: %02u:%02u:%02u:%03u\n", time.wHour, time.wMinute, time.wSecond, time.wMilliseconds);

    // encrypt parts and send
    file_offset = 0;
    file_bytes_sent = 0;
    for ( enc_part_i = 0; enc_part_i < enc_parts; enc_part_i++ )
    {
        DPrint("block: 0x%x\n", enc_part_i);
        DPrint("file_offset: 0x%zx\n", file_offset);
        
        s = loadBlockIntoBuffer(file, file_offset, file_buffer, enc_data_max_size, (uint32_t)buffer_size, is_encrypted);
        if ( s != 0 )
        {
            s = -3;
            goto exit;
        }

        // send encrypted block in network chunks of BUFFER_SIZE
        send_parts_count = (uint32_t)(buffer_size / BUFFER_SIZE);
        send_parts_rest = (uint32_t)(buffer_size % BUFFER_SIZE);
        sb_offset = 0;
        for ( send_part_i = 0; send_part_i < send_parts_count; send_part_i++ )
        {
            s = sendBytes(sock, &file_buffer[sb_offset], &file_bytes_sent, BUFFER_SIZE, enc_file_size);
            if ( s != 0 )
            {
                goto exit;
            }
            sb_offset += BUFFER_SIZE;
        }
                
        if ( send_parts_rest != 0 )
        {
            s = sendBytes(sock, &file_buffer[sb_offset], &file_bytes_sent, send_parts_rest, enc_file_size);
            if ( s != 0 )
            {
                goto exit;
            }
        }
    
        DPrint("waiting for part 0x%x received answer.\n", enc_part_i);
        // Wait for enc_block-received answer from server
        s = receiveAnswer(&answer, sock, is_encrypted);
        if ( s != 0 )
        {
            goto exit;
        }

        file_offset += enc_data_max_size;
    }
    if ( enc_rest > 0 )
    {
        DPrint("rest\n");
        DPrint("file_offset: 0x%zx\n", file_offset);
        
        s = loadBlockIntoBuffer(file, file_offset, file_buffer, enc_rest, (uint32_t)buffer_size, is_encrypted);
        if ( s != 0 )
        {
            goto exit;
        }
        
        if ( is_encrypted )
            enc_rest = GET_ENC_AES_SIZE(enc_rest) + AES_IV_SIZE;
        
        // send encrypted block in network chunks of BUFFER_SIZE
        send_parts_count = (uint32_t)(enc_rest / BUFFER_SIZE);
        send_parts_rest = (uint32_t)(enc_rest % BUFFER_SIZE);
        sb_offset = 0;
        for ( send_part_i = 0; send_part_i < send_parts_count; send_part_i++ )
        {
            s = sendBytes(sock, &file_buffer[sb_offset], &file_bytes_sent, BUFFER_SIZE, enc_file_size);
            if ( s != 0 )
            {
                goto exit;
            }
            sb_offset += BUFFER_SIZE;
        }
        
        if ( send_parts_rest != 0 )
        {
            s = sendBytes(sock, &file_buffer[sb_offset], &file_bytes_sent, send_parts_rest, enc_file_size);
            if ( s != 0 )
            {
                goto exit;
            }
        }
        
        // Wait for enc_block-received answer from server
        DPrint("waiting for rest received answer.\n");
        s = receiveAnswer(&answer, sock, is_encrypted);
        if ( s != 0 )
        {
            goto exit;
        }
    }
    
    
    // does not work, if block answer is sent without intermediate wait for other sides's response,
    // because the two answers (block answer, and fully-received answer) might be buffered and sent at once.
//    // wait for file-fully-received answer
//    DPrint("waiting for fully received answer.\n");
//    s = receiveAnswer(&answer, sock, is_encrypted);
//    if ( s != 0 )
//    {
//        goto exit;
//    }

    //GetSystemTime(&time);
    //printf("\ntime: %02u:%02u:%02u:%03u\n", time.wHour, time.wMinute, time.wSecond, time.wMilliseconds);

exit:
    printf("\n\n");
    if ( file )
        fclose(file);
    file = NULL;
    if ( file_buffer != NULL )
        free(file_buffer);
    file_buffer = NULL;
    memset(&key_header, 0, sizeof(key_header));
    delete_AESKey();

    return s;
}

int sendBytes(SOCKET sock, uint8_t* buffer, size_t* data_bytes_sent, uint32_t bytes_size, size_t data_full_size)
{
    FEnter();
    sendlen_t bytes_sent;
    uint32_t pc;

    bytes_sent = send(sock, (char*)buffer, bytes_size, 0);
    if ( bytes_sent <= 0 || (uint32_t)bytes_sent != bytes_size )
    {
        EPrintP("Send file bytes failed! (0x%x)\n", getLastSError());
        FLeave();
        return -1;
    }

    *data_bytes_sent += bytes_sent;
    pc = (uint32_t)((*data_bytes_sent) * 100 / data_full_size);
#ifdef DEBUG_PRINT
    DPrint("Bytes sent: 0x%zx/0x%zx (%u%%).\n", *data_bytes_sent, (size_t)data_full_size, pc);
#else
    printf("Bytes sent: 0x%zx/0x%zx (%u%%).\r", *data_bytes_sent, (size_t)data_full_size, pc);
#endif

    FLeave();
    return 0;
}

int loadBlockIntoBuffer(FILE* file, size_t offset, uint8_t* buffer, uint32_t read_size, uint32_t buffer_size, bool is_encrypted)
{
    FEnter();
    int errsv;
    size_t bytes_read;
    int s = 0;
    uint8_t iv[AES_IV_SIZE];

    size_t data_offset = (is_encrypted) ? AES_IV_SIZE : 0;
    uint8_t* data_ptr = (is_encrypted) ? &buffer[data_offset] : buffer;
    uint32_t buffer_rest_size = (is_encrypted) ? buffer_size - AES_IV_SIZE : buffer_size;
    
    DPrint("file: %p\n", file);
    DPrint("offset: 0x%zx\n", offset);
    DPrint("buffer: %p\n", buffer);
    DPrint("read_size: 0x%x\n", read_size);
    DPrint("buffer_size: 0x%x\n", buffer_size);
    DPrint("is_encrypted: 0x%x\n", is_encrypted);
    DPrint("buffer_rest_size: 0x%x\n", buffer_rest_size);

    memset(buffer, 0, buffer_size);

    errno = 0;
    fseek(file, offset, SEEK_SET);
    bytes_read = fread(data_ptr, 1, read_size, file);
    errsv = errno;
    DPrint("bytes_read: 0x%zx\n", bytes_read);
    DPrint("read_size: 0x%x\n", read_size);
    if ( bytes_read != read_size || errsv != 0 )
    {
        EPrintP("Read file bytes failed! (0x%x)\n", errsv);
        s = ( errsv == 0 ) ? -1 : errsv;
        goto clean;
    }

    // encrypt data block
    if ( is_encrypted )
    {
        s = generateIV(iv, AES_IV_SIZE);
        if ( s != 0 )
        {
            EPrintP("Generating IV failed! (0x%x)\n", s);
            goto clean;
        }
        // prefix data with iv
        memcpy(buffer, iv, AES_IV_SIZE);

        DPrint("iv: %p\n", buffer);
        DPrintBytes(iv, AES_IV_SIZE);

        DPrint("data: %p\n", data_ptr);
        DPrintBytes(data_ptr, read_size);

        s = encryptData(
            data_ptr, 
            (uint32_t)read_size, 
            &data_ptr, 
            &buffer_rest_size, 
            iv, 
            AES_IV_SIZE
        );
        if ( s != 0 )
        {
            EPrintP("\nEncrypting file data failed! (0x%x)\n", s);
            goto clean;
        }
        DPrint("enc size: 0x%x\n", buffer_rest_size);
        DPrint("enc data: %p\n", data_ptr);
        DPrintBytes(data_ptr, buffer_rest_size);
    }

clean:

    FLeave();
    return s;
}

int sendDir(const char* dir_path, SOCKET sock, uint16_t flags)
{
    DPrint("sendDir(%s)\n", dir_path);
    DPrint(" - check_file: %d\n", flags&FLAG_CHECK_FILE_HASH);
    DPrint(" - recursive: %d\n", flags&FLAG_RECURSIVE);
    DPrint(" - flat: %d\n", flags&FLAG_FLAT_COPY);
    int s = 0;
    //CHAR* types[2] = { };
    FCBParams params = { 
        .sock=sock, 
        .start_dir=dir_path, 
        .flags=flags, 
        .killed=false
    };

    uint32_t act_flags = 0;
    if ( flags&FLAG_RECURSIVE )
        act_flags |= FILES_FLAG_RECURSIVE;
    DPrint(" - act_flags: %u\n", act_flags);
    actOnFilesInDir(dir_path, &fileCB, NULL, act_flags, &params, &(params.killed));

    return s;
}

void fileCB(char* file, char* base_name, void* p)
{
    PFCBParams params = (PFCBParams)p;
    size_t start_dir_size = strlen(params->start_dir);
    size_t base_name_size = strlen(base_name);
    uint16_t sd_id;
    uint16_t sd_ln;
    if ( params->flags&FLAG_FLAT_COPY )
    {
        sd_id = 0;
        sd_ln = 0;
    }
    else
    {
        sd_id = (uint16_t)(start_dir_size + 1);
        sd_ln = (uint16_t)(strlen(file) - sd_id - base_name_size);
        if ( sd_ln > 1 )
            sd_ln--; // remove slash
    }
    
    DPrint("fileCB: %s\n", file);
    DPrint(" - start folder: %s (%zu)\n", params->start_dir, start_dir_size);
    DPrint(" - sub folder: %.*s (%u)\n", sd_ln, &file[sd_id], sd_ln);
    DPrint(" - base_name: %s (%zu)\n", base_name, base_name_size);
    DPrint(" - sub_dir_id: %u\n", sd_id);

#ifdef DEBUG_PRINT
    bool s =
#endif
    sendFile(file, base_name, sd_id, sd_ln, params->sock, params->flags);
#ifdef DEBUG_PRINT
    DPrint(" - send file success: %d\n", s);
#endif
//    if ( !s )
//        params->killed = true;
}

int receiveAnswer(PFsAnswer answer, SOCKET sock, bool is_encrypted)
{
    memset(gBuffer, 0, BUFFER_SIZE);
    memset(answer, 0, sizeof(*answer));
    
    reclen_t bytes_recv;
    bytes_recv = recv(sock, (char*)gBuffer, BUFFER_SIZE, 0);
    if ( bytes_recv == SOCKET_ERROR )
    {
        EPrintP("\nReceiving answer failed! (0x%x)\n", getLastSError());
        return -1;
    }
    DPrint("received bytes: 0x%x\n", (int)bytes_recv);
   
    uint32_t buffer_size;
    uint8_t* answer_ptr = NULL;
    uint32_t answer_size =0;
    int s;

    if ( is_encrypted )
    {
        //
        // [0:f] iv
        // [10:] answer
        //

        if ( bytes_recv < AES_IV_SIZE + FS_ANSWER_SEND_SIZE )
        {
            EPrintP("Received 0x%x answer to short! Expected 0x%x bytes! (0x%x)\n", bytes_recv, (AES_IV_SIZE + FS_ANSWER_SEND_SIZE), -1);
            return -1;
        }

        // calculate answer size and point to it
        answer_size = bytes_recv - AES_IV_SIZE;
        answer_ptr = (uint8_t*)&gBuffer[AES_IV_SIZE];

        // get iv
        uint8_t iv[AES_IV_SIZE];
        memcpy(iv, gBuffer, AES_IV_SIZE);
        DPrint("iv\n");
        DPrintMemCol8(iv, AES_IV_SIZE, 0);
        
        DPrint("encrypted answer\n");
        DPrintMemCol8(answer_ptr, answer_size, 0);

        buffer_size = BUFFER_SIZE;
        s = decryptData(answer_ptr, answer_size, &answer_ptr, &answer_size, iv, AES_IV_SIZE);
        if ( s != 0 )
        {
            EPrintP("\nDecrypting answer failed! (0x%x)\n", s);
            return -2;
        }
        DPrint("decrypted buffer\n");
        DPrintMemCol8(answer_ptr, answer_size, 0);
    }
    else
    {
        //
        // [:] answer
        //

        if ( bytes_recv < FS_ANSWER_SEND_SIZE )
        {
            EPrintP("Received 0x%x answer to short! Expected 0x%x bytes! (0x%x)\n", bytes_recv, FS_ANSWER_SEND_SIZE, -1);
            return -1;
        }

        answer_ptr = (uint8_t*)gBuffer;
        answer_size = bytes_recv;
    }

    s = loadFsAnswer(answer_ptr, answer_size, answer);
    if ( s != 0 )
    {
        EPrintP("Loading answer failed! (0x%x)\n", -1);
        return s;
    }
    if ( answer->type != FS_TYPE_ANSWER)
    {
        EPrintP("Expected answer, got 0x%"PRIx64"! (0x%x)\n", answer->type, -1);
        return -3;
    }

    DPrint("receiveAnswer\n");
    DPrint(" - state: 0x%x\n", answer->state);
    DPrint(" - code: 0x%x\n", answer->code);
    DPrint(" - info: 0x%zx\n", answer->info);
    
    if ( answer->code != FS_PACKET_SUCCESS )
    {
        switch ( answer->code )
        {
            case FS_ERROR_RECV_HEADER:
                printf("ERROR (0x%x): Header receiving failed!\n", answer->code);
                break;
            case FS_ERROR_CREATE_FILE:
                printf("ERROR (0x%x): Creating file failed!\n", answer->code);
                break;
            case FS_ERROR_WRITE_FILE:
                printf("ERROR (0x%x): Writing file failed!\n", answer->code);
                break;
            case FS_ERROR_CREATE_DIR:
                printf("ERROR (0x%x): Creating directory failed!\n", answer->code);
                break;
            case FS_ERROR_ALLOC_FILE_BUFFER:
                printf("ERROR (0x%x): Allocating file buffer failed!\n", answer->code);
                break;
            case FS_ERROR_DECRYPT_AES_KEY:
                printf("ERROR (0x%x): Decrypting AES key failed!\n", answer->code);
                break;
            case FS_ERROR_GENERATE_AES_KEY:
                printf("ERROR (0x%x): Generating AES key failed!\n", answer->code);
                break;
            case FS_ERROR_DECRYPT_FILE_HEADER:
                printf("ERROR (0x%x): Decrypting file header failed!\n", answer->code);
                break;
            case FS_ERROR_DECRYPT_FILE_DATA:
                printf("ERROR (0x%x): Decrypting file data failed!\n", answer->code);
                break;
            default:
                printf("ERROR (0x%x): ...!\n", answer->code);
                break;
        }
        printFsAnswer(answer, " - ");
        return -4;
    }
    
    return 0;
}

//void printUsage()
//{
//    printf("Usage: %s ip port [%cc] [%cr] [%cf] [%cv <version>] [%ck <path>] [%cs <size>] path [another%cpath ...]\n", 
//        APP_NAME, PARAM_IDENTIFIER, PARAM_IDENTIFIER, PARAM_IDENTIFIER, PARAM_IDENTIFIER, PARAM_IDENTIFIER, PARAM_IDENTIFIER, PATH_SEPARATOR);
//    printf("\n");
//    printf("Version: %s\n", APP_VERSION);
//    printf("Last changed: %s\n", APP_LAST_CHANGED);
//}

//void printHelp()
//{
//#ifdef _WIN32
//    const char* key_type = "der";
//#else
//    const char* key_type = "pem";
//#endif
//
//    printUsage();
//    printf("\nOptions\n");
//    printf(" - ip : The server ip port.\n");
//    printf(" - port : The server listening port.\n");
//    printf(" - %cc : Check file hashes of transmitted files. Default if transferred encrypted.\n", PARAM_IDENTIFIER);
//    printf(" - %cr : Copy dirs recursively.\n", PARAM_IDENTIFIER);
//    printf(" - %cf : Flatten copied dirs to base dir. Only meaningful if /r is set,\n", PARAM_IDENTIFIER);
//    printf(" - %cs : Maximum size of sent (encrypted) chunk. Has to be greater than 0x1000 and less than 0xFFFFFFFF. Default: 0x10000.\n", PARAM_IDENTIFIER);
//    printf(" - %cv : IP version 4 (default) or 6.\n", PARAM_IDENTIFIER);
//    printf(" - %ck : Path to a public RSA key.%s file used to encrypt the data.\n", PARAM_IDENTIFIER, key_type);
//    printf(" - path : One or more paths to files or directories to be sent.\n");
//}
