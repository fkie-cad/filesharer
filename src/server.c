#include "env.h"

#if defined(_WIN32)
    #include "warnings.h"
    #include "net/winSock.h"
#elif defined(_LINUX)
    #include "net/linSock.h"
#endif
#include "net/sock.h"

#include <stdlib.h>
#include <stdio.h>

#include <inttypes.h>
#include <stdint.h>
#if defined(_LINUX)
#include <errno.h>
#endif
#include <string.h>


#include "../shared/print.h"
#ifdef DEBUG_PRINT
#include "debug.h"
#endif
#if defined(_WIN32)
#include "files/FilesW.h"
#include "crypto/windows/HasherCNG.h"
#elif defined(_LINUX)
#include "files/FilesL.h"
#include "crypto/linux/HasherOpenSSL.h"
#endif
#include "crypto/crypto.h"
#include "FsHeader.h"
#include "flags.h"


#define APP_NAME "FsServer"

//#define FLAG_DECRYPT (0x8)

#define DATA_STATE_NONE (0x0)
#define DATA_STATE_KEY_HEADER (0x1)
#define DATA_STATE_FILE_HEADER (0x2)
#define DATA_STATE_FILE_DATA (0x3)

#define KEY_HEADER_BUFFER_SIZE (0x100)
#define BASE_NAME_MAX_SIZE (0x200)
#define SUB_DIR_MAX_SIZE (0x200)



int handleConnection(
    SOCKET ListenSocket, 
    char* rec_dir, 
    uint16_t flags
);

bool checkHash(
    char* fp, 
    uint8_t* f_hash
);

int createFilePath(
    char* FilePath, 
    uint32_t FilePathSize, 
    char* ParentDir, 
    char* SubDir, 
    char* BaseName, 
    FsFileHeader* FileHeader, 
    FsKeyHeader* KeyHeader, 
    SOCKET ClientSocket, 
    bool IsEncrypted
);

void printProgress(
    size_t br, 
    size_t fs
);

int writeBlockToFile(
    bool is_encrypted,
    SOCKET ClientSocket,
    FsKeyHeader* key_header,
    uint32_t enc_part_i,
    uint8_t* file_buffer,
    uint32_t* buffer_size,
    FILE* fp
);

int sendAnswer(
    uint8_t state, 
    uint32_t code, 
    size_t info, 
    SOCKET sock, 
    bool is_encrypted, 
    FsKeyHeader* key_header
);

int handleData(
    SOCKET ClientSocket, 
    uint32_t result, 
    int* data_state, 
    PFsKeyHeader key_header,
    PFsFileHeader file_header,
    bool is_encrypted,
    char* rec_dir,
    uint32_t *nrBlocks,
    size_t *data_full_size,
    uint32_t *block_bytes_received,
    size_t *file_bytes_received,
    uint8_t **file_buffer,
    FILE** fp,
    uint8_t *hash
);



static char file_path[MAX_PATH];
static char base_name[BASE_NAME_MAX_SIZE];
static char sub_dir[BASE_NAME_MAX_SIZE];
static uint8_t gBuffer[BUFFER_SIZE];

static int running = 0;


int __cdecl runServer(
    int argc, 
    char** argv,
    int start_i,
    SOCKET sock,
    PADDRINFOA addr_info,
    uint16_t flags
)
{
    bool s = 0;

    char *rec_dir = NULL;
    char full_path[MAX_PATH];

    if ( start_i >= argc )
        return -1;

    //
    // set target dir

    rec_dir = argv[start_i];
    memset(full_path, 0, MAX_PATH);
    s = (int)getFullPathName(rec_dir, MAX_PATH, full_path, NULL);
    if ( !s )
    {
        EPrint(-1, "Directory \"%s\" not found!", full_path);
        return 0;
    }
    s = checkPath(full_path, true);
    if (!s)
    {
        EPrint(-1, "Directory \"%s\" not found!", full_path);
        return 0;
    }
    cropTrailingSlash(full_path);
    printf("target dir: %s\n\n", full_path);
    


//    int iOptval = 1;
//    s = setsockopt(listenSocket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char*)&iOptval, sizeof(iOptval));
//    if ( s == SOCKET_ERROR)
//    {
//        printf("ERROR (0x%x): setsockopt for SO_EXCLUSIVEADDRUSE failed.\n", WSAGetLastError());
//        return -1;
//    }


    //
    // Setup the TCP listening socket

    errno = 0;
    s = bind(sock, addr_info->ai_addr, (int)addr_info->ai_addrlen);
    if ( s == SOCKET_ERROR )
    {
        s = getLastSError();
        EPrint(s, "bind failed!\n");
        goto clean;
    }
    DPrint("socket bound\n");

    errno = 0;
    s = listen(sock, 1);
    if ( s == SOCKET_ERROR )
    {
        s = getLastSError();
        EPrint(s, "listen failed\n");
        goto clean;
    }
    DPrint("listening\n");
    


    //
    // enter accept loop

    running = 1;
    while ( running )
    {
        handleConnection(sock, full_path, flags);
        printf("\n\n");
    }

clean:

    return s;
}

int handleConnection(SOCKET ListenSocket, char* rec_dir, uint16_t flags)
{
    uint32_t result;
    int le;
    bool is_encrypted = IS_ENCRYPTED(flags);
    
    SOCKET clientSocket = INVALID_SOCKET;
    SOCKADDR_STORAGE addr;
    socklen_t addr_ln = (socklen_t)sizeof(SOCKADDR_STORAGE);
    
    uint32_t nrBlocks = 0;
    size_t data_full_size = 0;
    uint32_t block_bytes_received = 0;
    size_t file_bytes_received = 0;
    int s = 0;

    uint8_t *file_buffer = NULL;
    FILE* fp = NULL;
    
    
    int data_state = (is_encrypted) ? DATA_STATE_KEY_HEADER : DATA_STATE_FILE_HEADER;
    FsKeyHeader key_header;
    FsFileHeader file_header;
    uint8_t hash[SHA256_BYTES_LN];

    // Accept a client socket
    printf("waiting for connection...\n");
    clientSocket = accept(ListenSocket, (PSOCKADDR)&addr, &addr_ln);
    if ( clientSocket == INVALID_SOCKET )
    {
        le = getLastSError();
        printf(" - accept failed with error: 0x%x\n", le);
        return 1;
    }
    printf(" - connection accepted\n");
    if ( addr_ln > 0)
    {
        printf("Connected Client Info:\n");
        printSockAddr(&addr, (int)addr_ln);
    }

    memset(&file_header, 0, sizeof(file_header));
    memset(&key_header, 0, sizeof(key_header));

    // Receive from connected client until connection is closed
    do
    {
        memset(gBuffer, 0, BUFFER_SIZE);
        DPrint("Waiting for data.\n");

        result = recv(clientSocket, (char*)gBuffer, BUFFER_SIZE, 0);
        if ( result > 0 )
        {
            s = handleData(
                    clientSocket, 
                    result, 
                    &data_state, 
                    &key_header,
                    &file_header,
                    is_encrypted,
                    rec_dir,
                    &nrBlocks,
                    &data_full_size,
                    &block_bytes_received,
                    &file_bytes_received,
                    &file_buffer,
                    &fp,
                    hash
                );
            if ( s != 0 )
                goto clean;
        }
        else if ( result == 0 )
        {
            printf("\n\n");
            printf("Closing connection ...\n");
        }
        else
        {
            printf("\n\n");

            le = getLastSError();
            checkReceiveError(le);
            
            s = -1;
            goto clean;
        }

    } while ( result > 0 );
    
clean:
    shutdown(clientSocket, SD_BOTH);
    //if (result == SOCKET_ERROR)
    //{
    //    le = getLastSError();
    //    printf("shutdown failed with error: %d\n", le);
    //    s = -1;
    //}

    closeSocket(&clientSocket);

    memset(&key_header, 0, sizeof(key_header));

    if ( fp )
        fclose(fp);
    if ( file_buffer )
        free(file_buffer);

    return s;
}

int handleData(
    SOCKET ClientSocket, 
    uint32_t result, 
    int* data_state, 
    PFsKeyHeader key_header,
    PFsFileHeader file_header,
    bool is_encrypted,
    char* rec_dir,
    uint32_t *nrBlocks,
    size_t *data_full_size,
    uint32_t *block_bytes_received,
    size_t *file_bytes_received,
    uint8_t **file_buffer,
    FILE** fp,
    uint8_t *hash
)
{
    uint8_t* buffer_ptr = NULL;
    uint32_t bytes_received = result;

    int s = 0;
    uint32_t buffer_size = BUFFER_SIZE;
    //int le;
    int errsv;

    if ( *data_state == DATA_STATE_KEY_HEADER )
    {
        memset(key_header, 0, sizeof(*key_header));

        printf("Key header received: 0x%x\n", result);

#ifdef _LINUX
        // Somehow AES padding does not work with a new connection and old context, or cross os with more than one file.
        // ERROR (0x6065064): EVP_DecryptFinal_ex failed when decrypting first file info header of new client connection.
        clean_AES();
        init_AES();
#endif
        
                
        buffer_ptr = (uint8_t*)key_header;
//        result = sizeof(*key_header);
        result = bytes_received; // openssl rsa wants plain buffer of encrypted size
#ifdef DEBUG_PRINT
        DPrint("encrypted key header");
        printMemory(gBuffer, bytes_received, 0x10, 0);
#endif

        s = decryptKey(
            gBuffer, 
            bytes_received, 
            &buffer_ptr, 
            &result
        );
        if ( s != 0 )
        {
            EPrintNl();
            EPrint(s, "Decrypting key header failed!\n");
            // can't really send an answer without decrypted key unless sending it unencrypted
            //sendAnswer(1, FS_ERROR_DECRYPT_AES_KEY, bytes_received, ClientSocket, is_encrypted, key_header);
            goto clean;
        }
#ifdef DEBUG_PRINT
        DPrint("decrypted key header");
        printMemory(buffer_ptr, result, 0x10, 0);
#endif

        if ( key_header->type != FS_TYPE_KEY_HEADER )
        {
            EPrintNl();
            EPrint(s, "Expected key header, but got 0x%"PRIx64"\n", key_header->type);
            // can't really send an answer without decrypted key unless sending it unencrypted
            goto clean;
        }

#ifdef DEBUG_PRINT
        DPrint("key header:\n");
        printFsKeyHeader(key_header, " - ");
#endif

        // generate key out of secret
        s = generateAESKey(key_header->secret, AES_SECRET_SIZE);
        if ( s != 0 )
        {
            EPrintNl();
            EPrint(s, "Generating AES key failed!\n");
            // can't really send an answer without generated key unless sending it unencrypted
            //sendAnswer(1, FS_ERROR_GENERATE_AES_KEY, bytes_received, ClientSocket, is_encrypted, key_header);
            goto clean;
        }

        // send header-received answer
        // TODO: send priv.key encrypted/signed sha256 of header as a signature
        errsv = sendAnswer(1, FS_PACKET_SUCCESS, bytes_received, ClientSocket, is_encrypted, key_header);
        if ( errsv != 0 )
        {
            goto clean;
        }

        *data_state = DATA_STATE_FILE_HEADER;
    }
    else if ( *data_state == DATA_STATE_FILE_HEADER )
    {
        printf("File header received: 0x%x\n", result);

        memset(file_header, 0, sizeof(*file_header));

        *file_bytes_received = 0;
                
        if ( is_encrypted )
        {
#ifdef DEBUG_PRINT
            DPrint("encrypted file header");
            printMemory(gBuffer, result, 0x10, 0);
#endif

            buffer_size = BUFFER_SIZE;
            buffer_ptr = (uint8_t*)gBuffer;
            s = decryptData(gBuffer, result, &buffer_ptr, &buffer_size, key_header->iv, AES_IV_SIZE);
            if ( s != 0 )
            {
                EPrintNl();
                EPrint(s, "Encrypting file header failed!\n");
                sendAnswer(4, FS_ERROR_DECRYPT_FILE_HEADER, 0, ClientSocket, is_encrypted, key_header);
                goto clean;
            }
#ifdef DEBUG_PRINT
            DPrint("decrypted file header");
            printMemory(gBuffer, buffer_size, 0x10, 0);
#endif
        }
        else
        {
            buffer_size = result;
        }

        loadFsFileHeader(gBuffer, file_header, base_name, BASE_NAME_MAX_SIZE, sub_dir, SUB_DIR_MAX_SIZE, hash, SHA256_BYTES_LN);
        printFsFileHeader(file_header, " - ");

        if ( file_header->type != FS_TYPE_FILE_HEADER )
        {
            EPrintNl();
            EPrint(s, "Expected file header, but got 0x%"PRIx64"\n", key_header->type);
            sendAnswer(4, FS_ERROR_WRONG_HEADER_TYPE, 0, ClientSocket, is_encrypted, key_header);
            goto clean;
        }

        if ( strlen(rec_dir) + file_header->sub_dir_ln + file_header->base_name_ln + 3 >= MAX_PATH )
        {
            sendAnswer(4, FS_ERROR_FILE_PATH_TOO_BIG, 0, ClientSocket, is_encrypted, key_header);
            s = -1;
            goto clean;
        }

        s = createFilePath(file_path, MAX_PATH, rec_dir, sub_dir, base_name, file_header, key_header, ClientSocket, is_encrypted);
        if ( s != 0 )
            goto clean;

        printf(" - file_path: %s\n", file_path);
        
        if ( is_encrypted )
            *data_full_size = ( file_header->parts_count * (size_t)file_header->parts_block_size ) + file_header->parts_rest;
        else
            *data_full_size = file_header->file_size;
        *nrBlocks = file_header->parts_count;

        // allocate file block buffer
        buffer_size = (file_header->parts_count > 0) 
                    ? file_header->parts_block_size 
                    : file_header->parts_rest;
        *file_buffer = (uint8_t*)malloc(buffer_size);
        if ( !(*file_buffer) )
        {
            EPrint(getLastError(), "malloc file buffer failed\n");
            sendAnswer(4, FS_ERROR_ALLOC_FILE_BUFFER, 0, ClientSocket, is_encrypted, key_header);
            s = -1;
            goto clean;
        }
        DPrint(" - buffer of 0x%x bytes allocated.\n", buffer_size);
        
        // create file
        errno = 0;
        *fp = fopen(file_path, "wb");
        errsv = errno;
        if ( *fp == NULL )
        {
            EPrint(errsv, "Creating file \"%s\" failed.\n", file_path);
            sendAnswer(2, FS_ERROR_CREATE_FILE, 0, ClientSocket, is_encrypted, key_header);
            s = -1;
            goto clean;
        }
        DPrint(" - file created\n");

        // send header-received answer
        errsv = sendAnswer(1, FS_PACKET_SUCCESS, bytes_received, ClientSocket, is_encrypted, key_header);
        if ( errsv != 0 )
        {
            goto clean;
        }
        
        *data_state = DATA_STATE_FILE_DATA;
    }
    else if ( *data_state == DATA_STATE_FILE_DATA )
    {
        DPrint("File data received: 0x%x\n", result);
        DPrint("nrBlocks: 0x%x\n", *nrBlocks);
        
        if ( !(*file_buffer) )
        {
            EPrint(-1, "No file buffer found\n");
            sendAnswer(4, FS_ERROR_NULL_FILE_BUFFER, 0, ClientSocket, is_encrypted, key_header);
            s = -1;
            goto clean;
        }
        
        DPrint("copy bytes into file buffer\n");
        memcpy(&(*file_buffer)[*block_bytes_received], gBuffer, bytes_received);
        
        *block_bytes_received += bytes_received;
        *file_bytes_received += bytes_received;
        DPrint("block_bytes_received: 0x%x\n", *block_bytes_received);
        DPrint("file_bytes_received: 0x%zx\n", *file_bytes_received);

        printProgress(*file_bytes_received, *data_full_size);

        // writing block 
        if ( *nrBlocks > 0 && *block_bytes_received == file_header->parts_block_size )
        {
            DPrint("Writing block 0x%x\n", file_header->parts_count - (*nrBlocks));
            buffer_size = (uint32_t)file_header->parts_block_size;
            s = writeBlockToFile(is_encrypted, ClientSocket, key_header, (file_header->parts_count - (*nrBlocks)), *file_buffer, &buffer_size, *fp);
            if ( s != 0 )
                goto clean;
            
            (*nrBlocks)--;
            
            DPrint("\n");
            DPrint("File block received successfully\n");
            
            memset(*file_buffer, 0, file_header->parts_block_size);
            *block_bytes_received = 0;

            DPrint("Awaiting next block\n");
        }

        // writing rest 
        if ( *nrBlocks == 0 && *block_bytes_received == file_header->parts_rest )
        {
            DPrint("Writing rest\n");
            buffer_size = (uint32_t)file_header->parts_rest;
            s = writeBlockToFile(is_encrypted, ClientSocket, key_header, (file_header->parts_count - (*nrBlocks)), *file_buffer, &buffer_size, *fp);
            if ( s != 0 )
                goto clean;

            DPrint("File rest received successfully\n");
            
            memset(*file_buffer, 0, file_header->parts_rest);
            *block_bytes_received = 0;
        }

        // fully received, send answer, check hash
        if ( *file_bytes_received == *data_full_size )
        {
            DPrint("File fully received.\n");

            // does not work, if block answer is sent without intermediate wait for other sides's response,
            // because the two answers (block answer, and fully-received answer) might be buffered and sent at once.
//            DPrint("Sending answer.\n");
//            // send file-fully-received answer
//            errsv = sendAnswer(2, FS_PACKET_SUCCESS, *file_bytes_received, ClientSocket, is_encrypted, key_header);
//            if ( errsv != 0 )
//            {
//                goto clean;
//            }
            printf("\n");
            printf("File received successfully\n");
            
            if ( *file_buffer )
                free(*file_buffer);
            *file_buffer = NULL;

            // Close before calculating hash
            if ( *fp ) // always true
                fclose(*fp);
            *fp = NULL;

            if ( file_header->hash_ln > 0 )
            {
                if ( checkHash(file_path, file_header->hash) )
                    printf(" - Checking hash: correct.\n");
                else
                    printf(" - Checking hash: ERROR!\n");
            }

            *data_state = (is_encrypted) ? DATA_STATE_KEY_HEADER : DATA_STATE_FILE_HEADER;
            memset(key_header, 0, sizeof(*key_header)); 

            printf("Ready for next\n");
            printf("\n");
        }
    }

clean:
    if ( s != 0 )
    {
        if ( *fp )
            fclose(*fp);
        *fp = NULL;

        if ( *file_buffer )
            free(*file_buffer);
        *file_buffer = NULL;
    }
    return s;
}

int sendAnswer(uint8_t state, uint32_t code, size_t info, SOCKET sock, bool is_encrypted, FsKeyHeader* key_header)
{
    int errsv;
    sendlen_t bytes_sent;
    int s;
    FsAnswer a = { .state = state, .code = code, .info = info };
    s = generateRand(a.garbage, AES_IV_SIZE);
    if ( s != 0 )
    {
        EPrintNl();
        EPrint(s, "Generating IV failed!\n");
        return -1;
    }
    uint32_t answer_size = (uint32_t)saveFsAnswer(gBuffer, &a);
    uint32_t buffer_size = BUFFER_SIZE;
    uint8_t* buffer_ptr = (uint8_t*)gBuffer;
    
    DPrint("sendAnswer\n");
    
    if ( is_encrypted )
    {
#ifdef DEBUG_PRINT
        DPrint(" - buffer:");
        printMemory(gBuffer, answer_size, 0x10, 0);
#endif
        s = encryptData(
            gBuffer, 
            answer_size, 
            &buffer_ptr, 
            &buffer_size, 
            key_header->iv, 
            AES_IV_SIZE
        );
        if ( s != 0 )
        {
            EPrintNl();
            EPrint(s, "Encrypting file header failed!\n");
            return -2;
        }
#ifdef DEBUG_PRINT
        DPrint(" - encrypted:");
        printMemory(buffer_ptr, buffer_size, 0x10, 0);
#endif
    }
    else
    {
        buffer_size = answer_size;
    }

    errno = 0;
    bytes_sent = send(sock, (char*)gBuffer, buffer_size, 0);
    
    DPrint(" - bytes_sent: 0x%x\n", (int)bytes_sent);
    if ( bytes_sent < 0 )
    {
        errsv = getLastSError();
        EPrint(errsv, "Sending answer failed.\n");
        return -3;
    }
    return 0;
}

bool checkHash(char* path, uint8_t* f_hash)
{
    uint8_t hash[SHA256_BYTES_LN];
    int s;

    printf("Calculating hash...");
    s = sha256File(path, hash, SHA256_BYTES_LN);
    if ( s != 0 )
    {
        EPrintCr();
        EPrint(s, "Calculating hash failed!\n");
        return false;
    }
    printf("\r");
    printHash(hash, SHA256_BYTES_LN, " - hash: ", "\n");

    return memcmp(hash, f_hash, SHA256_BYTES_LN) == 0;
}

int createFilePath(
    char* FilePath, 
    uint32_t FilePathSize, 
    char* ParentDir, 
    char* SubDir, 
    char* BaseName, 
    FsFileHeader* FileHeader, 
    FsKeyHeader* KeyHeader, 
    SOCKET ClientSocket, 
    bool IsEncrypted
)
{
    int s = 0;
    
    memset(FilePath, 0, FilePathSize);
    int pb = sprintf(FilePath, "%s", ParentDir);
    if ( FileHeader->sub_dir_ln != 0 )
    {
        convertPathSeparator(SubDir);
        pb += sprintf(&FilePath[pb], "%c%s", PATH_SEPARATOR, SubDir);
        s = mkdir_r(FilePath);
        if ( s != 0 )
        {
            sendAnswer(4, FS_ERROR_CREATE_DIR, 0, ClientSocket, IsEncrypted, KeyHeader);
            return s;
        }
    }

    s = sprintf(&FilePath[pb], "%c%s", PATH_SEPARATOR, BaseName);
    if ( s < 0 || s >= (int)FilePathSize )
        return s;
    s = 0;

    return s;
}

void printProgress(size_t br, size_t fs)
{
    uint16_t pc = (uint16_t)((float)br / (float)fs * 100.0);
    printf("Bytes received: 0x%zx/0x%zx (%u%%).", br, fs, pc);
#ifdef DEBUG_PRINT
    printf("\n");
#else
    printf("\r");
#endif
}

int writeBlockToFile(
    bool is_encrypted,
    SOCKET ClientSocket,
    //FsFileHeader* file_header,
    FsKeyHeader* key_header,
    uint32_t enc_part_i,
    uint8_t* file_buffer,
    uint32_t* buffer_size,
    FILE* fp
)
{
    int s = 0;

    uint8_t* buffer_ptr = NULL;
    size_t bytes_written;
    uint8_t tmp_iv[AES_IV_SIZE];
    
    DPrint("writeBlockToFile\n");

    // decrypt block buffer
    if ( is_encrypted )
    {
        memcpy(tmp_iv, key_header->iv, AES_IV_SIZE);
        rotate64Iv(tmp_iv, enc_part_i);
#ifdef DEBUG_PRINT
        DPrint("iv: ");
        for ( int x=0;x<0x10;x++ )
            printf("%02x ", tmp_iv[x]);
        printf("\n");
#endif

        buffer_ptr = (uint8_t*)(file_buffer);
        s = decryptData(file_buffer, *buffer_size, &buffer_ptr, buffer_size, tmp_iv, AES_IV_SIZE);
        if ( s != 0 )
        {
            EPrintNl();
            EPrint(s, "Decrypting file data failed!\n");
            sendAnswer(4, FS_ERROR_DECRYPT_FILE_DATA, *buffer_size, ClientSocket, is_encrypted, key_header);
            return s;
        }
        DPrint("  file decrypted\n");
    }
    DPrint("  buffer size: 0x%x\n", *buffer_size);
            
    // write file block
    errno = 0;
    //fseek(fp, offset, SEEK_SET);
    bytes_written = fwrite(file_buffer, 1, *buffer_size, fp);
    s = errno;

    if ( bytes_written != *buffer_size )
    {
        EPrint(s, "Writing file failed.");
        sendAnswer(2, FS_ERROR_WRITE_FILE, bytes_written, ClientSocket, is_encrypted, key_header);
        if ( s== 0) s = -1;
        return s;
    }
    DPrint("  block written\n");
    DPrint("  sending answer\n");

    // send file-block-received answer
    s = sendAnswer(2, FS_PACKET_SUCCESS, *buffer_size, ClientSocket, is_encrypted, key_header);
    //if ( s != 0 )
    //{
    //    return s;
    //}

    return s;
}

//void printUsage()
//{
//    printf("Usage: %s port rec%cdir [%ci 4|6] [%ck path%cto%ckey]\n", APP_NAME, PATH_SEPARATOR, PARAM_IDENTIFIER, PARAM_IDENTIFIER, PATH_SEPARATOR, PATH_SEPARATOR);
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
//    printf(" - port : The server listening port.\n");
//    printf(" - rec%cdir : The existing base directory, the shared files are stored in.\n", PATH_SEPARATOR);
//    printf(" - %ci : IP version 4 (default) or 6.\n", PARAM_IDENTIFIER);
//    printf(" - %ck : Path to a private key.%s file to decrypt encrypted data from the client.\n", PARAM_IDENTIFIER, key_type);
//}
