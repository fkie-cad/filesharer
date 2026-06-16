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
    uint8_t* file_buffer,
    uint32_t* buffer_size,
    FILE* fp
);

int sendAnswer(
    uint8_t state, 
    uint32_t code, 
    size_t info, 
    SOCKET sock, 
    bool is_encrypted
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



int runServer(
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
    size_t fpcb = 0;

    if ( start_i >= argc )
        return -1;

    //
    // set target dir

    rec_dir = argv[start_i];
    memset(full_path, 0, MAX_PATH);
    fpcb = getFullPathName(rec_dir, MAX_PATH, full_path, NULL);
    if ( !fpcb )
    {
        EPrintP("Directory \"%s\" not found! (0x%x)", full_path, -1);
        return -1;
    }
    s = checkPath(full_path, true);
    if ( !s )
    {
        EPrintP("Directory \"%s\" not found! (0x%x)", full_path, -1);
        return -1;
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
        EPrintP("bind failed! (0x%x)\n", s);
        goto clean;
    }
    DPrint("socket bound\n");

    printLocalAddresses();
    printf("\n");

    errno = 0;
    s = listen(sock, 1);
    if ( s == SOCKET_ERROR )
    {
        s = getLastSError();
        EPrintP("listen failed! (0x%x)\n", s);
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
        printf("  accept failed with error: 0x%x\n", le);
        return 1;
    }
    printf("  connection accepted\n");
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

    uint8_t* iv_ptr = NULL;
    uint8_t* data_ptr = NULL;
    uint32_t data_size = 0;

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
        DPrint("encrypted key header\n");
        DPrintBytes(gBuffer, bytes_received);

        s = decryptKey(
            gBuffer, 
            bytes_received, 
            &buffer_ptr, 
            &result
        );
        if ( s != 0 )
        {
            EPrintP("\nDecrypting key header failed! (0x%x)\n", s);
            // can't really send an answer without decrypted key unless sending it unencrypted
            //sendAnswer(1, FS_ERROR_DECRYPT_AES_KEY, bytes_received, ClientSocket, is_encrypted);
            goto clean;
        }
        DPrint("decrypted key header\n");
        DPrintMemCol8(buffer_ptr, result, 0);

        if ( key_header->type != FS_TYPE_KEY_HEADER )
        {
            EPrintP("\nExpected key header, but got 0x%"PRIx64"! (0x%x)\n", key_header->type, s);
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
            EPrintP("\nGenerating AES key failed! (0x%x)\n", s);
            // can't really send an answer without generated key unless sending it unencrypted
            //sendAnswer(1, FS_ERROR_GENERATE_AES_KEY, bytes_received, ClientSocket, is_encrypted);
            goto clean;
        }

        // send header-received answer
        // TODO: send priv.key encrypted/signed sha256 of header as a signature
        errsv = sendAnswer(1, FS_PACKET_SUCCESS, bytes_received, ClientSocket, is_encrypted);
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
            DPrint("encrypted file header\n");
            DPrintBytes(gBuffer, result);

            iv_ptr = gBuffer;
            data_ptr = &gBuffer[AES_IV_SIZE];
            data_size = result - AES_IV_SIZE;

            buffer_size = BUFFER_SIZE - AES_IV_SIZE;
            buffer_ptr = (uint8_t*)gBuffer;
            s = decryptData(data_ptr, data_size, &data_ptr, &buffer_size, iv_ptr, AES_IV_SIZE);
            if ( s != 0 )
            {
                EPrintP("\nEncrypting file header failed! (0x%x)\n", s);
                sendAnswer(4, FS_ERROR_DECRYPT_FILE_HEADER, 0, ClientSocket, is_encrypted);
                goto clean;
            }
            DPrint("decrypted file header\n");
            DPrintMemCol8(data_ptr, buffer_size, 0);
        }
        else
        {
            data_ptr = &gBuffer[0];
            data_size = result;
            buffer_size = result;
        }

        s = loadFsFileHeader(data_ptr, buffer_size, file_header, base_name, BASE_NAME_MAX_SIZE, sub_dir, SUB_DIR_MAX_SIZE, hash, SHA256_BYTES_LN);
        if ( s != 0 )
        {
            EPrintP("\nExpected file header too short! (0x%x)\n", s);
            sendAnswer(4, FS_ERROR_WRONG_HEADER_SIZE, 0, ClientSocket, is_encrypted);
            goto clean;
        }
        printFsFileHeader(file_header, " - ");

        if ( file_header->type != FS_TYPE_FILE_HEADER )
        {
            EPrintP("\nExpected file header, but got 0x%"PRIx64"! (0x%x)\n", key_header->type, s);
            sendAnswer(4, FS_ERROR_WRONG_HEADER_TYPE, 0, ClientSocket, is_encrypted);
            goto clean;
        }

        if ( strlen(rec_dir) + file_header->sub_dir_ln + file_header->base_name_ln + 3 >= MAX_PATH )
        {
            sendAnswer(4, FS_ERROR_FILE_PATH_TOO_BIG, 0, ClientSocket, is_encrypted);
            s = -1;
            goto clean;
        }

        s = createFilePath(file_path, MAX_PATH, rec_dir, sub_dir, base_name, file_header, ClientSocket, is_encrypted);
        if ( s != 0 )
            goto clean;

        printf(" - file_path: %s\n", file_path);
        
        if ( is_encrypted )
            *data_full_size = ( file_header->parts_count * (size_t)file_header->parts_block_size ) + file_header->parts_rest;
        else
            *data_full_size = file_header->file_size;
        *nrBlocks = file_header->parts_count;

        // allocate file block buffer
        buffer_size = ( file_header->parts_count > 0 ) 
                    ? file_header->parts_block_size 
                    : file_header->parts_rest;
        *file_buffer = (uint8_t*)malloc(buffer_size);
        if ( !(*file_buffer) )
        {
            EPrintP("malloc file buffer failed! (0x%x)\n", getLastError());
            sendAnswer(4, FS_ERROR_ALLOC_FILE_BUFFER, 0, ClientSocket, is_encrypted);
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
            EPrintP("Creating file \"%s\" failed! (0x%x)\n", file_path, errsv);
            sendAnswer(2, FS_ERROR_CREATE_FILE, 0, ClientSocket, is_encrypted);
            s = -1;
            goto clean;
        }
        DPrint(" - file created\n");

        // send header-received answer
        errsv = sendAnswer(1, FS_PACKET_SUCCESS, bytes_received, ClientSocket, is_encrypted);
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
            EPrintP("No file buffer found! (0x%x)\n", -1);
            sendAnswer(4, FS_ERROR_NULL_FILE_BUFFER, 0, ClientSocket, is_encrypted);
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
            s = writeBlockToFile(is_encrypted, ClientSocket, *file_buffer, &buffer_size, *fp);
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
            s = writeBlockToFile(is_encrypted, ClientSocket, *file_buffer, &buffer_size, *fp);
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
//            errsv = sendAnswer(2, FS_PACKET_SUCCESS, *file_bytes_received, ClientSocket, is_encrypted);
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

            // send "hash-correct" answer ??

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

int sendAnswer(uint8_t state, uint32_t code, size_t info, SOCKET sock, bool is_encrypted)
{
    int errsv;
    sendlen_t bytes_sent;
    sendlen_t send_size;
    int s = 0;

    size_t answer_offset = ( is_encrypted ) ? AES_IV_SIZE : 0;
    uint8_t* answer_ptr = &gBuffer[answer_offset];

    FsAnswer a = { .state = state, .code = code, .info = info };
    uint32_t answer_size = (uint32_t)saveFsAnswer(answer_ptr, &a);
    uint32_t buffer_size = BUFFER_SIZE;
    //uint8_t* buffer_ptr = (uint8_t*)gBuffer;
    
    DPrint("sendAnswer\n");
    
    if ( is_encrypted )
    {
        DPrint("  buffer:\n");
        DPrintBytes(gBuffer, answer_size);
        
        uint8_t iv[AES_IV_SIZE];
        s = generateIV(iv, AES_IV_SIZE);
        if ( s != 0 )
        {
            EPrintP("Generating IV failed! (0x%x)\n", s);
            goto clean;
        }
        // prefix data with iv
        memcpy(gBuffer, iv, AES_IV_SIZE);
        buffer_size -= AES_IV_SIZE;

        s = encryptData(
            answer_ptr, 
            answer_size, 
            &answer_ptr, 
            &buffer_size, 
            iv, 
            AES_IV_SIZE
        );
        if ( s != 0 )
        {
            EPrintP("\nEncrypting file header failed! (0x%x)\n", s);
            goto clean;
        }
        DPrint("  encrypted:\n");
        DPrintBytes(answer_ptr, buffer_size);

        send_size = AES_IV_SIZE + buffer_size;
    }
    else
    {
        send_size = answer_size;
    }

    // make compiler happy sanity check
    if ( send_size < 0 || (uint32_t)send_size > BUFFER_SIZE )
    {
        EPrintP("Answer send size out of range! (0x%x)\n", (uint32_t)send_size);
        s = -1;
        goto clean;
    }
    errno = 0;

#if defined(_WIN32)
// disabling false positive:
// warning C6385: Reading invalid data from 'gBuffer'
#pragma warning(disable: 6385)
#endif
    bytes_sent = send(sock, (char*)gBuffer, send_size, 0);
#if defined(_WIN32)
#pragma warning(default: 6385)
#endif
    
    DPrint("  bytes_sent: 0x%x\n", (int)bytes_sent);
    if ( bytes_sent < 0 )
    {
        errsv = getLastSError();
        EPrintP("Sending answer failed! (0x%x)\n", errsv);
        return -3;
    }

clean:

    return s;
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
        EPrintP("Calculating hash failed! (0x%x)\n", s);
        return false;
    }
    printf("\r");
    printHash(hash, SHA256_BYTES_LN, " - hash: ", "\n");

    return memcmp(hash, f_hash, SHA256_BYTES_LN) == 0;
}

int createFilePath(
    char* FilePath, // out
    uint32_t FilePathMaxSize, 
    char* ParentDir, 
    char* SubDir, 
    char* BaseName, 
    FsFileHeader* FileHeader, 
    SOCKET ClientSocket, 
    bool IsEncrypted
)
{
    FEnter();
    
    int s = 0;

    int pb = 0;
    int bw = 0;
    size_t fpbw = 0;
    size_t pd_cb = strlen(ParentDir);
    
    DPrint("  FilePath: %s\n", FilePath);
    DPrint("  FilePathMaxSize: 0x%x\n", FilePathMaxSize);
    DPrint("  ParentDir: %s\n", ParentDir);
    DPrint("  SubDir: %s\n", SubDir);
    DPrint("  BaseName: %s\n", BaseName);
    DPrint("  FileHeader: %p\n", (void*)FileHeader);
    // DPrint("  ClientSocket: %p\n", (void*)ClientSocket);
    DPrint("  IsEncrypted: %d\n", IsEncrypted);

    char* tmpPath = malloc(FilePathMaxSize);
    if ( !tmpPath )
    {
        s = getLastError();
        goto clean;
    }
    
    memset(FilePath, 0, FilePathMaxSize);
    memset(tmpPath, 0, FilePathMaxSize);
    bw = sprintf(tmpPath, "%s", ParentDir);
    if ( bw == -1 )
    {
        s = -1;
        goto clean;
    }
    pb += bw;

    // tmpPath = ParentDir
    if ( FileHeader->sub_dir_ln != 0 )
    {
        convertPathSeparator(SubDir);
        cropTrailingSlash(SubDir);
        // construct directory string
        bw = sprintf(&tmpPath[pb], "%c%s", PATH_SEPARATOR, SubDir);
        if ( bw == -1 )
        {
            s = -1;
            goto clean;
        }
        pb += bw;
        // tmpPath = ParentDir/SubDir
        
        // get abs path
        fpbw = getFullPathName(tmpPath, FilePathMaxSize, FilePath, NULL);
        // check if we are still in ParentDir
        if ( !fpbw || fpbw >= FilePathMaxSize
            || strncmp(FilePath, ParentDir, pd_cb) != 0
            || (FilePath[pd_cb] != PATH_SEPARATOR && FilePath[pd_cb] != '\0') )
        {
            s = -2;
            goto clean;
        }

        // create directory
        s = mkdir_r(FilePath);
        if ( s != 0 )
            goto clean;
    }

    // add BaseName to construct full file path
    bw = sprintf(&tmpPath[pb], "%c%s", PATH_SEPARATOR, BaseName);
    // tmpPath = ParentDir/SubDir/BaseName
    if ( bw < 0 || (uint32_t)bw >= FilePathMaxSize )
    {
        s = getLastError();
        EPrintP("sprintf failed! (0x%x)\n", s);
        goto clean;
    }
    DPrint("  tmpPath: %s\n", tmpPath);
    // get abs path
    char* checkBaseName = NULL;
    fpbw = getFullPathName(tmpPath, FilePathMaxSize, FilePath, (char**)&checkBaseName);
    DPrint("fpbw: 0x%zx\n", fpbw);
    DPrint("checkBaseName: %s\n", checkBaseName);
    // check if we are still in ParentDir and baseName fits

    if ( !fpbw || fpbw >= FilePathMaxSize
        || strncmp(FilePath, ParentDir, pd_cb) != 0
        || (FilePath[pd_cb] != PATH_SEPARATOR && FilePath[pd_cb] != '\0')
        || strcmp(checkBaseName, BaseName) != 0 )
    {
        s = -3;
        EPrintP("parent dir check failed! (0x%x)\n", s);
        goto clean;
    }
    s = 0;

    //memcpy(FilePath, tmpPath, pb);
    DPrint("  FilePath: %s\n", FilePath);
    
clean:
    if ( s != 0 )
    {
        sendAnswer(4, FS_ERROR_CREATE_DIR, 0, ClientSocket, IsEncrypted);
        memset(FilePath, 0, FilePathMaxSize);
    }
    if ( tmpPath )
        free(tmpPath);
    
    FLeave();
    return s;
}

void printProgress(size_t br, size_t fs)
{
    uint16_t pc = (uint16_t)(br * 100 / fs);
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
    uint8_t* file_buffer,
    uint32_t* buffer_size,
    FILE* fp
)
{
    int s = 0;

    //uint8_t* buffer_ptr = NULL;
    size_t bytes_written;

    uint8_t iv[AES_IV_SIZE];

    uint8_t* iv_ptr = ( is_encrypted ) ? file_buffer : NULL;
    size_t data_offset = ( is_encrypted ) ? AES_IV_SIZE : 0;
    uint8_t* data_ptr = &file_buffer[data_offset];
    uint32_t data_size = 0;
    
    DPrint("writeBlockToFile\n");

    // decrypt block buffer
    if ( is_encrypted )
    {
        memcpy(iv, iv_ptr, AES_IV_SIZE);
        DPrint("iv:\n");
        DPrintBytes(iv, AES_IV_SIZE);
        
        data_size = *buffer_size - AES_IV_SIZE;
        DPrint("data:\n");
        DPrintBytes(data_ptr, data_size);

        s = decryptData(data_ptr, data_size, &data_ptr, buffer_size, iv, AES_IV_SIZE);
        if ( s != 0 )
        {
            EPrintP("\nDecrypting file data failed! (0x%x)\n", s);
            sendAnswer(4, FS_ERROR_DECRYPT_FILE_DATA, *buffer_size, ClientSocket, is_encrypted);
            return s;
        }
        DPrint("  file decrypted\n");
        data_size = *buffer_size;
    }
    else
    {
        data_size = *buffer_size;
    }
    DPrint("  buffer size: 0x%x\n", *buffer_size);
    
    // write file block
    errno = 0;
    //fseek(fp, offset, SEEK_SET);
    bytes_written = fwrite(data_ptr, 1, data_size, fp);
    s = errno;

    if ( bytes_written != data_size )
    {
        EPrintP("Writing file failed! (0x%x)", s);
        sendAnswer(2, FS_ERROR_WRITE_FILE, bytes_written, ClientSocket, is_encrypted);
        if ( s == 0 )
            s = -1;
        return s;
    }
    DPrint("  block written\n");
    DPrint("  sending answer\n");

    // send file-block-received answer
    s = sendAnswer(2, FS_PACKET_SUCCESS, data_size, ClientSocket, is_encrypted);
    //if ( s != 0 )
    //{
    //    return s;
    //}

    return s;
}
