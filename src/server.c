#define _CRT_SECURE_NO_WARNINGS

#include "env.h"

#if defined(_WIN32)
#include "net/winSock.h"
#elif defined(_LINUX)
#include "net/linSock.h"
#endif
#include "net/sock.h"

#include <stdlib.h>
#include <stdio.h>
//#include <signal.h>

#include <stdint.h>
#if defined(_LINUX)
#include <errno.h>
#endif
#include <string.h>

#include "types.h"
#include "values.h"
#include "version.h"
#include "debug.h"
#include "args.h"

#if defined(_WIN32)
#include "files/FilesW.h"
#include "crypto/windows/HasherCNG.h"
#elif defined(_LINUX)
#include "files/FilesL.h"
#include "crypto/linux/HasherOpenSSL.h"
#endif
#include "crypto/crypto.h"
#include "FsHeader.h"


#define APP_NAME "FsServer"

#define FLAG_DECRYPT (0x8)

#define DATA_STATE_NONE (0x1)
#define DATA_STATE_KEY_HEADER (0x1)
#define DATA_STATE_FILE_HEADER (0x2)
#define DATA_STATE_FILE_DATA (0x3)

#define KEY_HEADER_BUFFER_SIZE (0x100)
#define BASE_NAME_MAX_SIZE (0x200)
#define SUB_DIR_MAX_SIZE (0x200)

void printUsage();
void printHelp();
int handleConnection(SOCKET ListenSocket, char* rec_dir, uint16_t flags);
bool checkHash(char* fp, uint8_t* f_hash);

bool sendAnswer(
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
    size_t *file_bytes_received,
    uint8_t **file_buffer,
    uint8_t *hash
);



char file_path[MAX_PATH];
char base_name[BASE_NAME_MAX_SIZE];
char sub_dir[BASE_NAME_MAX_SIZE];
uint8_t buffer[BUFFER_SIZE];

int running = 0;

bool parseParams(
    int argc, 
    char** argv, 
    uint16_t* flags, 
    ADDRESS_FAMILY* family, 
    char** key_path, 
    int start_i
)
{
    int i;
    char* arg;
    char* val;
    int ipv;
    bool s = true;

    for ( i = start_i; i < argc; i++ )
    {
        arg = argv[i];
        val = ( i < argc - 1 ) ? argv[i+1] : NULL;

        if ( ( arg[0] == LIN_PARAM_IDENTIFIER || arg[0] == WIN_PARAM_IDENTIFIER ) && arg[1] != 0 && arg[2] == 0 )
        {
            if ( arg[1] == 'k' )
            {
                if ( val == NULL )
                    break;

                *key_path = val;
                *flags |= FLAG_DECRYPT;
                i++;
            }
            else if ( arg[1] == 'i' )
            {
                if ( val == NULL )
                    break;

                ipv = (int)strtoul(val, NULL, 0);
                if ( ipv == 4 )
                {
                    *family = AF_INET;
                }
                else if ( ipv == 6 )
                {
                    *family = AF_INET6;
                }
                i++;
            }
        }
        else
        {
            break;
        }
    }

    return s;
}

int __cdecl main(int argc, char* argv[])
{
    int r;
    bool s = 0;
    int le;
    uint16_t flags = 0;

    SOCKET ListenSocket = INVALID_SOCKET;
    
    char *Address = NULL;
    ADDRESS_FAMILY family = AF_INET;
    struct addrinfo *addr_info = NULL;

    char *port_str = NULL;
    char *rec_dir = NULL;
    char full_path[MAX_PATH];
    char* key_path = NULL;
    char full_key_path[MAX_PATH];
    int start_i = 3;

    printf("%s - %s\n\n", APP_NAME, APP_VERSION);

    if ( isAskForHelp(argc, argv) )
    {
        printHelp();
        return 0;
    }

    if ( argc < start_i )
    {
        printUsage();
        return 0;
    }

    port_str = argv[1];
    rec_dir = argv[2];
    if (strnlen(rec_dir, MAX_PATH) >= MAX_PATH)
        rec_dir[MAX_PATH - 1] = 0;

    s = parseParams(argc, argv, &flags, &family, &key_path, start_i);
    if ( !s )
    {
        printUsage();
        return -1;
    }
    
#ifdef DEBUG_PRINT
    printf("port: %s\n", port_str);
    printf("family: %s\n", family==AF_INET?"AF_INET":(family==AF_INET6)?"AF_INET6":"NONE");
    printf("key_path: %s\n", key_path);
    printf("rec_dir: %s\n", rec_dir);
#endif

    memset(full_key_path, 0, MAX_PATH);
    if ( key_path != NULL )
    {
        s = (int)getFullPathName(key_path, full_key_path, NULL);
        if ( !s )
        {
            printf("ERROR: Key file \"%s\" not found!", key_path);
            return -1;
        }
        s = checkPath(full_key_path, false);
        if ( !s )
        {
            printf("ERROR: Key file \"%s\" not found!", full_key_path);
            return -1;
        }
    }

    memset(full_path, 0, MAX_PATH);
    s = (int)getFullPathName(rec_dir, full_path, NULL);
    if ( !s )
    {
        printf("ERROR: Directory \"%s\" not found!", full_path);
        return 0;
    }
    s = checkPath(full_path, true);
    if (!s)
    {
        printf("ERROR: Directory \"%s\" not found!", full_path);
        return 0;
    }
    printf("save dir: %s\n\n", full_path);
    
    s = initConnection(&addr_info, family, Address, port_str, &ListenSocket, AI_PASSIVE);
    if ( s != 0 )
    {
        goto clean;
    }
    
//    int iOptval = 1;
//    s = setsockopt(ListenSocket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char*)&iOptval, sizeof(iOptval));
//    if ( s == SOCKET_ERROR)
//    {
//        printf("ERROR (0x%x): setsockopt for SO_EXCLUSIVEADDRUSE failed.\n", WSAGetLastError());
//        return -1;
//    }

    // Setup the TCP listening socket
    errno = 0;
    r = bind(ListenSocket, addr_info->ai_addr, (int)addr_info->ai_addrlen);
    if ( r == SOCKET_ERROR )
    {
        le = getLastSError();
        printf("bind failed with error: 0x%x\n", le);
        s = le;
        goto clean;
    }
#ifdef DEBUG_PRINT
    printf("socket bound\n");
#endif

    freeaddrinfo(addr_info);
    addr_info = NULL;

    errno = 0;
    r = listen(ListenSocket, 1);
    if ( r == SOCKET_ERROR )
    {
        le = getLastSError();
        printf("listen failed with error: %d\n", le);
        s = le;
        goto clean;
    }
#ifdef DEBUG_PRINT
    printf("listening\n");
#endif
    
    if ( flags&FLAG_DECRYPT )
    {
#ifdef DEBUG_PRINT
        printf("Init Crypto\n");
#endif
        s = c_init(full_key_path, INIT_PRIV_KEY);
        if ( s != 0 )
        {
            s = -4;
            printf("ERROR (0x%x): Initializing crypto failed.", -4);
            goto clean;
        }
    }
    
    // enter accept loop
    running = 1;
    while ( running )
    {
        handleConnection(ListenSocket, full_path, flags);
        printf("\n\n");
    }

clean:
    if ( addr_info != NULL )
        freeaddrinfo(addr_info);
    cleanUp(&ListenSocket);
    if ( flags&FLAG_DECRYPT )
        c_clean();

    return s;
}

int handleConnection(SOCKET ListenSocket, char* rec_dir, uint16_t flags)
{
    uint32_t result;
    int le;
    bool is_encrypted = flags&FLAG_DECRYPT;
    
    SOCKET ClientSocket = INVALID_SOCKET;
    SOCKADDR_STORAGE addr;
    socklen_t addr_ln = sizeof(SOCKADDR_STORAGE);

    size_t file_bytes_received = 0;
    int s = 0;

    uint8_t *file_buffer = NULL;
    
    
    int data_state = (is_encrypted) ? DATA_STATE_KEY_HEADER : DATA_STATE_FILE_HEADER;
    FsKeyHeader key_header;
    FsFileHeader file_header;
    uint8_t hash[SHA256_BYTES_LN];

    // Accept a client socket
    printf("waiting for connection...\n");
    ClientSocket = accept(ListenSocket, (PSOCKADDR)&addr, &addr_ln);
    if ( ClientSocket == INVALID_SOCKET )
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
        memset(buffer, 0, BUFFER_SIZE);
#ifdef DEBUG_PRINT
        printf("Waiting for data.\n");
#endif
        result = recv(ClientSocket, (char*)buffer, BUFFER_SIZE, 0);
        if ( result > 0 )
        {
            s = handleData(
                    ClientSocket, 
                    result, 
                    &data_state, 
                    &key_header,
                    &file_header,
                    is_encrypted,
                    rec_dir,
                    &file_bytes_received,
                    &file_buffer,
                    hash
                );
            if ( s != 0 )
                goto clean;
        }
        else if ( result == 0 )
        {
            printf("\n\n");
            printf("Connection closing...\n");
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
    shutdown(ClientSocket, SD_BOTH);
    //if (result == SOCKET_ERROR)
    //{
    //    le = getLastSError();
    //    printf("shutdown failed with error: %d\n", le);
    //    s = -1;
    //}

    closeSocket(&ClientSocket);

    memset(&key_header, 0, sizeof(key_header));

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
    size_t *file_bytes_received,
    uint8_t **file_buffer,
    uint8_t *hash
)
{
    uint8_t* buffer_ptr = NULL;

    FILE* fp = NULL;

    size_t bytes_written;
    uint32_t bytes_received = result;

    int pc;
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
        printf("encrypted key header");
        printMemory(buffer, bytes_received, 0x10, 0);
#endif

        s = decryptKey(
            buffer, 
            bytes_received, 
            &buffer_ptr, 
            &result
        );
        if ( s != 0 )
        {
            printf("\nERROR (0x%x): Decrypting key header failed!\n", s);
            // can't really send an answer without decrypted key unless sending it unencrypted
            //sendAnswer(1, FS_ERROR_DECRYPT_AES_KEY, bytes_received, ClientSocket, is_encrypted, key_header);
            goto clean;
        }
#ifdef DEBUG_PRINT
        printf("decrypted key header");
        printMemory(buffer_ptr, result, 0x10, 0);
#endif

        if ( key_header->type != FS_TYPE_KEY_HEADER )
        {
            printf("\nERROR (0x%x): Expected key header, but got 0x%"PRIx64"\n", s, key_header->type);
            // can't really send an answer without decrypted key unless sending it unencrypted
            goto clean;
        }

#ifdef DEBUG_PRINT
        printf("key header:\n");
        printFsKeyHeader(key_header, " - ");
#endif

        // generate key out of secret
        s = generateAESKey(key_header->secret, AES_SECRET_SIZE);
        if ( s != 0 )
        {
            printf("\nERROR (0x%x): Generating AES key failed!\n", s);
            // can't really send an answer without generated key unless sending it unencrypted
            //sendAnswer(1, FS_ERROR_GENERATE_AES_KEY, bytes_received, ClientSocket, is_encrypted, key_header);
            goto clean;
        }

        // send header-received answer
        // TODO: send priv.key encrypted/signed sha256 of header as a signature
        errsv = sendAnswer(1, FS_PACKET_SUCCESS, bytes_received, ClientSocket, is_encrypted, key_header);
        if ( !errsv )
        {
            s = -1;
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
            printf("encrypted file header");
            printMemory(buffer, result, 0x10, 0);
#endif

            buffer_size = BUFFER_SIZE;
            buffer_ptr = (uint8_t*)buffer;
            s = decryptData(buffer, result, &buffer_ptr, &buffer_size, key_header->iv, AES_IV_SIZE);
            if ( s != 0 )
            {
                printf("\nERROR (0x%x): Encrypting file header failed!\n", s);
                sendAnswer(4, FS_ERROR_DECRYPT_FILE_HEADER, 0, ClientSocket, is_encrypted, key_header);
                goto clean;
            }
#ifdef DEBUG_PRINT
            printf("decrypted file header");
            printMemory(buffer, buffer_size, 0x10, 0);
#endif
        }
        else
        {
            buffer_size = result;
        }

        loadFsFileHeader(buffer, file_header, base_name, BASE_NAME_MAX_SIZE, sub_dir, SUB_DIR_MAX_SIZE, hash, SHA256_BYTES_LN);

        if ( file_header->type != FS_TYPE_FILE_HEADER )
        {
            printf("\nERROR (0x%x): Expected file header, but got 0x%"PRIx64"\n", s, key_header->type);
            sendAnswer(4, FS_ERROR_WRONG_HEADER_TYPE, 0, ClientSocket, is_encrypted, key_header);
            goto clean;
        }

        if ( file_header->sub_dir_ln != 0 )
        {
            memset(file_path, 0, MAX_PATH);
            convertPathSeparator(sub_dir);
            sprintf(file_path, "%s%c%s", rec_dir, PATH_SEPARATOR, sub_dir);
            errsv = mkdir_r(file_path);
            if ( errsv != 0 )
            {
                sendAnswer(4, FS_ERROR_CREATE_DIR, 0, ClientSocket, is_encrypted, key_header);
                s = -1;
                goto clean;
            }
        }

        memset(file_path, 0, MAX_PATH);
        sprintf(file_path, "%s%c%s%c%s", rec_dir, PATH_SEPARATOR, sub_dir, PATH_SEPARATOR, base_name);
        //sprintf(file_path, "%s%c%s", rec_dir, PATH_SEPARATOR, base_name);
        file_path[MAX_PATH - 1] = 0;

        printFsFileHeader(file_header, " - ");
        printf(" - file_path: %s\n", file_path);
        
        // allocate file buffer
        (*file_buffer) = (uint8_t*)malloc(file_header->file_size);
        if ( !(*file_buffer) )
        {
            printf("Error (0x%x): malloc file buffer failed\n", getLastError());
            sendAnswer(4, FS_ERROR_ALLOC_FILE_BUFFER, 0, ClientSocket, is_encrypted, key_header);
            s = -1;
            goto clean;
        }

        // send header-received answer
        errsv = sendAnswer(1, FS_PACKET_SUCCESS, bytes_received, ClientSocket, is_encrypted, key_header);
        if ( !errsv )
        {
            s = -1;
            goto clean;
        }
        
        *data_state = DATA_STATE_FILE_DATA;
    }
    else if ( *data_state == DATA_STATE_FILE_DATA )
    {
#ifdef DEBUG_PRINT
        printf("File data received: 0x%x\n", result);
#endif

        
#ifdef DEBUG_PRINT
        printf("copy bytes into file buffer\n");
#endif
        if ( !(*file_buffer) )
        {
            printf("Error: No file buffer found\n");
            sendAnswer(4, FS_ERROR_NULL_FILE_BUFFER, 0, ClientSocket, is_encrypted, key_header);
            s = -1;
            goto clean;
        }

        memcpy(&(*file_buffer)[*file_bytes_received], buffer, bytes_received);
        
        *file_bytes_received += bytes_received;

        pc = (int)((float)*file_bytes_received / (float)file_header->file_size * 100.0);
        printf("Bytes received: 0x%zx/0x%zx (%d%%).", *file_bytes_received, file_header->file_size, pc);
#ifdef DEBUG_PRINT
        printf("\n");
#else
        printf("\r");
#endif

        if ( *file_bytes_received == file_header->file_size )
        {
            // create file
            errno = 0;
            fp = fopen(file_path, "wb");
            errsv = errno;
            if ( fp == NULL )
            {
                printf("ERROR (0x%x): Creating file \"%s\" failed.\n", errsv, file_path);
                sendAnswer(2, FS_ERROR_CREATE_FILE, 0, ClientSocket, is_encrypted, key_header);
                s = -1;
                goto clean;
            }
#ifdef DEBUG_PRINT
            printf(" - file created\n");
#endif
                
            // decrypt file buffer
            if ( is_encrypted )
            {
                buffer_size = (uint32_t)file_header->file_size;
                buffer_ptr = (uint8_t*)(*file_buffer);
                s = decryptData((*file_buffer), buffer_size, &buffer_ptr, &buffer_size, key_header->iv, AES_IV_SIZE);
                if ( s != 0 )
                {
                    printf("\nERROR (0x%x): Decrypting file data failed!\n", s);
                    sendAnswer(4, FS_ERROR_DECRYPT_FILE_DATA, buffer_size, ClientSocket, is_encrypted, key_header);
                    goto clean;
                }
#ifdef DEBUG_PRINT
                printf("file decrypted\n");
#endif
            }
            else
            {
                buffer_size = (uint32_t)file_header->file_size;
            }
#ifdef DEBUG_PRINT
            printf("file size: 0x%x\n", buffer_size);
#endif
            
            // write file
            errno = 0;
            bytes_written = fwrite((*file_buffer), 1, buffer_size, fp);
            errsv = errno;

            if ( bytes_written != buffer_size )
            {
                printf("ERROR (0x%x): Writing file failed.", errsv);
                sendAnswer(2, FS_ERROR_WRITE_FILE, bytes_written, ClientSocket, is_encrypted, key_header);
                s = -1;
                goto clean;
            }
#ifdef DEBUG_PRINT
            printf("file written\n");
#endif

            // send file-fully-received answer
            errsv = sendAnswer(2, FS_PACKET_SUCCESS, *file_bytes_received, ClientSocket, is_encrypted, key_header);
            if ( !errsv )
            {
                s = -1;
                goto clean;
            }
            printf("\n");
            printf("File received successfully\n");
            
            if ( (*file_buffer) )
                free((*file_buffer));
            (*file_buffer) = NULL;

            // Close before calculating hash
            // The buffer could be used too to calculate the hash.
            if ( fp ) // always true
                fclose(fp);
            fp = NULL;

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
    if ( fp )
        fclose(fp);
    fp = NULL;
    if ( s != 0 )
    {
        if ( (*file_buffer) )
            free((*file_buffer));
        (*file_buffer) = NULL;
    }
    return s;
}

bool sendAnswer(uint8_t state, uint32_t code, size_t info, SOCKET sock, bool is_encrypted, FsKeyHeader* key_header)
{
    int errsv;
    sendlen_t bytes_sent;
    int s;
    FsAnswer a = { .state = state, .code = code, .info = info };
    s = generateRand(a.garbage, AES_IV_SIZE);
    if ( s != 0 )
    {
        printf("\nERROR (0x%x): Generating IV failed!\n", s);
        return false;
    }
    uint32_t answer_size = (uint32_t)saveFsAnswer(buffer, &a);
    uint32_t buffer_size = BUFFER_SIZE;
    uint8_t* buffer_ptr = (uint8_t*)buffer;
#ifdef DEBUG_PRINT
    printf("send answer\n");
#endif
    if ( is_encrypted )
    {
#ifdef DEBUG_PRINT
        printf("buffer:");
        printMemory(buffer, answer_size, 0x10, 0);
#endif
        s = encryptData(
            buffer, 
            answer_size, 
            &buffer_ptr, 
            &buffer_size, 
            key_header->iv, 
            AES_IV_SIZE
        );
        if ( s != 0 )
        {
            printf("\nERROR (0x%x): Encrypting file header failed!\n", s);
            return false;
        }
#ifdef DEBUG_PRINT
        printf("encrypted:");
        printMemory(buffer_ptr, buffer_size, 0x10, 0);
#endif
    }
    else
    {
        buffer_size = answer_size;
    }

    errno = 0;
    bytes_sent = send(sock, (char*)buffer, buffer_size, 0);
#ifdef DEBUG_PRINT
    printf(" - bytes_sent: 0x%x\n", (int)bytes_sent);
#endif
    if ( bytes_sent < 0 )
    {
        errsv = getLastSError();
        printf("ERROR (0x%x): Sending answer failed.\n", errsv);
        return false;
    }
    return true;
}

bool checkHash(char* path, uint8_t* f_hash)
{
    uint8_t hash[SHA256_BYTES_LN];
    int s;

    printf("Calculating hash...");
    s = sha256File(path, hash, SHA256_BYTES_LN);
    if ( s != 0 )
    {
        printf("\rERROR (0x%x: Calculating hash failed!\n", s);
        return false;
    }
    printf("\r");
    printHash(hash, SHA256_BYTES_LN, " - hash: ", "\n");

    return memcmp(hash, f_hash, SHA256_BYTES_LN) == 0;
}

void printUsage()
{
    printf("Usage: %s port rec%cdir [/i 4|6] [/k path/to/key]\n", APP_NAME, PATH_SEPARATOR);
    printf("\n");
    printf("Version: %s\n", APP_VERSION);
    printf("Last changed: %s\n", APP_LAST_CHANGED);
}

void printHelp()
{
    printUsage();
    printf("\nOptions\n");
    printf(" - port : The server listening port.\n");
    printf(" - rec%cdir : The existing base directory, the shared files are stored in.\n", PATH_SEPARATOR);
    printf(" - %ci : IP version 4 (default) or 6.\n", PARAM_IDENTIFIER);
    printf(" - %ck : Path to a private key.der file to decrypt encrypted data from the client.\n", PARAM_IDENTIFIER);
}
