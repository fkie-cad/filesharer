#define _CRT_SECURE_NO_WARNINGS

#include "env.h"

#if defined(_WIN32)
    #define _CRT_SECURE_NO_WARNINGS
    #include "net/winSock.h"
#elif defined(_LINUX)
    #include "net/linSock.h"
#endif
#include "net/sock.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#if defined(_LINUX)
#include <errno.h>
#endif



#include "types.h"
#include "values.h"
#include "version.h"
#include "debug.h"
#include "args.h"
#if defined(_WIN32)
#include "files/filesW.h"
#include "crypto/windows/HasherCNG.h"
#elif defined(_LINUX)
#include "files/FilesL.h"
#include "crypto/linux/HasherOpenSSL.h"
#endif
#include "crypto/crypto.h"
#include "FsHeader.h"

// callback params struct for directory sharing
typedef struct _FCBParams {
    SOCKET sock;
    const char* start_dir;
    uint16_t flags;
    bool killed;
} FCBParams, *PFCBParams;


#define APP_NAME "FsClient"

#define FLAG_CHECK_FILE_HASH (0x1)
#define FLAG_RECURSIVE (0x2)
#define FLAG_FLAT_COPY (0x4)
#define FLAG_ENCRYPT (0x8)

//char full_path[MAX_PATH];
uint8_t buffer[BUFFER_SIZE];


void printUsage();
void printHelp();
bool sendFile(const char* file_path, const char* base_name, uint16_t sd_id, uint16_t sd_ln, SOCKET s, uint16_t flags);
int sendDir(const char* dir_path, SOCKET s, uint16_t flags);
void fileCB(char* file, char* base_name, void* p);
bool receiveAnswer(PFsAnswer answer, SOCKET sock, bool is_encrypted, FsKeyHeader* key_header);

bool parseParams(int argc, char** argv, uint16_t* flags, ADDRESS_FAMILY* family, char** key_path, int* start_file_i)
{
    int i;
    char* arg;
    char* val;
    int ipv;

    for ( i = *start_file_i; i < argc; i++ )
    {
        arg = argv[i];
        val = ( i < argc - 1 ) ? argv[i+1] : NULL;

        if ( ( arg[0] == LIN_PARAM_IDENTIFIER || arg[0] == WIN_PARAM_IDENTIFIER ) && arg[1] != 0 && arg[2] == 0 )
        {
            if ( arg[1] == 'c' )
            {
                *flags |= FLAG_CHECK_FILE_HASH;
            }
            else if ( arg[1] == 'r' )
            {
                *flags |= FLAG_RECURSIVE;
            }
            else if (arg[1] == 'f')
            {
                *flags |= FLAG_FLAT_COPY;
            }
            else if (arg[1] == 'k')
            {
                if ( val == NULL )
                    break;
                *key_path = val;
                *flags |= FLAG_ENCRYPT | FLAG_CHECK_FILE_HASH;
                i++;
            }
            else if (arg[1] == 'i')
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

    *start_file_i = i;
    return *start_file_i < argc;
}

int __cdecl main(int argc , char *argv[])
{
    SOCKET sock = INVALID_SOCKET;
    PADDRINFOA addr_info = NULL;
    ADDRESS_FAMILY family = AF_INET;
    
    char * ip;
    char* port_str;
    uint16_t flags = 0;
    char* key_path = NULL;
    char full_key_path[MAX_PATH];

    int nr_of_files;
    int i ;
    int j;
    int start_file_i = 3;

    char path[MAX_PATH];
    const char* base_name = NULL;

    bool s;
    int errsv;


    printf("%s - %s\n\n", APP_NAME, APP_VERSION);

    if ( isAskForHelp(argc, argv) )
    {
        printHelp();
        return 0;
    }
    
    if ( argc <= start_file_i )
    {
        printUsage();
        return 0;
    }
    
    ip = argv[1];
    port_str = argv[2];
    s = parseParams(argc, argv, &flags, &family, &key_path, &start_file_i);
    if ( !s )
    {
        printUsage();
        return -1;
    }
    nr_of_files = argc - start_file_i;
    
    s = initConnection(&addr_info, family, ip, port_str, &sock, 0);
    if ( s != 0 )
    {
        goto clean;
    }
    s = connectSock(sock, addr_info);
    if ( s != 0 )
    {
        goto clean;
    }

    // check key path
    if ( key_path != NULL )
    {
        memset(full_key_path, 0, MAX_PATH);
        s = (int)getFullPathName(key_path, MAX_PATH, full_key_path, NULL);
        if ( !s )
        {
            errsv = getLastError();
            printf("ERROR (0x%x): Get full key path failed.", errsv);
            s = -3;
            goto clean;
        }
        if ( !fileExists(full_key_path) )
        {
            s = -2;
            printf("ERROR (0x%x): Key file not found.", -2);
            goto clean;
        }

        s = c_init(full_key_path, INIT_PUB_KEY);
        if ( s != 0 )
        {
            s = -4;
            printf("ERROR (0x%x): Init pub key failed.", -4);
            goto clean;
        }
    }

    // file loop
    for ( i = start_file_i, j=1; i < argc; i++, j++ )
    {
#ifdef DEBUG_PRINT
        printf("argv[%d]: %s\n", i, argv[i]);
#endif
        printf("Path %d / %d : %s\n", j, nr_of_files, argv[i]);

        if ( strnlen(argv[i], MAX_PATH) >= MAX_PATH )
            argv[i][MAX_PATH - 1] = 0;
        
        memset(path, 0, MAX_PATH);
        s = (int)getFullPathName(argv[i], MAX_PATH ,path, &base_name);
        if ( !s )
        {
            errsv = getLastError();
            printf("ERROR (0x%x): Get full path failed.", errsv);
            s = -1;
            break;
        }
        cropTrailingSlash(path);
#ifdef DEBUG_PRINT
        printf(" - path: %s\n", path);
        printf(" - base_name: %s\n", base_name);
#endif
        if ( fileExists(path) )
            sendFile(path, base_name, 0, 0, sock, flags);
        else if ( dirExists(path) )
            sendDir(path, sock, flags);
        else
            printf("ERROR: Path \"%s\" does not exist!\n", path);
//        if ( !s )
//            break;
    }

    printf("Bye.\n");
clean:
    if ( addr_info )
        freeaddrinfo(addr_info);
    cleanUp(&sock);
    if ( flags&FLAG_ENCRYPT )
        c_clean();

    return s;
}

bool sendFile(const char* file_path, const char* base_name, uint16_t sd_id, uint16_t sd_ln, SOCKET sock, uint16_t flags)
{
    FILE* fp = NULL;
    int bytes_read;
    sendlen_t bytes_sent;
    size_t file_bytes_sent;

    FsKeyHeader key_header;
    FsFileHeader file_header;
    FsAnswer answer;
    uint8_t* buffer_ptr = NULL;

    bool is_encrypted = flags&FLAG_ENCRYPT;
    uint32_t header_size;
    bool ret = true;
    uint32_t buffer_size;
    int errsv;
    int pc;
    int s;

    uint8_t* file_buffer = NULL;

    uint8_t hash[SHA256_BYTES_LN];

    printf("send: %s\n", file_path);

    errno = 0;
    fp = fopen(file_path, "rb");
    errsv = errno;
    if ( fp == NULL )
    {
        printf("ERROR (0x%x): Can't open file \"%s\".\n", errsv, file_path);
        return false;
    }
    
    memset(&key_header, 0, sizeof(key_header));
    memset(&file_header, 0, sizeof(file_header));

    s = getFileSize(file_path, &file_header.file_size);
    if ( s != 0 || file_header.file_size == 0 )
    {
        printf("INFO: File size is 0!\n");
        ret = false;
        goto exit;
    }

    if ( flags&FLAG_CHECK_FILE_HASH )
    {
        memset(hash, 0, SHA256_BYTES_LN);
        printf("Calculating hash...");
        s = sha256File(file_path, hash, SHA256_BYTES_LN);
        if ( s != 0 )
        {
            printf("\nERROR (0x%x): Calculating hash failed!\n", s);
            ret = false;
            goto exit;
        }
        printf("\r");
    }

    // send RSA encrypted AES secret and IV
    if ( is_encrypted )
    {
        s = saveFsKeyHeader(&key_header);
        if ( s != 0 )
        {
            printf("ERROR (0x%x): saveFsKeyHeader failed!\n", s);
            ret = false;
            goto exit;
        }

        s = generateAESKey(key_header.secret, AES_SECRET_SIZE);
        if ( s != 0 )
        {
            printf("ERROR (0x%x): Generating AES key failed!\n", s);
            return s;
        }

#ifdef DEBUG_PRINT
        printf("key header:\n");
        printFsKeyHeader(&key_header, " - ");
#endif

        buffer_size = BUFFER_SIZE;
        buffer_ptr = (uint8_t*)buffer;
        s = encryptKey(
            (uint8_t*)&key_header, 
            FS_KEY_HEADER_SIZE,
            &buffer_ptr, 
            &buffer_size
        );
        if ( s != 0 )
        {
            printf("ERROR (0x%x): Encrypting key header failed!\n", s);
            ret = false;
            goto exit;
        }
#ifdef DEBUG_PRINT
        printf("encrypted key header");
        printMemory(buffer, buffer_size, 0x10, 0);
#endif

        bytes_sent = send(sock, (char*)buffer, buffer_size, 0);
        if ( bytes_sent < 0 )
        {
            errsv = getLastSError();
            printf("ERROR (0x%x): Send header failed.\n", errsv);
            ret = false;
            goto exit;
        }
#ifdef DEBUG_PRINT
        printf("bytes sent 0x%x\n", (int)bytes_sent);
        printf("Waiting for answer.\n");
#endif 

        // Wait for key-header-received answer from server to keep it separated
        s = receiveAnswer(&answer, sock, is_encrypted, &key_header);
        if ( !s )
        {
            ret = false;
            goto exit;
        }
#ifdef DEBUG_PRINT
        printf("Answer OK.\n");
        printf("Sending file header.\n");
#endif
    }

    // allocate file buffer
    buffer_size = (uint32_t)file_header.file_size + AES_STD_BLOCK_SIZE;
    file_buffer = (uint8_t*)malloc(buffer_size);
    if ( file_buffer == NULL )
    {
        printf("Error (0x%x): malloc file buffer failed\n", getLastError());
        ret = false;
        goto exit;
    }
    
    // read entire file into buffer
    errno = 0;
    bytes_read = (int) fread(file_buffer, 1, file_header.file_size, fp);
    errsv = errno;
    if ( bytes_read == 0 || bytes_read != file_header.file_size )
    {
        printf("ERROR (0x%x): Read file bytes failed.\n", errsv);
        ret = false;
        goto exit;
    }

    // encrypt entire file 
    // done before sending file header, because the result might be greater then file size
    if ( is_encrypted )
    {
        //buffer_size = file_header.file_size + AES_STD_BLOCK_SIZE;
        buffer_ptr = (uint8_t*)file_buffer;
        s = encryptData(
            file_buffer, 
            (uint32_t)file_header.file_size, 
            &buffer_ptr, 
            &buffer_size, 
            key_header.iv, 
            AES_IV_SIZE
        );
        if ( s != 0 )
        {
            printf("\nERROR (0x%x): Encrypting file data failed!\n", s);
            goto exit;
        }

        // adjust file size
        file_header.file_size = buffer_size; 
    }

    // fill file header
    s = generateRand(file_header.garbage, AES_IV_SIZE);
    if ( s != 0 )
    {
        printf("\nERROR (0x%x): Generating Garbage failed!\n", s);
        ret = false;
        goto exit;
    }
    file_header.hash_ln = (flags&FLAG_CHECK_FILE_HASH) ? SHA256_BYTES_LN : 0;
    file_header.hash = (flags&FLAG_CHECK_FILE_HASH) ? hash : NULL;
    file_header.base_name_ln = (uint16_t)strlen(base_name);
    file_header.sub_dir_ln = sd_ln;
    file_header.sub_dir = &file_path[sd_id];
    file_header.base_name = (char*)base_name;
    header_size = (uint32_t)saveFsFileHeader(buffer, &file_header);
    printf("header (0x%x):                \n", header_size);
    printFsFileHeader(&file_header, " - ");
    
#ifdef DEBUG_PRINT
    printf(" - &file_path[%u]: %.*s (%u)\n", sd_id, sd_ln, &file_path[sd_id], sd_ln);
#endif
    
    // encrypt file header
    if ( is_encrypted )
    {
#ifdef DEBUG_PRINT
        printf("file header");
        printMemory(buffer, header_size, 0x10, 0);
#endif

        buffer_size = BUFFER_SIZE;
        buffer_ptr = (uint8_t*)buffer;
        s = encryptData(
            buffer, 
            header_size, 
            &buffer_ptr, 
            &buffer_size, 
            key_header.iv, 
            AES_IV_SIZE
        );
        if ( s != 0 )
        {
            printf("\nERROR (0x%x): Encrypting file header failed!\n", s);
            ret = false;
            goto exit;
        }
#ifdef DEBUG_PRINT
        printf("encrypted file header (0x%x)", buffer_size);
        printMemory(buffer, buffer_size, 0x10, 0);
#endif
    }
    else
    {
        buffer_size = header_size;
    }
    
#ifdef DEBUG_PRINT
    printf(" - header_size 0x%x\n", header_size);
#endif
    bytes_sent = send(sock, (char*)buffer, buffer_size, 0);
    if (bytes_sent < 0)
    {
        errsv = getLastSError();
        printf("ERROR (0x%x): Send header failed.\n", errsv);
        ret = false;
        goto exit;
    }
#ifdef DEBUG_PRINT
    printf("bytes sent 0x%x\n", (int)bytes_sent);
    printf("Waiting for answer.\n");
#endif

    // Wait for header-received answer from server to keep it separated from file
    s = receiveAnswer(&answer, sock, is_encrypted, &key_header);
    if ( !s )
    {
        ret = false;
        goto exit;
    }
#ifdef DEBUG_PRINT
    printf("Answer OK.\n");
    printf("Sending file.\n");
#endif

    // send file buffer in blocks of BUFFER_SIZE
    file_bytes_sent = 0;
    buffer_size = (uint32_t)file_header.file_size;
    bytes_read = BUFFER_SIZE;
    while ( file_bytes_sent < buffer_size )
    {
        if ( file_bytes_sent + BUFFER_SIZE > buffer_size )
        {
            bytes_read = buffer_size - (uint32_t)file_bytes_sent;
        }

        errno = 0;
        bytes_sent = send(sock, (char*)&file_buffer[file_bytes_sent], bytes_read, 0);
#ifdef DEBUG_PRINT
        printf("bytes_sent: 0x%x\n", (int)bytes_sent);
#endif
        if ( bytes_sent < 0 || bytes_sent != bytes_read )
        {
            errsv = getLastSError();
            printf("ERROR (0x%x): Send file bytes failed.\n", errsv);
            ret = false;
            goto exit;
        }

        file_bytes_sent += bytes_sent;

        pc = (int)((float)file_bytes_sent / (float)buffer_size * 100.0);
#ifdef DEBUG_PRINT
        printf("Bytes sent: 0x%zx/0x%x (%d%%).\n", file_bytes_sent, buffer_size, pc);
#else
        printf("Bytes sent: 0x%zx/0x%x (%d%%).\r", file_bytes_sent, buffer_size, pc);
#endif

        // end of file
        //if ( file_bytes_sent >= buffer_size)
        //    break;
    }
#ifdef DEBUG_PRINT
    printf("file finished\n");
#endif
    
    // Wait for file-fully-received answer from server
    s = receiveAnswer(&answer, sock, is_encrypted, &key_header);
    if ( !s )
    {
        ret = false;
        //goto exit;
    }

exit:
    printf("\n\n");
    fclose(fp);
    if ( file_buffer != NULL )
        free(file_buffer);
    file_buffer = NULL;
    memset(&key_header, 0, sizeof(key_header));
    delete_AESKey();

    return ret;
}

int sendDir(const char* dir_path, SOCKET sock, uint16_t flags)
{
#ifdef DEBUG_PRINT
    printf("sendDir(%s)\n", dir_path);
    printf(" - check_file: %d\n", flags&FLAG_CHECK_FILE_HASH);
    printf(" - recursive: %d\n", flags&FLAG_RECURSIVE);
    printf(" - flat: %d\n", flags&FLAG_FLAT_COPY);
#endif
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
    
#ifdef DEBUG_PRINT
    printf("fileCB: %s\n", file);
    printf(" - start folder: %s (%zu)\n", params->start_dir, start_dir_size);
    printf(" - sub folder: %.*s (%d)\n", sd_ln, &file[sd_id], sd_ln);
    printf(" - base_name: %s (%zu)\n", base_name, base_name_size);
    printf(" - sub_dir_id: %u\n", sd_id);
#endif

#ifdef DEBUG_PRINT
    bool s =
#endif
    sendFile(file, base_name, sd_id, sd_ln, params->sock, params->flags);
#ifdef DEBUG_PRINT
    printf(" - send file success: %d\n", s);
#endif
//    if ( !s )
//        params->killed = true;
}

bool receiveAnswer(PFsAnswer answer, SOCKET sock, bool is_encrypted, FsKeyHeader* key_header)
{
    memset(buffer, 0, BUFFER_SIZE);
    memset(answer, 0, sizeof(*answer));
    reclen_t bytes_rec;
    bytes_rec = recv(sock, (char*)buffer, BUFFER_SIZE, 0);
    if ( bytes_rec == SOCKET_ERROR )
    {
#ifdef ERROR_PRINT
        printf("\nERROR (0x%x): recveiving answer failed!\n", getLastSError());
        return false;
#endif
    }
#ifdef DEBUG_PRINT
    printf("received bytes: 0x%x\n", (int)bytes_rec);
#endif
    uint32_t buffer_size;
    uint8_t* buffer_ptr = (uint8_t*)buffer;
    int s;

    if ( is_encrypted )
    {
#ifdef DEBUG_PRINT
//        printFsKeyHeader(key_header, " - ");
        printf("encrypted buffer");
        printMemory(buffer, bytes_rec, 0x10, 0);
#endif
        buffer_size = BUFFER_SIZE;
        s = decryptData(buffer, bytes_rec, &buffer_ptr, &buffer_size, key_header->iv, AES_IV_SIZE);
        if ( s != 0 )
        {
            printf("\nERROR (0x%x): Decrypting answer failed!\n", s);
            return false;
        }
#ifdef DEBUG_PRINT
        printf("decrypted buffer");
        printMemory(buffer_ptr, buffer_size, 0x10, 0);
#endif
    }
    else
    {
        buffer_size = bytes_rec;
    }

    s = loadFsAnswer(buffer, buffer_size, answer);
    if ( s != 0 )
    {
        printf("ERROR: Loading answer failed.\n");
        return false;
    }
    if ( answer->type != FS_TYPE_ANSWER)
    {
        printf("ERROR: Expected Answer, got 0x%"PRIx64".\n", answer->type);
        return false;
    }

#ifdef DEBUG_PRINT
    printf("receiveAnswer\n");
    printf(" - state: 0x%x\n", answer->state);
    printf(" - code: 0x%x\n", answer->code);
    printf(" - info: 0x%zx\n", answer->info);
#endif
    if ( answer->code != FS_PACKET_SUCCESS )
    {
        if ( answer->code == FS_ERROR_RECV_HEADER )
            printf("ERROR (0x%x): Header receiving failed!\n", answer->code);
        else if ( answer->code == FS_ERROR_CREATE_FILE )
            printf("ERROR (0x%x): Creating file failed!\n", answer->code);
        else if ( answer->code == FS_ERROR_WRITE_FILE )
            printf("ERROR (0x%x): Writing file failed!\n", answer->code);
        else if ( answer->code == FS_ERROR_CREATE_DIR )
            printf("ERROR (0x%x): Createing directory failed!\n", answer->code);
        else if ( answer->code == FS_ERROR_ALLOC_FILE_BUFFER )
            printf("ERROR (0x%x): Allocating file buffer failed!\n", answer->code);
        else if ( answer->code == FS_ERROR_DECRYPT_AES_KEY )
            printf("ERROR (0x%x): Decrypting AES key failed!\n", answer->code);
        else if ( answer->code == FS_ERROR_GENERATE_AES_KEY )
            printf("ERROR (0x%x): Generating AES key failed!\n", answer->code);
        else if ( answer->code == FS_ERROR_DECRYPT_FILE_HEADER )
            printf("ERROR (0x%x): Decrypting file header failed!\n", answer->code);
        else if ( answer->code == FS_ERROR_DECRYPT_FILE_DATA )
            printf("ERROR (0x%x): Decrypting file data failed!\n", answer->code);
        else 
            printf("ERROR (0x%x): ...!\n", answer->code);
        printFsAnswer(answer, " - ");
        return false;
    }
    
    return true;
}

void printUsage()
{
    printf("Usage: %s ip port [%cc] [%cr] [%cf] [%ci 4] [%ck pub.key] path [another%cpath ...]\n", APP_NAME, PARAM_IDENTIFIER, PARAM_IDENTIFIER, PARAM_IDENTIFIER, PARAM_IDENTIFIER, PARAM_IDENTIFIER, PATH_SEPARATOR);
    printf("\n");
    printf("Version: %s\n", APP_VERSION);
    printf("Last changed: %s\n", APP_LAST_CHANGED);
}

void printHelp()
{
#ifdef _WIN32
    const char* key_type = "der";
#else
    const char* key_type = "pem";
#endif

    printUsage();
    printf("\nOptions\n");
    printf(" - ip : The server ip port.\n");
    printf(" - port : The server listening port.\n");
    printf(" - %cc : Check file hashes of transmitted files. Default if transferred encrypted.\n", PARAM_IDENTIFIER);
    printf(" - %cr : Copy dirs recursively.\n", PARAM_IDENTIFIER);
    printf(" - %cf : Flatten copied dirs to base dir. Only meaningful if /r is set,\n", PARAM_IDENTIFIER);
    printf(" - %ci : IP version 4 (default) or 6.\n", PARAM_IDENTIFIER);
    printf(" - %ck : Path to a public RSA key.%s file used to encrypt the data.\n", PARAM_IDENTIFIER, key_type);
    printf(" - path : One or more paths to files or directories to be send.\n");
}
