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
//#include <signal.h>

#include <inttypes.h>
#include <stdint.h>
#if defined(_LINUX)
#include <errno.h>
#endif
#include <string.h>

#include "types.h"
#include "values.h"
#include "version.h"
#include "args.h"

#include "../shared/print.h"
#if defined(_WIN32)
#include "files/FilesW.h"
#include "crypto/windows/HasherCNG.h"
#elif defined(_LINUX)
#include "files/FilesL.h"
#include "crypto/linux/HasherOpenSSL.h"
#endif
#include "crypto/crypto.h"
#include "flags.h"
#include "FsHeader.h"


#define APP_NAME "FShare"


//#define DATA_STATE_NONE (0x0)
//#define DATA_STATE_KEY_HEADER (0x1)
//#define DATA_STATE_FILE_HEADER (0x2)
//#define DATA_STATE_FILE_DATA (0x3)

//#define KEY_HEADER_BUFFER_SIZE (0x100)
//#define BASE_NAME_MAX_SIZE (0x200)
//#define SUB_DIR_MAX_SIZE (0x200)


int parseParams(
    int argc, 
    char** argv, 
    uint16_t* flags, 
    char** ip, 
    char** port, 
    ADDRESS_FAMILY* family, 
    char** key_path, 
    uint32_t* block_size, 
    int* start_i
);

int checkParams(
    int argc,
    char** argv,
    int start_i,
    uint16_t flags, 
    char* ip, 
    char* port, 
    ADDRESS_FAMILY family, 
    char* key_path
);

void printUsage();

void printHelp();

int runClient(
    int argc,
    char** argv,
    int start_i,
    uint32_t block_size,
    SOCKET sock,
    PADDRINFOA addr_info,
    uint16_t flags
);

int runServer(
    int argc, 
    char** argv,
    int start_i,
    SOCKET sock,
    PADDRINFOA addr_info,
    uint16_t flags
);


int __cdecl main(int argc, char* argv[])
{
    bool s = 0;
    
    uint16_t flags = 0;

    SOCKET sock = INVALID_SOCKET;
    
    ADDRESS_FAMILY family = AF_INET;
    struct addrinfo *addr_info = NULL;

    char *ip = NULL;
    char *port = NULL;
    
    char* key_path = NULL;
    char full_key_path[MAX_PATH];

    uint32_t block_size = STD_BLOCK_SIZE;

    int start_i = 1;

    printf("%s - %s\n\n", APP_NAME, APP_VERSION);
    printf("Compiled: %s -- %s\n\n", __DATE__, __TIME__);

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

    s = parseParams(argc, argv, &flags, &ip, &port, &family, &key_path, &block_size, &start_i);
    if ( s != 0 )
    {
        printUsage();
        return -1;
    }
    
    s = checkParams(argc, argv, start_i, flags, ip, port, family, key_path);
    if ( s != 0 )
    {
        printUsage();
        return -1;
    }

    DPrint("ip: %s\n", ip);
    DPrint("port: %s\n", port);
    DPrint("family: %s\n", family==AF_INET?"AF_INET":(family==AF_INET6)?"AF_INET6":"NONE");
    DPrint("key_path: %s\n", key_path);
    DPrint("flags: 0x%x\n", flags);
    DPrint("start_i: 0x%x\n", start_i);


    memset(full_key_path, 0, MAX_PATH);
    if ( key_path != NULL )
    {
        s = (int)getFullPathName(key_path, MAX_PATH, full_key_path, NULL);
        if ( !s )
        {
            s = getLastError();
            EPrint(s, "Key file \"%s\" not found!", key_path);
            return s;
        }
        if ( !fileExists(full_key_path) )
        {
            s = -2;
            EPrint(s, "Key file \"%s\" not found!", key_path);
            return s;
        }
        s = c_init(full_key_path, (flags&FLAG_SERVER)?INIT_PRIV_KEY:INIT_PUB_KEY);
        if ( s != 0 )
        {
            s = -4;
            EPrint(s, "Init key failed.\n");
            goto clean;
        }
    }



    s = initConnection(&addr_info, family, ip, port, &sock, (flags&FLAG_SERVER)?AI_PASSIVE:0);
    if ( s != 0 )
    {
        EPrint(s, "initConnection failed.\n");
        goto clean;
    }
    


    if ( flags & FLAG_SERVER )
    {
        runServer(
            argc,
            argv,
            start_i,
            sock,
            addr_info,
            flags
        );
    }
    else if ( flags & FLAG_CLIENT )
    {
        runClient(
            argc,
            argv,
            start_i,
            block_size,
            sock,
            addr_info,
            flags
        );
    }

clean:
    if ( addr_info != NULL )
        freeaddrinfo(addr_info);
    cleanUp(&sock);
    if ( flags&FLAG_ENCRYPTED )
        c_clean();

    return s;
}


//#define IS_1C_ARG(_a_) ( ( _a_[0] == LIN_PARAM_IDENTIFIER || _a_[0] == WIN_PARAM_IDENTIFIER ) && _a_[1] != 0 && _a_[2] == 0 )
#define IS_1C_ARG(_a_, _v_) ( ( _a_[0] == LIN_PARAM_IDENTIFIER || _a_[0] == WIN_PARAM_IDENTIFIER ) && _a_[1] == _v_ && _a_[2] == 0 )
#define IS_4C_ARG(_a_, _v_) ( ( _a_[0] == LIN_PARAM_IDENTIFIER || _a_[0] == WIN_PARAM_IDENTIFIER ) && _a_[1] == _v_[0] && _a_[2] == _v_[1] && _a_[3] == _v_[2] && _a_[4] == _v_[3] && _a_[5] == 0 )
int parseParams(
    int argc, 
    char** argv, 
    uint16_t* flags, 
    char** ip, 
    char** port, 
    ADDRESS_FAMILY* family, 
    char** key_path, 
    uint32_t* block_size, 
    int* start_i
)
{
    int i;
    char* arg = NULL;
    char* val1 = NULL;
    char* val2 = NULL;
    int ipv;

    for ( i = *start_i; i < argc; i++ )
    {
        arg = argv[i];
        val1 = ( i < argc - 1 ) ? argv[i+1] : NULL;
        val2 = ( i < argc - 2 ) ? argv[i+2] : NULL;

        //if ( !IS_1C_ARG(arg) )
        //{
        //    DPrint("Not an arg: %s\n", arg);
        //    break;
        //}
        
        if ( IS_1C_ARG(arg, 'c') )
        {
            *flags |= FLAG_CHECK_FILE_HASH;
        }
        else if ( IS_1C_ARG(arg, 'm') )
        {
            if ( val1 == NULL )
                break;

            if ( val1[0] == 's' && val1[1] == 0 )
                *flags |= FLAG_SERVER;
            else if ( val1[0] == 'c' && val1[1] == 0 )
                *flags |= FLAG_CLIENT;

            i++;
        }
        else if ( IS_4C_ARG(arg, "recv") )
        {
            if ( val1 == NULL )
                break;

            *port = val1;

            *flags |= FLAG_SERVER;

            i++;
        }
        else if ( IS_4C_ARG(arg, "send") )
        {
            if ( val1 == NULL || val2 == NULL )
                break;

            *ip = val1;
            *port = val2;

            *flags |= FLAG_CLIENT;

            i++;
            i++;
        }
        else if ( IS_1C_ARG(arg, 'f') )
        {
            *flags |= FLAG_FLAT_COPY;
        }
        else if ( IS_1C_ARG(arg, 'k') )
        {
            if ( val1 == NULL )
                break;

            *key_path = val1;
            *flags |= FLAG_ENCRYPTED | FLAG_CHECK_FILE_HASH;

            i++;
        }
        else if ( IS_1C_ARG(arg, 'r') )
        {
            *flags |= FLAG_RECURSIVE;
        }
        else if ( IS_1C_ARG(arg, 's') )
        {
            if ( val1 == NULL )
                break;

            *block_size = strtoul(val1, NULL, 0);

            i++;
        }
        else if ( IS_1C_ARG(arg, 'v') )
        {
            if ( val1 == NULL )
                break;

            ipv = (int)strtoul(val1, NULL, 0);
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
        else
        {
            //DPrint("Unknown arg: %s\n", arg);
            break;
        }
    }
    
    *start_i = i;

    if ( *start_i >= argc ) 
        return -1;
    return 0;
}
#undef IS_1C_ARG
#undef IS_4C_ARG

int checkParams(
    int argc,
    char** argv,
    int start_i,
    uint16_t flags,
    char* ip,
    char* port,
    ADDRESS_FAMILY family,
    char* key_path
)
{
    int s = 0;

    DPrint("flags: 0x%x\n", flags);

    uint16_t f = flags & (FLAG_SERVER|FLAG_CLIENT);
    if ( !f || (f & (f - 1)) != 0 )
    {
        s = -1;
        EPrint(s, "No valid mode set. Either set server (recv) or client (send|get) mode!\n");
    }

    if ( flags & FLAG_ENCRYPTED && key_path == NULL )
    {
        s = -1;
        EPrint(s, "A key is required for encryption!\n");
    }
    if ( flags & FLAG_CLIENT )
    {
        if ( ip == NULL )
        {
            s = -1;
            EPrint(s, "No ip set!\n");
        }
        if ( !fileExists(argv[start_i]) 
            && !dirExists(argv[start_i]) )
        {
            s = -1;
            EPrint(s, "No (valid) path set!\n");
        }
    }
    if ( flags & FLAG_SERVER )
    {
        if ( !dirExists(argv[start_i]) )
        {
            s = -1;
            EPrint(s, "No (valid) receive dir set!\n");
        }
    }
    if ( port == NULL )
    {
        s = -1;
        EPrint(s, "No port set!\n");
    }
    if ( family != AF_INET && family != AF_INET6 )
    {
        s = -1;
        EPrint(s, "Unknown ip version!\n");
    }
    if ( s != 0 )
    {
        EPrintNl();
    }

    return s;
}

void printUsage()
{
    printf("Usage: %s %csend <ip> <port>|%crecv <port> [%cv <version>] [%ck <path>] [%cc] [%cr] [%cf] [%cs <size>] <path> [...]\n",
        APP_NAME, 
        PARAM_IDENTIFIER, 
        PARAM_IDENTIFIER, 
        PARAM_IDENTIFIER, 
        PARAM_IDENTIFIER, 
        PARAM_IDENTIFIER, 
        PARAM_IDENTIFIER, 
        PARAM_IDENTIFIER, 
        PARAM_IDENTIFIER);
    
    printf("\n");
    printf("Version: %s\n", APP_VERSION);
    printf("Last changed: %s\n", APP_LAST_CHANGED);
}

void printHelp(void)
{
#ifdef _WIN32
    const char* key_type = "der";
#else
    const char* key_type = "pem";
#endif

    printUsage();
    printf("\nOptions\n");
    printf(" - %crecv: Start a receiving server on <port>.\n", PARAM_IDENTIFIER);
    printf(" - %csend: Start a sending client to <ip> on <port>).\n", PARAM_IDENTIFIER);
    printf(" - %cv: IP version 4 (default) or 6.\n", PARAM_IDENTIFIER);
    printf(" - %ck: Path to an SSL key.%s file to encrypt or decrypt data. "
           "The server has to use the private key, the client the public key.\n", 
           PARAM_IDENTIFIER, key_type);
    printf("\n");
    printf("Server only options:\n");
    printf(" - path: The existing target base directory, the shared files are stored in.\n");
    printf("\n");
    printf("Client only options:\n");
    printf(" - %cc : Check file hashes of transmitted files. Set by default, if transferred encrypted.\n", PARAM_IDENTIFIER);
    printf(" - %cr : Copy dirs recursively.\n", PARAM_IDENTIFIER);
    printf(" - %cf : Flatten copied dirs to base dir. "
           "Only used if /r is set.\n",
           PARAM_IDENTIFIER);
    printf(" - %cs : Maximum size of encrypted chunk. "
           "Has to be greater than 0x1000 and less than 0xFFFFFFFF. "
           "Defaults to 0x%x.\n",
           PARAM_IDENTIFIER, STD_BLOCK_SIZE);
    printf(" - path : One or more paths to files or directories to be sent.\n");
    printf("\n");
    printf("Examples:\n");
    printf(" - server: %s %crecv 1234 %cv 4 %ck keys%cpriv.%s files%c\n", 
        APP_NAME, 
        PARAM_IDENTIFIER, 
        PARAM_IDENTIFIER, 
        PARAM_IDENTIFIER, PATH_SEPARATOR, key_type, 
        PATH_SEPARATOR);
    printf(" - client: %s %csend 127.0.0.1 1234 %cv 4 %ck keys%cpub.%s %cc file1 file2\n", 
        APP_NAME, 
        PARAM_IDENTIFIER, 
        PARAM_IDENTIFIER, 
        PARAM_IDENTIFIER, PATH_SEPARATOR, key_type, 
        PARAM_IDENTIFIER);
}
