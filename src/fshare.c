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
#include "flags.h"
#include "FsHeader.h"


#define APP_NAME "FShare"


#define DATA_STATE_NONE (0x0)
#define DATA_STATE_KEY_HEADER (0x1)
#define DATA_STATE_FILE_HEADER (0x2)
#define DATA_STATE_FILE_DATA (0x3)

#define KEY_HEADER_BUFFER_SIZE (0x100)
#define BASE_NAME_MAX_SIZE (0x200)
#define SUB_DIR_MAX_SIZE (0x200)


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

int __cdecl runServer(
    int argc, 
    char** argv,
    int start_i,
    SOCKET sock,
    PADDRINFOA addr_info,
    uint16_t flags
);


//char file_path[MAX_PATH];
//char base_name[BASE_NAME_MAX_SIZE];
//char sub_dir[BASE_NAME_MAX_SIZE];
//uint8_t gBuffer[BUFFER_SIZE];
//
//int running = 0;



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

    uint32_t block_size = 0;

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

    s = checkParams(flags, ip, port, family, key_path);
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
            EPrint(s, "Init pub key failed.\n");
            goto clean;
        }
    }



    s = initConnection(&addr_info, family, ip, port, &sock, (flags&FLAG_SERVER)?AI_PASSIVE:0);
    if ( s != 0 )
    {
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


#define IS_SC_ARG(_a_) ( ( _a_[0] == LIN_PARAM_IDENTIFIER || _a_[0] == WIN_PARAM_IDENTIFIER ) && _a_[1] != 0 && _a_[2] == 0 )
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
    char* arg;
    char* val;
    int ipv;

    for ( i = *start_i; i < argc; i++ )
    {
        arg = argv[i];
        val = ( i < argc - 1 ) ? argv[i+1] : NULL;

        if ( !IS_SC_ARG(arg) )
        {
            DPrint("Not an arg: %s\n", arg);
            break;
        }


        if ( arg[1] == 'c' )
        {
            *flags |= FLAG_CHECK_FILE_HASH;
        }
        else if ( arg[1] == 'i' )
        {
            if ( val == NULL )
                break;

            *ip = val;
            i++;
        }
        else if ( arg[1] == 'm' )
        {
            if ( val == NULL )
                break;

            if ( val[0] == 's' && val[1] == 0 )
                *flags |= FLAG_SERVER;
            else if ( val[0] == 'c' && val[1] == 0 )
                *flags |= FLAG_CLIENT;

            i++;
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
            *flags |= FLAG_ENCRYPTED | FLAG_CHECK_FILE_HASH;

            i++;
        }
        else if ( arg[1] == 'p' )
        {
            if ( val == NULL )
                break;

            *port = val;

            i++;
        }
        else if ( arg[1] == 'r' )
        {
            *flags |= FLAG_RECURSIVE;
        }
        else if ( arg[1] == 's' )
        {
            if ( val == NULL )
                break;

            *block_size = strtoul(val, NULL, 0);

            i++;
        }
        else if ( arg[1] == 'v' )
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
        else
        {
            DPrint("Unknown arg: %s\n", arg);
        }
    }
    
    *start_i = i;
    if ( *start_i >= argc ) 
        return -1;
    return 0;
}
#undef IS_SC_ARG

int checkParams(
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
    DPrint("f: 0x%x\n", f);
    if ( (f & (f - 1)) != 0 )
    {
        s = -1;
        EPrint(s, "No mode set. Either set server (s) or client (m) mode!\n");
    }

    if ( flags & FLAG_ENCRYPTED && key_path == NULL )
    {
        s = -1;
        EPrint(s, "A key is required for encryption!\n");
    }
    if ( flags & FLAG_CLIENT && ip == NULL )
    {
        s = -1;
        EPrint(s, "No ip set!\n");
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
    printf("Usage: %s %cm <mode> [%ci <ip>] %cp <port> [%cv <version>] [%ck <path>] [%cc] [%cr] [%cf] [%cs <size>] path [...]\n", 
        APP_NAME, 
        PARAM_IDENTIFIER, 
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

void printHelp()
{
#ifdef _WIN32
    const char* key_type = "der";
#else
    const char* key_type = "pem";
#endif

    printUsage();
    printf("\nOptions\n");
    printf(" - %cm: Share mode: receiving server (s) or sending client (c).\n", PARAM_IDENTIFIER);
    printf(" - %ci: The server ip. Not necessary in server mode.\n", PARAM_IDENTIFIER);
    printf(" - %cp: The server listening port.\n", PARAM_IDENTIFIER);
    printf(" - %cv: IP version 4 (default) or 6.\n", PARAM_IDENTIFIER);
    printf(" - %ck: Path to an SSL key.%s file to encrypt or decrypt data. "
           "The server has to use the private key, the client the public key.\n", 
           PARAM_IDENTIFIER, key_type);
    printf("Server only options:\n");
    printf(" - path: The existing target base directory, the shared files are stored in.\n");
    printf("Client only options:\n");
    printf(" - %cc : Check file hashes of transmitted files. Set by default, if transferred encrypted.\n", PARAM_IDENTIFIER);
    printf(" - %cr : Copy dirs recursively.\n", PARAM_IDENTIFIER);
    printf(" - %cf : Flatten copied dirs to base dir. "
           "Only meaningful if /r is set.\n", 
           PARAM_IDENTIFIER);
    printf(" - %cs : Maximum size of encrypted chunk. "
           "Has to be greater than 0x1000 and less than 0xFFFFFFFF. "
           "Defaults to 0x%x.\n", 
           PARAM_IDENTIFIER, (PAGE_SIZE<<0x8));
    printf(" - path : One or more paths to files or directories to be sent.\n");
    printf("\n");
    printf("Examples:\n");
    printf(" - server: %s %cm s %cp 1234 %cv 4 %ck keys%cpriv.%s files%c\n", 
        APP_NAME, 
        PARAM_IDENTIFIER, 
        PARAM_IDENTIFIER, 
        PARAM_IDENTIFIER, 
        PARAM_IDENTIFIER, 
        PATH_SEPARATOR, key_type, 
        PATH_SEPARATOR);
    printf(" - client: %s %cm c %ci 127.0.0.1 %cp 1234 %cv 4 %ck keys%cpub.%s %cc file1 file2\n", 
        APP_NAME, 
        PARAM_IDENTIFIER, 
        PARAM_IDENTIFIER, 
        PARAM_IDENTIFIER, 
        PARAM_IDENTIFIER, 
        PARAM_IDENTIFIER, 
        PATH_SEPARATOR, key_type, 
        PARAM_IDENTIFIER);
}
