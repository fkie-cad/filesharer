#ifdef _WIN32
    #include <windows.h>
    #include "testAESCng.h"
    #include "testRSACng.h"
#else
    #include "testAESOpenSSL.h"
    #include "testRSAOpenSSL.h"
    #define __cdecl
#endif
#include "testServer.h"

#include <stdint.h>

#define TEST_NONE_FLAG   (0)
#define TEST_AES_FLAG    (1)
#define TEST_RSA_FLAG    (2)
#define TEST_SERVER_FLAG (4)

int __cdecl main(int argc , char *argv[])
{
    int i;
    char* arg = NULL;
    uint16_t test = 0;

    for ( i = 1; i < argc; i++ )
    {
        arg = argv[i];

        if ( arg[0] != '/' && arg[0] != '-' )
            break;

        if ( strcmp(arg, "/aes") == 0 )
        {
            test |= TEST_AES_FLAG;
            continue;
        }
        else if ( strcmp(arg, "/rsa") == 0 )
        {
            test |= TEST_RSA_FLAG;
            continue;
        }
        else if ( strcmp(arg, "/server") == 0 )
        {
            test |= TEST_SERVER_FLAG;
            continue;
        }
    }
    if ( test == TEST_NONE_FLAG )
    {
        //test = 0xFFFF;
        printf("No option provided.\n");
        printf("Usage: Tests /aes.\n");
        printf("Usage: Tests /rsa pub.key priv.key.\n");
        printf("Usage: Tests /server\n");
    }

    if ( test & TEST_RSA_FLAG )
        testRSA(argc-i , &argv[i]);

    if ( test & TEST_AES_FLAG )
        testAES(argc-i , &argv[i]);

    if ( test & TEST_SERVER_FLAG )
        testServer(argc-i , &argv[i]);

    return 0;
}
