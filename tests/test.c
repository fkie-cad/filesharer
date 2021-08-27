#ifdef _WIN32
    #include <windows.h>
    #include "testAESCng.h"
    #include "testRSACng.h"
#else
    #include "testAESOpenSSL.h"
    #include "testRSAOpenSSL.h"
    #define __cdecl
#endif
#include <stdint.h>

#define TEST_AES_FLAG (1)
#define TEST_RSA_FLAG (2)

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

        if ( arg[1] == 'a' &&  arg[2] == 'e' && arg[3] == 's' && arg[4] == 0 )
        {
            test |= TEST_AES_FLAG;
            continue;
        }
        if ( arg[1] == 'r' &&  arg[2] == 's' && arg[3] == 'a' && arg[4] == 0 )
        {
            test |= TEST_RSA_FLAG;
            continue;
        }
    }
    if ( test == 0 )
    {
        //test = 0xFFFF;
        printf("No option provided.\n");
        printf("Usage: Tests /aes.\n");
        printf("Usage: Tests /rsa pub.key priv.key.\n");
    }

    if ( test & TEST_RSA_FLAG )
        testRSA(argc-i , &argv[i]);

    if ( test & TEST_AES_FLAG )
        testAES(argc-i , &argv[i]);

    return 0;
}
