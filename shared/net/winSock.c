#include <stdio.h>

#include "winSock.h"


static wsa_started = 0;

int initS()
{
    WSADATA wsa;
    //debug_info("\nInitialising Winsock... ");
    if ( WSAStartup(MAKEWORD(2,2),&wsa) != 0 )
    {
#ifdef ERROR_PRINT
        printf("Failed. Error Code : %d\n", WSAGetLastError());
#endif
        return -1;
    }
#ifdef DEBUG_PRINT
    printf("wsa\n");
    printf(" wVersion: 0x%04x\n", wsa.wVersion);
    printf(" wHighVersion: 0x%04x\n", wsa.wHighVersion);
    printf(" iMaxSockets: 0x%x\n", wsa.iMaxSockets);
    printf(" iMaxUdpDg: 0x%x\n", wsa.iMaxUdpDg);
    printf(" lpVendorInfo: %p\n", (PVOID)wsa.lpVendorInfo); // should be ignored
    printf(" szDescription: %.*s\n", WSADESCRIPTION_LEN, wsa.szDescription);
    printf(" szSystemStatus: %.*s\n", WSASYS_STATUS_LEN, wsa.szSystemStatus);
#endif

    wsa_started = 1;
    return 0;
}

void closeSocket(SOCKET* s)
{
    if ( !s || *s == INVALID_SOCKET )
        return;

    closesocket(*s);
    *s = INVALID_SOCKET;
}

void cleanUp(SOCKET* s)
{
    closeSocket(s);
    if ( wsa_started )
        WSACleanup();
}

int getLastSError()
{
    return WSAGetLastError();
}

int getLastError()
{
    return GetLastError();
}

void checkReceiveError(int le)
{
    if (le == WSAECONNRESET)
        printf("connection reset\n");
    else if (le == WSAECONNABORTED)
        printf("connection aborted\n");
    else if (le == WSAENOTCONN)
        printf("not connected\n");
    else
        printf("ERROR (0x%lx): recv failed.\n", le);
}
