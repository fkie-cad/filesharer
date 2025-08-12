#include <stdio.h>

#include "winSock.h"


static int wsa_started = 0;

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

int printLocalAddresses()
{
    int s = 0;
    char ac[80] = {0};

    if ( gethostname(ac, sizeof(ac)) == SOCKET_ERROR )
    {
        s = WSAGetLastError();
        printf("[e] Error when getting local host name! (0x%x)\n", s);
        return WSAGetLastError();
    }
    printf("Host name is %s\n",  ac);

    struct hostent *phe = gethostbyname(ac);
    if ( phe == 0 )
    {
        s = WSAGetLastError();
        printf("[e] Bad host lookup! (0x%x)\n", s);
        return s;
    }
    
#ifdef DEBUG_PRINT
    printf("h_name: %s\n", phe->h_name);
#endif
    if ( phe->h_aliases && phe->h_aliases[0] != 0)
    {
        printf("Aliases:\n");
        for ( size_t i = 0; phe->h_aliases[i] != 0; ++i )
        {
            printf("[%zu]: %p\n", i, phe->h_aliases[i]);
        }
    }
#ifdef DEBUG_PRINT
    printf("h_addrtype: 0x%x\n", phe->h_addrtype);
    printf("h_length: 0x%x\n", phe->h_length);
#endif
    printf("Address list:\n");
    char ip_str[0x40];
    for ( unsigned int i = 0; phe->h_addr_list[i] != 0; ++i )
    {
        struct in_addr addr;
        memcpy(&addr, phe->h_addr_list[i], sizeof(struct in_addr));
        memset(ip_str, 0, 0x40);
        inet_ntop(phe->h_addrtype, &addr, ip_str, 0x40);
        printf("[%u] %s\n", i, ip_str);
    }
    
    return 0;
}
