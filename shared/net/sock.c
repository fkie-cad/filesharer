#include <stdio.h>
#include <string.h>

#include "sock.h"
#include "../print.h"



int initConnection(
    PADDRINFOA *addr_info,
    ADDRESS_FAMILY family,
    char *ip,
    char *port_str,
    SOCKET *sock,
    int flags // AI_PASSIVE for server(bind)
)
{
    int s;

    ADDRINFOA hints;

    s = initS();
    if ( s != 0 )
        return s;
    
    DPrint("Initialized.\n");

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = flags;

    // Resolve the server address and port
    DPrint("getaddrinfo\n");
    s = getaddrinfo(ip, port_str, &hints, addr_info);
    if ( s != 0 || (*addr_info)->ai_addr == NULL)
    {
        EPrint(s, "getaddrinfo failed with error\n");
        s = -1;
        goto clean;
    }
#ifdef DEBUG_PRINT
    printAddrInfo(*addr_info);
#endif

    //Create a socket
    *sock = socket((*addr_info)->ai_family, (*addr_info)->ai_socktype, (*addr_info)->ai_protocol);
    if ( *sock == INVALID_SOCKET )
    {
        s = getLastSError();
        EPrint(s, "Could not create socket.\n");
        goto clean;
    }
    
    DPrint("Socket created.\n");
    
clean:
    ;

    return s;
}

int connectSock(
    SOCKET sock, 
    PADDRINFOA addr_info
)
{
    int s;
    //Connect to remote server
    s = connect(sock , addr_info->ai_addr, (int)addr_info->ai_addrlen);
    if ( s < 0)
    {
#if defined(ERROR_PRINT) && defined(_WIN32)
        s = getLastSError();
        if ( s == WSAESHUTDOWN )
            printf("ERROR (0x%x): WSAESHUTDOWN.\n", s);
        else if ( s == WSAETIMEDOUT )
            printf("ERROR (0x%x): WSAETIMEDOUT.\n", s);
        else if ( s == WSAECONNREFUSED )
            printf("ERROR (0x%x): WSAECONNREFUSED.\n", s);
        else if ( s == WSAEHOSTDOWN )
            printf("ERROR (0x%x): WSAEHOSTDOWN.\n", s);
        else
            printf("ERROR (0x%x): Connect error.\n", s);
#endif
        return s;
    }
    
#ifdef DEBUG_PRINT
    printf("Connected.\n");
#endif
    return 0;
}

void printAddrInfo(ADDRINFOA *info)
{
    printf(" - ai_flags: %d\n", info->ai_flags);
    printf(" - ai_family: %d\n", info->ai_family);
    printf(" - ai_socktype: %d\n", info->ai_socktype);
    printf(" - ai_protocol: %d\n", info->ai_protocol);
#ifdef _WIN32
    printf(" - ai_addrlen: 0x%zx\n", info->ai_addrlen);
#else
    printf(" - ai_addrlen: 0x%x\n", info->ai_addrlen);
#endif
    printf(" - ai_canonname: %s\n", info->ai_canonname);
    printf(" - ai_addr: 0x%p\n", (void*)info->ai_addr);
    if ( info->ai_addr )
    {
        printSockAddr((PSOCKADDR_STORAGE)info->ai_addr, (int)info->ai_addrlen);
    }
    while ( info->ai_next )
        printAddrInfo(info->ai_next);
}

void printSockAddr(PSOCKADDR_STORAGE addr, int addr_ln)
{
    int i;
    PSOCKADDR addr4 = NULL;
    PSOCKADDR_IN6 addr6 = NULL;
    uint16_t port;

    //printf(" - addr_ln: 0x%x\n", addr_ln);
    //uint8_t* a = (uint8_t*)addr;
    //for ( i=0; i<addr_ln; i++ )
    //    printf("%02x ", a[i]);
    //printf("\n");

    printf(" - sa_family: 0x%x\n", addr->ss_family);
    if ( addr->ss_family == AF_INET )
    {
        if ( addr_ln < sizeof(SOCKADDR) )
            return;
        addr4 = (PSOCKADDR)addr;
        port = ntohs( MAKE_UINT16(&addr4->sa_data[0]) );
        printf(" - port: 0x%x (%u)\n", port, port);
        printf(" - ip: ");
        printf("%u", (uint8_t)addr4->sa_data[2]);
        for ( i=3; i<6; i++ )
            printf(".%u", (uint8_t)addr4->sa_data[i]);
        printf("\n");
    }
    else
    {
        if ( addr_ln < sizeof(SOCKADDR_IN6) )
            return;
        addr6 = (PSOCKADDR_IN6)addr;
        printf(" - port: 0x%x (%u)\n", ntohs(addr6->sin6_port), ntohs(addr6->sin6_port));
        printf(" - flowinfo: 0x%x\n", addr6->sin6_flowinfo);
#ifdef _WIN32
        printf(" - ip: %x", ntohs(addr6->sin6_addr.u.Word[0]));
        for ( i=1; i<8; i++ )
            printf(":%x", ntohs(addr6->sin6_addr.u.Word[i]));
        printf("\n");
#else
        printf(" - ip: %x", ntohs(addr6->sin6_addr.s6_addr16[0]));
        for ( i=1; i<8; i++ )
            printf(":%x", ntohs(addr6->sin6_addr.s6_addr16[i]));
        printf("\n");
#endif
        printf(" - flowinfo: 0x%x\n", addr6->sin6_scope_id);
#if defined(_WIN32) && !defined(WDK7600)
        printf(" - scope.zone: 0x%x\n", addr6->sin6_scope_struct.Zone);
        printf(" - scope.Level: 0x%x\n", addr6->sin6_scope_struct.Level);
#endif
        printf("\n");
    }
}
