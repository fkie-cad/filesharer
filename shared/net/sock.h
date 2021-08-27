#ifndef SOCK_H
#define SOCK_H

#if defined(__linux__) || defined(__linux) || defined(linux)
#define _LINUX
#endif

#if defined(_WIN32)
#include "winSock.h"
#elif defined(_LINUX)
#include "linSock.h"
#endif
#include <stdint.h>



#define MAKE_UINTXX(_t_, _ptr_) ((_t_)*(_t_*)(_ptr_))
#define MAKE_UINT16(_ptr_) (MAKE_UINTXX(uint16_t, _ptr_))
#define MAKE_UINT32(_ptr_) (MAKE_UINTXX(uint32_t, _ptr_))
#define MAKE_UINT64(_ptr_) (MAKE_UINTXX(uint64_t, _ptr_))



int initConnection(
    PADDRINFOA *addr_info,
    ADDRESS_FAMILY family,
    char *ip,
    char *port_str,
    SOCKET *sock,
    int flags
);

int connectSock(
    SOCKET sock, 
    PADDRINFOA addr_info
);

void printAddrInfo(
    ADDRINFOA *info
);

void printSockAddr(
    PSOCKADDR_STORAGE addr, 
    int addr_ln
);

#endif
