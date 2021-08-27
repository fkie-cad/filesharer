#ifndef SHARED_LINUX_SOCKET_H
#define SHARED_LINUX_SOCKET_H

#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <stdio.h>

#include "types.h"



#ifndef SOCKET
#define SOCKET int
#endif

#ifndef SOCKADDR_STORAGE_DEF
typedef struct sockaddr_storage SOCKADDR_STORAGE;
typedef SOCKADDR_STORAGE *PSOCKADDR_STORAGE;
#define SOCKADDR_STORAGE_DEF
#endif

#ifndef ADDRINFOA_DEF
typedef struct addrinfo ADDRINFOA;
typedef ADDRINFOA *PADDRINFOA;
#define ADDRINFOA_DEF
#endif

#ifndef SOCKADDR_DEF
typedef struct sockaddr SOCKADDR;
typedef SOCKADDR *PSOCKADDR;
#define SOCKADDR_DEF
#endif

#ifndef SOCKADDR_IN6_DEF
typedef struct sockaddr_in6 SOCKADDR_IN6;
typedef SOCKADDR_IN6 *PSOCKADDR_IN6;
#define SOCKADDR_IN6_DEF
#endif

#ifndef ADDRESS_FAMILY_DEF
typedef uint16_t ADDRESS_FAMILY;
typedef ADDRESS_FAMILY *PADDRESS_FAMILY;
#define ADDRESS_FAMILY_DEF
#endif

#define INVALID_SOCKET (SOCKET)(~0)
#define SOCKET_ERROR (-1)

#define  SD_RECEIVE (0)
#define  SD_SEND (1)
#define  SD_BOTH (2)

#ifndef reclen_t_def
typedef ssize_t reclen_t;
#define reclen_t_def
#endif

#ifndef sendlen_t_def
typedef ssize_t sendlen_t;
#define sendlen_t_def
#endif



int initS();

void closeSocket(
    SOCKET* s
);

void cleanUp(
    SOCKET* s
);

int getLastSError();

int getLastError();

void checkReceiveError(
    int le
);

#endif
