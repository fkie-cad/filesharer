#ifndef SHARED_WINDOWS_SOCKET_H
#define SHARED_WINDOWS_SOCKET_H

//#undef UNICODE

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN0
#endif

#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h> // before windows.h !!!
#include <windows.h>
#include <WINIOCTL.H>
#include <Ws2tcpip.h>

#include <stdio.h>



#ifndef socklen_t_def
typedef int socklen_t;
#define socklen_t_def
#endif

#ifndef reclen_t_def
typedef int reclen_t;
#define reclen_t_def
#endif

#ifndef sendlen_t
typedef int sendlen_t;
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
