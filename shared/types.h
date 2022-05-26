#ifndef SHARED_TYPES_H
#define SHARED_TYPES_H

#include <limits.h>

#if defined (_WIN32)
#include <windows.h>
#endif

#ifndef __cdecl
#define __cdecl
#endif

#ifndef MAX_PATH
#define MAX_PATH PATH_MAX
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

#ifndef bool
//#if defined (_WIN32)
//#define bool BOOL
//#define true TRUE
//#define false FALSE
//#elif defined (__linux)
#define bool int
#define true 1
#define false 0
//#endif
#endif

//#ifndef uchar
//#if defined (_WIN32)
//#define uchar UCHAR
//#elif defined (__linux)
//#define uchar unsigned char
//#endif
//#endif

#define WIN_PARAM_IDENTIFIER ('/')
#define LIN_PARAM_IDENTIFIER ('-')
#if defined(_WIN32)
#define PARAM_IDENTIFIER WIN_PARAM_IDENTIFIER
#elif defined(_LINUX)
#define PARAM_IDENTIFIER LIN_PARAM_IDENTIFIER
#endif

#endif
