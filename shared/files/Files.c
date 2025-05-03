//#include <unistd.h>

#if defined(__linux__) || defined(__linux) || defined(linux)
#include <errno.h>
#endif
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "Files.h"



void cropTrailingSlash(char* path)
{
    if ( path == NULL )
        return;
    
    size_t n = strlen(path);
    if ( n == 0 )
        return;
    if ( path[n-1] == '/' )
        path[n-1] = 0;
#ifdef _WIN32
    if ( path[n-1] == '\\' )
        path[n-1] = 0;
#endif
}

void convertPathSeparator(char* path)
{
    if ( path == NULL )
        return;
    
    size_t n = strlen(path);
    if ( n == 0 )
        return;
    char* tmp = path;

#ifdef _WIN32
    char from = LIN_PATH_SEPARATOR;
    char to = WIN_PATH_SEPARATOR;
#else
    char from = WIN_PATH_SEPARATOR;
    char to = LIN_PATH_SEPARATOR;
#endif

    while ( *tmp != 0 )
    {
        if ( *tmp == from )
            *tmp = to;
        tmp++;
    }
}

int getFileSize(
    const char* path, 
    size_t* size
)
{
#if defined(_WIN64)
    struct _stat64 stat_buf;
#else
    struct stat stat_buf;
#endif
    if ( path == NULL )
        return 0;
    memset(&stat_buf, 0, sizeof(stat_buf));
    errno = 0;
    int rc = stat(path, &stat_buf);
    int errsv = errno;
    if ( rc == 0 )
        *size =  stat_buf.st_size;
    else
    {
        //printf("ERROR (0x%x): fstat error on file \"%s\"\n", errsv, path);
        return errsv;
    }
    return 0;
}

int fileExists(const char* path)
{
#if defined(_WIN64)
    struct _stat64 s;
#else
    struct stat s;
#endif
    if ( path == NULL )
        return 0;
    if ( stat(path, &s) == 0 )
    {
        if ( s.st_mode & S_IFREG )
            return 1;
    }

    return 0;
}

int dirExists(const char* path)
{
#if defined(_WIN64)
    struct _stat64 s;
#else
    struct stat s;
#endif
    if ( path == NULL )
        return 0;
    if (stat(path, &s) == 0 )
    {
        if ( s.st_mode & S_IFDIR )
            return 1;
    }

    return 0;
}

int checkPath(const char* path, int is_dir)
{
    if (is_dir)
        return dirExists(path);
    else
        return fileExists(path);
}

size_t getBaseName(
    const char* file_path,
    size_t file_path_ln, 
    char** base_name
)
{
    if ( file_path == 0 || file_path[0] == 0 || file_path_ln == 0 || base_name == NULL )
    {
        return 0;
    }

    size_t offset = getBaseNameOffset(file_path, file_path_ln);
    if ( offset >= file_path_ln )
    {
        *base_name = NULL;
        return 0;
    }	
    *base_name = &file_path[offset];
    return file_path_ln - offset;
}

void getBaseNameC(const char* file_path, char* file_name, size_t* file_name_ln)
{
    size_t offset;
    size_t file_path_ln = strnlen(file_path, *file_name_ln);
    size_t fn;

    if ( file_path_ln == 0 )
    {
        *file_name_ln = 0;
        file_name[0] = 0;
        return;
    }

    offset = getBaseNameOffset(file_path, strlen(file_path));
    if ( file_path_ln < offset )
    {
        *file_name_ln = 0;
        file_name[0] = 0;
    }
    fn = file_path_ln - offset;
    memcpy(file_name, &file_path[offset], fn);
    file_name[*file_name_ln-1] = 0;

    *file_name_ln = fn;
}

char* getBaseNameA(const char* file_path, size_t *file_name_ln)
{
    size_t offset;
    char* file_name;
    size_t file_path_ln = strnlen(file_path, *file_name_ln);

    if ( file_path_ln == 0 ) return NULL;

    offset = getBaseNameOffset(file_path, strlen(file_path));
    *file_name_ln = file_path_ln - offset;
    file_name = (char*) malloc(*file_name_ln+1);
    if ( !file_name )
    {
        *file_name_ln = 0;
        return NULL;
    }
    memcpy(file_name, &file_path[offset], *file_name_ln);
    file_name[*file_name_ln] = 0;

    return file_name;
}

size_t getBaseNameOffset(
    const char* file_path,
    size_t file_path_ln
)
{
    if ( file_path_ln == 0 )
        return 0;
    size_t i = file_path_ln - 1;
    while ( 1 )
    {
        if ( file_path[i] == '/' 
#ifdef _WIN32 
            || file_path[i] == '\\' 
#endif
            )
        {
            return i + 1;
        }

        if ( i > 1 )
            i--;
        else
            break;
    }
    return 0;
}



//char* getDirOfBinary(int pid)
//{
//	if ( pid == 0 )
//		pid = getpid();
//
//	char szTmp[32] = {0};
//	char pBuf[512] = {0};
//	size_t len = 512;
//	sprintf(szTmp, "/proc/%d/exe", pid);
//	int bytes = readlink(szTmp, pBuf, len);
//	if ( bytes < len - 1 )
//		bytes = len - 1;
//	if(bytes >= 0)
//		pBuf[bytes] = '\0';
//
////		printf("szTmp: %s\n", szTmp);
////		printf("pBuf: %s\n", pBuf);
//	char* bin = char*(pBuf);
//	size_t slash = bin.rfind("/");
//	if ( slash == char*::npos )
//		slash = bin.size();
//	char* bin_dir = bin.substr(0, slash);
////		printf("bin_dir: %s\n", bin_dir);
//
//	return bin_dir;
//}
