#ifndef TEST_SERVER_H
#define TEST_SERVER_H

#include "../shared/env.h"

//#if defined(_WIN32)
//    #include "warnings.h"
//    #include "net/winSock.h"
//#elif defined(_LINUX)
//    #include "net/linSock.h"
//#endif
//#include "net/sock.h"

#include <stdlib.h>
#include <stdio.h>

#include <inttypes.h>
#include <stdint.h>
#if defined(_LINUX)
#include <errno.h>
#endif
#include <string.h>


#include "../shared/print.h"
#if defined(_WIN32)
#include "../shared/files/FilesW.h"
#elif defined(_LINUX)
#include "../shared/files/FilesL.h"
#endif

int getLastError()
{
#if defined(_WIN32)
    return GetLastError();
#else
    return errno;
#endif
}

int createFilePath(
    char* FilePath, 
    uint32_t FilePathMaxSize, 
    char* ParentDir, 
    char* SubDir, 
    char* BaseName, 
    uint16_t sub_dir_ln
    //FsKeyHeader* KeyHeader, 
    //SOCKET ClientSocket, 
    //bool IsEncrypted
)
{
    int s = 0;

    char* tmpPath = malloc(FilePathMaxSize);
    if ( !tmpPath )
    {
        s = getLastError();
        goto clean;
    }
    
    memset(FilePath, 0, FilePathMaxSize);
    memset(tmpPath, 0, FilePathMaxSize);
    size_t pb = sprintf(tmpPath, "%s", ParentDir);
    if ( sub_dir_ln != 0 )
    {
        convertPathSeparator(SubDir);
        cropTrailingSlash(SubDir);
        // construct directory string
        pb += sprintf(&tmpPath[pb], "%c%s", PATH_SEPARATOR, SubDir);
        // get abs path
        size_t pb2 = getFullPathName(tmpPath, FilePathMaxSize, FilePath, NULL);
        // check if we are still in ParentDir
        if ( !pb2 || pb2 >= FilePathMaxSize 
            || strncmp(FilePath, ParentDir, strlen(ParentDir)) != 0 )
        {
            s = -2;
            goto clean;
        }
        // create directory
        //s = mkdir_r(FilePath);
        //if ( s != 0 )
        //    goto clean;
    }

    // construct full file path
    pb = sprintf(&tmpPath[pb], "%c%s", PATH_SEPARATOR, BaseName);
    if ( pb < 0 || pb >= (int)FilePathMaxSize )
    {
        s = getLastError();
        goto clean;
    }
    // get abs path
    char* checkBaseName = NULL;
    pb = getFullPathName(tmpPath, FilePathMaxSize, FilePath, &checkBaseName);
    // check if we are still in ParentDir
    if ( !pb || pb >= FilePathMaxSize 
        || strncmp(FilePath, ParentDir, strlen(ParentDir)) != 0
        || strcmp(checkBaseName, BaseName) != 0 )
    {
        s = -3;
        goto clean;
    }
    s = 0;
    
    memcpy(FilePath, tmpPath, pb);

clean:
    if ( s != 0 )
    {
        //sendAnswer(4, FS_ERROR_CREATE_DIR, 0, ClientSocket, IsEncrypted, KeyHeader);
        memset(FilePath, 0, FilePathMaxSize);
    }

    return s;
}

void testServer(int argc , char *argv[])
{
    printf("testServer\n");
    printf("-----------------------------\n");

    int s = 0;

    char file_path[MAX_PATH];
    char parent_dir[MAX_PATH];
    getFullPathName("parent/dir", MAX_PATH, parent_dir, NULL);

    typedef struct _TEST_OBJ {
        char* sub_dir;
        char* base_name;
    } TEST_OBJ, *PTEST_OBJ;

    TEST_OBJ test_obj[] = {
        { "", "exe" }, // 0
        { "a/", "exe" }, // 0
        { "a/b", "fun.exe" }, // 0
        { "..\\a", "../mal." }, // -2
        { "../../a/..\\b", "../../mal.ware" }, // -2
        { "/a/b", "../../mal.ware" }, // -3
        { "/a/b", "../../../mal.ware" }, // -3
        { "/a/b", "../mal.ware" }, // -3
    };

    size_t n = ARRAYSIZE(test_obj);

    printf("parent_dir: %s\n", parent_dir);
    for ( size_t i = 0; i < n; i++ )
    {
        uint16_t sub_dir_ln = (uint16_t)strlen( test_obj[i].sub_dir);
        printf("%zu/%zu\n", i+1, n);
        printf("  sub_dir: %s\n", test_obj[i].sub_dir);
        printf("  sub_dir_ln: 0x%x\n", sub_dir_ln);
        printf("  base_name: %s\n", test_obj[i].base_name);
        s = createFilePath(file_path, MAX_PATH, parent_dir, test_obj[i].sub_dir, test_obj[i].base_name, sub_dir_ln);
        printf("  file_path: %s\n", file_path);
        printf("  s: 0x%x\n", s);
        printf("\n");
    }

}

#endif
