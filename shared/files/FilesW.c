#include <stdio.h>
#include <direct.h>

#include "debug.h"
#include "FilesW.h"
#include "collections/Fifo.h"



int actOnFilesInDir(const char* dir, FileCallback cb, const char** types, uint32_t flags, void* params, int* killed)
{
    debug_info("actOnFilesInDir(%s)\n", dir);
    HANDLE hFind = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATA ffd;
    char* mask = "*";
    char spec[MAX_PATH];
    char* act_path = NULL;
    Fifo directories;
    int s = 1;
    PFifoEntry entry;
    (void)types;
    int recursive = flags & FILES_FLAG_RECURSIVE;

    if ( !dirExists(dir) )
    {
        printf("ERROR: FileUtil::actOnFilesInDir: \"%s\" does not exist!", dir);
        return 0;
    }

    //cropTrailingSlash(dir);

    Fifo_init(&directories);
    Fifo_push(&directories, dir, (size_t)strlen(dir)+1);

    while (!Fifo_empty(&directories) && !(*killed))
    {
        entry = Fifo_front(&directories);
        act_path = (char*)entry->value;

        debug_info(" - act_path: %s\n", act_path);
        memset(spec, 0, MAX_PATH);
        snprintf(spec, MAX_PATH, "%s\\%s", act_path, mask);
        spec[MAX_PATH - 1] = 0;
        debug_info(" - spec: %s\n", spec);

        hFind = FindFirstFile(spec, &ffd);
        if (hFind == INVALID_HANDLE_VALUE)
        {
            printf(" - ERROR (0x%x): hfinf\n", GetLastError());
            s = 0;
            break;
        }
        do
        {
            if (strcmp(ffd.cFileName, ".") != 0 &&
                strcmp(ffd.cFileName, "..") != 0)
            {
                memset(spec, 0, MAX_PATH);
                debug_info(" - - act_path: %s\n", act_path);
                debug_info(" - - ffd.cFileName: %s\n", ffd.cFileName);
                snprintf(spec, MAX_PATH, "%s\\%s", act_path, ffd.cFileName);
                spec[MAX_PATH - 1] = 0;
                if ( (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) )
                {
                    if (!recursive)
                        continue;

                    debug_info(" - - dir: %s\n", spec);
                    s = (int)Fifo_push(&directories, spec, strlen(spec)+1);
                    debug_info(" - - fifo size: %u\n", s);
                    if (s == 0)
                    {
                        printf("Fifo push error!\n");
                        break;
                    }
                }
                else
                {
                    debug_info(" - - file: %s\n", spec);
                    cb(spec, ffd.cFileName, params);
                }
            }
        }
        while (FindNextFile(hFind, &ffd) != 0 && !(*killed));

        if (GetLastError() != ERROR_NO_MORE_FILES)
        {
            FindClose(hFind);
            s = 1;
            break;
        }

        Fifo_pop_front(&directories);

        FindClose(hFind);
        hFind = INVALID_HANDLE_VALUE;
    }
    
    Fifo_clear(&directories);

    return s;
}


//BOOL checkPath(PCHAR path, BOOL is_dir)
//{
//	HANDLE file;
//	DWORD attributes = FILE_ATTRIBUTE_NORMAL;
//	if (is_dir)
//		attributes = FILE_FLAG_BACKUP_SEMANTICS;
//
//	file = CreateFile(
//		path,
//		GENERIC_READ,
//		FILE_SHARE_READ,
//		NULL,
//		OPEN_EXISTING,
//		attributes,
//		NULL
//	);
//
//	if (file == INVALID_HANDLE_VALUE)
//	{
//		printf("ERROR (0x%lx): \"%s\" does not exist.\n", GetLastError(), path);
//		return FALSE;
//	}
//
//	if (is_dir)
//	{
//		BY_HANDLE_FILE_INFORMATION FileInformation = { 0 };
//		BOOL s = GetFileInformationByHandle(file, &FileInformation);
//		if (!s)
//		{
//			printf("ERROR (0x%lx): getFileInformationByHandle failed.\n", GetLastError());
//			return FALSE;
//		}
//
//		if (!(FileInformation.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
//		{
//			printf("ERROR: \"%s\" not a directory.\n", path);
//			return FALSE;
//		}
//	}
//
//	CloseHandle(file);
//
//	return TRUE;
//}

size_t getFullPathName(
    const char* src, 
    char* full_path, 
    const char** base_name
)
{
    int fpl = GetFullPathNameA((char*)src, MAX_PATH, full_path, (char**)base_name);
    if (!fpl)
    {
        printf("ERROR (0x%lx): Get full path failed for \"%s\".", GetLastError(), src);
        return 0;
    }
    return fpl;
}

int mkdir_r(const char* dir)
{
    BOOL s;

    const char* path = dir;
    const size_t len = strlen(path);
    char _path[MAX_PATH];
    char* p;
    int errsv;

    errno = 0;
    debug_info("mkdir_r\n");

    // Copy char* so its mutable
    if ( len > sizeof(_path) - 1 )
    {
        errno = ENAMETOOLONG;
        return -1;
    }
    errsv = strcpy_s(_path, MAX_PATH, path);
    if ( errsv != 0 )
    {
        printf("ERROR (0x%x): strcpy_s(%s)!\n", errsv, path);
        return -1;
    }
    _path[MAX_PATH-1] = 0;

    for ( p = _path + 1; *p; p++ )
    {
        if ( *p == PATH_SEPARATOR )
        {
            // Temporarily truncate
            *p = '\0';

            s = CreateDirectoryA(_path, NULL);
            if ( !s )
            {
                errsv = GetLastError();
                if (errsv != ERROR_ALREADY_EXISTS)
                {
                    printf("ERROR (0x%x): Creating directory \"%s\" failed!\n", GetLastError(), _path);
                    return -1;
                }
            }

            *p = PATH_SEPARATOR;
        }
    }

    s = CreateDirectoryA(_path, NULL);
    if ( !s )
    {
        errsv = GetLastError();
        if ( errsv != ERROR_ALREADY_EXISTS )
        {
            printf("ERROR (0x%x): Creating directory \"%s\" failed!\n", GetLastError(), _path);
            return -1;
        }
    }

    return 0;
}
