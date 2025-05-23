#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>

#include <dirent.h>

#include "print.h"
#include "FilesL.h"
#include "collections/Fifo.h"



#define LINK_NAME_MAX (PATH_MAX)


int actOnFilesInDir(const char* path, FileCallback cb, const char** types, uint32_t flags, void* params, const int* killed)
{
    Fifo directories;
    PFifoEntry entry;

    const char* act_path;
    DIR *dir;
    struct dirent *ent;
    char ent_path[PATH_MAX];
    ssize_t r;
    char link_name[LINK_NAME_MAX];
    int s = 1;
    int recursive = flags & FILES_FLAG_RECURSIVE;
    int follow_links = flags & FILES_FLAG_FOLLOW_LINKS;
//    int skip_hidden_files = flags & FILES_FLAG_SKIP_HIDDEN_FILES;
    int skip_hidden_dirs = flags & FILES_FLAG_SKIP_HIDDEN_DIRS;
    (void)types;

    if ( !dirExists(path) )
    {
        printf("ERROR: FileUtil::actOnFilesInDir: \"%s\" does not exist!", path);
        return 0;
    }

//  cropTrailingSlash(path);
    Fifo_init(&directories);
    Fifo_push(&directories, path, (size_t)strlen(path)+1);

    while ( !Fifo_empty(&directories) && !(*killed) )
    {
        entry = Fifo_front(&directories);
        act_path = (char*)entry->value;

        dir = opendir(act_path);
        if ( !dir )
        {
            printf("Could not open dir %s\n", act_path);
            s = 0;
            break;
        }

        while ((ent = readdir(dir)) != NULL && !(*killed) )
        {
            if ( ent->d_type == DT_REG )
            {
                snprintf(ent_path, PATH_MAX, "%s/%s", act_path, ent->d_name);
                ent_path[MAX_PATH-1] = 0;
                cb(ent_path, ent->d_name, params);
            }
            else if ( ent->d_type == DT_LNK && follow_links )
            {
                snprintf(ent_path, PATH_MAX, "%s/%s", act_path, ent->d_name);
                memset(link_name, 0, LINK_NAME_MAX);
                r = readlink(ent_path, link_name, LINK_NAME_MAX);
                if (r < 0) {
//                  printf("ERROR: FilesL::actOnFiles : Link resolution failed for %s\n", ent_path);
                    continue;
                }
                link_name[LINK_NAME_MAX-1] = 0;

                cb(link_name, ent->d_name, params);
            }
            else if ( recursive
                      && ent->d_type == DT_DIR && strcmp(ent->d_name, ".") != 0  && strcmp(ent->d_name, "..") != 0
                      && !(skip_hidden_dirs && ent->d_name[0] == '.') )
            {
                snprintf(ent_path, PATH_MAX, "%s/%s", act_path, ent->d_name);
                ent_path[MAX_PATH-1] = 0;
                DPrint(" - - dir: %s\n", ent_path);
                s = (int)Fifo_push(&directories, ent_path, strlen(ent_path)+1);
                DPrint(" - - fifo size: %u\n", s);
                if (s == 0)
                {
                    printf("Fifo push error!\n");
                    break;
                }
            }
        }
        closedir(dir);
        Fifo_pop_front(&directories);
    }

    Fifo_clear(&directories);

    return s;
}

int getTempFile(char* buf, const char* prefix)
{
    int s = 1;
    snprintf(buf, 128, "/tmp/%sXXXXXX.tmp", prefix);
    buf[127] = 0;

    s = mkstemps(buf, 4);
    return s;
}

void listFilesOfDir(char* path)
{
    DIR *d;
    struct dirent *dir;
    d = opendir(path);

    if ( !d )
        perror("listFilesOfDir: could not open dir!\n");

    while ( (dir = readdir(d)) != NULL )
    {
        if ( dir->d_type == DT_REG )
            printf("%s, ", dir->d_name);
    }
    closedir(d);
    printf("\n");
}

size_t getFullPathName(const char* src, size_t max, char* full_path, char** base_name)
{
#ifdef DEBUG_PRINT
    printf("[>] getFullPathName()\n");
    printf("  src: %s\n", src);
#endif
    //sin = expandFilePath(src, full_path, n);
    char* fp = realpath(src, full_path);
#ifdef DEBUG_PRINT
    printf("  full_path: %s\n", full_path);
#endif
    if ( fp == NULL && errno != ENOENT )
    {
        printf("[e] realpath failed! (0x%x)\n", errno);
        return 0;
    }
    size_t n = strlen(full_path);
#ifdef DEBUG_PRINT
    printf("  n: 0x%zx\n", n);
#endif
    if ( base_name != NULL )
    {
        size_t bn = getBaseName(full_path, n, base_name);
#ifdef DEBUG_PRINT
        printf("  bn: 0x%zx\n", bn);
#endif
        if ( !bn )
            return 0;
#ifdef DEBUG_PRINT
        printf("  base_name: %s\n", *base_name);
#endif
    }

#ifdef DEBUG_PRINT
    printf("[<] getFullPathName()\n");
#endif
    return n;
}

int mkdir_r(const char* dir)
{
    const char* path = dir;
    const size_t len = strlen(path);
    char _path[MAX_PATH];
    char* p;
    int errsv;

    errno = 0;

    if (len > sizeof(_path) - 1)
    {
        errno = ENAMETOOLONG;
        return errno;
    }
    errno = 0;
    strncpy(_path, path, MAX_PATH);
    errsv = errno;
    if (errsv != 0)
    {
        printf("ERROR (0x%x): strncpy(%s)!\n", errsv, path);
        return errsv;
    }
    _path[MAX_PATH-1] = 0;

    // Iterate the char*
    for (p = _path + 1; *p; p++)
    {
        if (*p == PATH_SEPARATOR)
        {
            // Temporarily truncate
            *p = '\0';

            if ( mkdir(_path, S_IRWXU) != 0 )
            {
                if (errno != EEXIST)
                {
                    printf("ERROR (0x%x): Creating directory \"%s\" failed!\n", errsv, _path);
                    return errno;
                }
            }

            *p = PATH_SEPARATOR;
        }
    }

    if ( mkdir(_path, S_IRWXU) != 0 )
    {
        if ( errno != EEXIST )
            return errno;
    }

    return 0;
}
