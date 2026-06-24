#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
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

char *realpath_noent(const char *path, char *resolved)
{
    FEnter();

    int errsv = 0;
    char scratch[PATH_MAX] = { 0 };
    char suffix[PATH_MAX] = ""; // non-existing trailing part
    char tmp[PATH_MAX] = { 0 };
    char real[PATH_MAX] = { 0 };

    strncpy(scratch, path, PATH_MAX - 1);
    scratch[PATH_MAX - 1] = '\0';

    while ( 1 )
    {
        DPrint("scratch: %s\n", scratch);
        DPrint("real: %s\n", real);
     
        char* rp = realpath(scratch, real );
        DPrint("realpath(scratch, real ): %s\n", rp);
        if ( rp != NULL )
        {
            DPrint("realpath(scratch, real ) != NULL\n");
            DPrint("  real: %s\n", real);
            DPrint("  suffix: %s\n", suffix);
            // Found the deepest existing ancestor
            if ( suffix[0] != '\0' )
            {
                size_t real_cb = strlen(real);
                size_t suffix_cb = strlen(suffix);

                if ( real_cb + 1 + suffix_cb >= PATH_MAX )
                    return NULL; // overflow

                memcpy(resolved, real, real_cb);
                resolved[real_cb] = '/';
                memcpy(resolved+real_cb+1, suffix, suffix_cb+1);
                // snprintf(resolved, PATH_MAX, "%s/%s", real, suffix); // -Werror=format-truncation
            }
            else
            {
                strncpy(resolved, real, PATH_MAX);
            }
            DPrint("  resolved: %s\n", resolved);
            errno = 0;
            break;
        }

        // Peel off the last component into the suffix
        strncpy(tmp, scratch, PATH_MAX);
        char *base = basename(tmp); // last component
        DPrint("realpath(scratch, real ) == NULL\n");
        DPrint("  tmp: %s\n", tmp);
        DPrint("  base: %s\n", base);

        if (strcmp(base, "/") == 0 || strcmp(base, ".") == 0)
        {
            // Hit the root or a degenerate case — give up
            return NULL;
        }

        DPrint("  suffix: %s\n", suffix);
        // Prepend base to suffix: suffix = base/suffix  (or just base)
        if (suffix[0] != '\0')
        {
            size_t base_cb = strlen(base);
            size_t suffix_cb = strlen(suffix);

            if ( base_cb + 1 + suffix_cb >= PATH_MAX )
                return NULL; // overflow

            char new_suffix[PATH_MAX];
            memcpy(new_suffix, base, base_cb);
            new_suffix[base_cb] = '/';
            memcpy(new_suffix+base_cb+1, suffix, suffix_cb+1);
            // snprintf(new_suffix, PATH_MAX, "%s/%s", base, suffix); // -Werror=format-truncation
            strncpy(suffix, new_suffix, PATH_MAX);
        }
        else
        {
            size_t base_cb = strlen(base);
            if ( base_cb >= PATH_MAX )
                return NULL; // overflow

            memcpy(suffix, base, base_cb+1);
        }
        DPrint("  suffix: %s\n", suffix);

        // Move up: scratch = dirname(scratch)
        strncpy(tmp, scratch, PATH_MAX);
        DPrint("  tmp: %s\n", tmp);
        char *dir = dirname(tmp);
        DPrint("  dir: %s\n", dir);

        if ( strcmp(dir, scratch) == 0 ) // no progress (e.g. at "/")
            return NULL;

        size_t dir_cb = strlen(dir);
        if ( dir_cb >= PATH_MAX )
            return NULL; // overflow

        memcpy(scratch, dir, dir_cb+1);
        DPrint("  scratch: %s\n", scratch);
    }

    FLeave();
    return resolved;
}

size_t getFullPathName(const char* src, size_t max, char* full_path, char** base_name)
{
    FEnter();
    int errsv = 0;
    
    DPrint("  src: %s\n", src);
    
    char* fp = realpath_noent(src, full_path);
    errsv = errno;
    DPrint("  errno: 0x%x\n", errsv);
    DPrint("  full_path: %s\n", full_path);
    if ( fp == NULL || errsv != 0 )
    {
        printf("[e] realpath_noent failed! (0x%x)\n", errno);
        return 0;
    }
    size_t n = strlen(full_path);
    DPrint("  n: 0x%zx\n", n);
    if ( base_name != NULL )
    {
        *base_name = basename(full_path);
        if ( !base_name )
            return 0;
//         size_t bn = getBaseName(full_path, n, base_name);
//         DPrint("  bn: 0x%zx\n", bn);
        // if ( !bn )
        //     return 0;
        DPrint("  base_name: %s\n", *base_name);
    }

    FLeave();
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
