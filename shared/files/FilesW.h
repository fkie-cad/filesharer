#ifndef SHARED_FILES_W_H
#define SHARED_FILES_W_H

#include <windows.h>
#include <winternl.h>

#include "Files.h"
#include "FilesFlags.h"


#if defined(_WIN32)
#define mkdir(p) _mkdir(p)
//#define struct stat struct __stat64 
#endif


#define PATH_SEPARATOR WIN_PATH_SEPARATOR



typedef void (*FileCallback)(char*, char*, void*);
//typedef int (*Condition)(char*);



/**
* Find files in directory with specified file_type and call back on each file.
* Links will be followed, unless FileUtil::FOLLOW_LINKS is set to false.
* Hidden directories may be skipped by setting FileUtil::SKIP_HIDDEN_DIRS.
* Hidden files may be skipped by setting FileUtil::SKIP_HIDDEN_FILES.
*
* @param	dir char* the directory to search
* @param	cb FileCallback the callback(char*) called on each found file
* @param	types char** A white list of file types to search for
* @param	flags : FLAG_RECURSIVE
* @param	params void* Addidtional params to be passed back in the callback
*/
int actOnFilesInDir(
    const char* dir,
    FileCallback cb,
    const char** types,
    uint32_t flags,
    void* params,
    int* killed
);

//int actOnFilesInDir(const char* path, const FileCallback* cb, const Condition* condition, int recursive)

/**
* Find files in directory with specified file_type and call back on each file.
* Links will be followed, unless FileUtil::FOLLOW_LINKS is set to false.
* Hidden directories may be skipped by setting FileUtil::SKIP_HIDDEN_DIRS.
* Hidden files may be skipped by setting FileUtil::SKIP_HIDDEN_FILES.
*
* @param	dir char* the directory to search (recursive if #recursive_search is true)
* @param	cb FileCallback the callback(char*) called on each found file
* @param	types char** A black list of file types that are skipped.
* @param	recursive int do a "recursive" search including all subdirectories
* @throws	runtime_error
*/
int actOnFilesInDirWithBlackList(
    const char* dir, 
    const FileCallback* cb,
    const char** types,
    int recursive
);

/**
* Count files in a given directory structure.
* Links will be followed, unless FileUtil::FOLLOW_LINKS is set to false.
* Hidden directories may be skipped by setting FileUtil::SKIP_HIDDEN_DIRS.
* Hidden files may be skipped by setting FileUtil::SKIP_HIDDEN_FILES.
*
* @param	directory char* the directory path
* @param	set<char*> file_types
* @param	c int condition whether to whitelist or blacklist the given file types
* @param	recursive int flag for recursive directory search
* @return	uint64_t file_count
* @throws	runtime_error
*/
uint64_t countFiles(
    const char* dir, 
    const char** types, 
    int c, 
    int recursive
);

//BOOL checkPath(PCHAR path, BOOL is_dir);

size_t getFullPathName(
    const char* src, 
    size_t n,
    char* full_path, 
    const char** base_name
);

/**
 * Make dirs recursively.
 * From: https://gist.github.com/JonathonReinhart/8c0d90191c38af2dcadb102c4e202950
 *
 * @param	dir char* the dir path
 */
int mkdir_r(const char* path);

#endif
