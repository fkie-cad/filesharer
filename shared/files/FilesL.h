#ifndef SHARED_FILES_L_H
#define SHARED_FILES_L_H

#include <stdint.h>
#include <stdio.h>

#include "Files.h"
#include "FilesFlags.h"

#define PATH_SEPARATOR LIN_PATH_SEPARATOR




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
* @param	flags : FILES_FLAG_RECURSIVE, FILES_FLAG_FOLLOW_LINKS, FILES_FLAG_SKIP_HIDDEN_DIRS
* @param	params void* Additional params to be passed back in the callback
*/
int actOnFilesInDir(
        const char* dir,
        FileCallback cb,
        const char** types,
        uint32_t flags,
        void* params,
        const int* killed
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

/**
 * Expand a leading '~' in src to a full file path in dest.
 * dest has to be size of PATH_MAX.
 *
 * @param src char*
 * @param dest char*
 */
size_t expandFilePath(const char* src, char* dest, size_t n);

/**
 * Create a temporary file and store its name in buf.
 * Currently Linux only.
 *
 * @param	buf char[128]
 * @param	prefix char* name prefix of the tmp file
 * @return	int status code
 */
int getTempFile(char* buf, const char* prefix);

/**
 * List all files in a directory.
 *
 * @param path char* the directory path.
 */
void listFilesOfDir(char* path);

/**
 * Get full path and base name
 *
 * @param src char* the path.
 * @param full_path char* Allocated pointer to the full path buffer.
 * @param path char* Pointer to the base_name in the full_path. No allocation required.
 */
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
