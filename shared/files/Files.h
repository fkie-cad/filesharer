#ifndef SHARED_FILES_H
#define SHARED_FILES_H


#if defined(_WIN32)
#include <windows.h>
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>



#if defined(Win64) || defined(_WIN64)
#define fseek(f, o, t) _fseeki64(f, o, t)
#define ftell(s) _ftelli64(s)
#define wstat(p,b) _wstat64(p,b)
#define stat(p,b) _stat64(p,b)
#endif

#define LIN_PATH_SEPARATOR (0x2F)
#define WIN_PATH_SEPARATOR (0x5C)



/*
 * Crop trailing slash of a path.
 *
 * @param	path char* the path
 */
void cropTrailingSlash(
    char* path
);

/*
 * Convert file path slash to os default.
 *
 * @param	path char* the path
 */
void convertPathSeparator(
    char* path
);

/**
* Get file size the POSIX way in bytes.
* Does not open the file.
* Faster than the fstream method.
*
* @param	path char* the file source
* @return	uint32_t the file size
*/
int getFileSize(
    const char* path, 
    size_t* size
);

/**
* Check if a file exists.
*
* @param path
* @return
*/
int fileExists(
    const char* path
);

/**
 * Check if a dir exists.
 *
 * @param path
 * @return
 */
int dirExists(
    const char* path
);

/**
 * Check if a path (dir or file) exists.
 *
 * @param path
 * @return
 */
int checkPath(
    const char* path, 
    int is_dir
);

/**
 * Extract the base file name out of a file_path.
 * "Light" version just pointing to the file_name in the memory of file_path.
 *
 * @param file_path char*
 * @param file_name char**
 */
size_t getBaseName(
    const char* file_path,
    size_t file_path_ln, 
    const char** base_name
);

/**
 * Extract the base file name out of a file_path.
 * (C)opying the found name into file_name.
 * Make sure, file_name char[] has a capacity of file_name_ln.
 * If file_name[] will be zero terminated and may be cropped if buffer is too small.
 *
 * @param file_path char*
 * @param file_name char*
 */
void getBaseNameC(
    const char* file_path, 
    char* file_name, 
    size_t *file_name_ln
);

/**
 * Extract the base file name out of a file_path.
 * Copying the found name into file_name (a)llocated char*.
 * Caller is responsible for freeing it!
 *
 * @param 	file_path char*
 * @return	char* the file name
 */
char* getBaseNameA(
    const char* file_path, 
    size_t *file_name_ln
);

size_t getBaseNameOffset(
    const char* file_path,
    size_t file_path_ln
);

#endif
