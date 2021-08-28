#ifndef SHARED_VALUES_H
#define SHARED_VALUES_H

#define BUFFER_SIZE (0x1000)

#define AES_SECRET_SIZE (0x20)

#define FS_PACKET_SUCCESS (0x00000000)
#define FS_ERROR_RECV_HEADER (0xE0000001)
#define FS_ERROR_WRONG_HEADER_TYPE (0xE0000002)

#define FS_ERROR_CREATE_FILE (0xE0000010)
#define FS_ERROR_WRITE_FILE (0xE0000011)
#define FS_ERROR_CREATE_DIR (0xE0000012)
#define FS_ERROR_ALLOC_FILE_BUFFER (0xE0000013)
#define FS_ERROR_NULL_FILE_BUFFER (0xE0000014)
#define FS_ERROR_FILE_PATH_TOO_BIG (0xE0000015)

#define FS_ERROR_DECRYPT_AES_KEY (0xE0000020)
#define FS_ERROR_GENERATE_AES_KEY (0xE0000021)
#define FS_ERROR_DECRYPT_FILE_HEADER (0xE0000022)
#define FS_ERROR_DECRYPT_FILE_DATA (0xE0000023)

#endif
