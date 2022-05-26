#ifndef FLAGS_H
#define FLAGS_H

#define FLAG_CHECK_FILE_HASH     (0x1)
#define FLAG_RECURSIVE           (0x2)
#define FLAG_FLAT_COPY           (0x4)
#define FLAG_ENCRYPTED           (0x8)
#define FLAG_SERVER             (0x10)
#define FLAG_CLIENT             (0x20)


#define IS_ENCRYPTED(_f_) (_f_&FLAG_ENCRYPTED)

#endif
