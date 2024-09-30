#ifndef PRINT_H
#define PRINT_H

#if DEBUG_PRINT
#define DPrint(...) \
                {printf("[d] ");\
                 printf(__VA_ARGS__);}
#define FPrint() \
                {printf(DRIVER_NAME ": [f] %s\n", __FUNCTION__)};
#define DPrintMemCol8(_b_, _s_, _o_) \
{ \
    for ( size_t _i_ = 0; _i_ < (size_t)_s_; _i_+=0x10 ) \
    { \
        size_t _end_ = (_i_+0x10<_s_)?(_i_+0x10):((size_t)_s_); \
        uint32_t _gap_ = (_i_+0x10<=_s_) ? 0 : (uint32_t)((0x10+_i_-(size_t)_s_)*3); \
        printf("%p  ", (((uint8_t*)_o_)+_i_)); \
         \
        for ( size_t _j_ = _i_, _k_=0; _j_ < _end_; _j_++, _k_++ ) \
        { \
            printf("%02x", ((uint8_t*)_b_)[_j_]); \
            printf("%c", (_k_==7?'-':' ')); \
        } \
        for ( uint32_t _j_ = 0; _j_ < _gap_; _j_++ ) \
        { \
            printf(" "); \
        } \
        printf("  "); \
        for ( size_t _j_ = _i_; _j_ < _end_; _j_++ ) \
        { \
            if ( ((uint8_t*)_b_)[_j_] < 0x20 || ((uint8_t*)_b_)[_j_] > 0x7E || ((uint8_t*)_b_)[_j_] == 0x25 ) \
            { \
                printf("."); \
            }  \
            else \
            { \
                printf("%c", ((uint8_t*)_b_)[_j_]); \
            } \
        } \
        printf("\n"); \
    } \
}
#define DPrintMemCol16(_b_, _s_) \
    if ( _s_ % 2 != 0 ) _s_ = _s_ - 1; \
    \
    for ( size_t _i_ = 0; _i_ < (size_t)_s_; _i_+=0x10 ) \
    { \
        size_t _end_ = (_i_+0x10<_s_)?(_i_+0x10):((size_t)_s_); \
        uint32_t _gap_ = (_i_+0x10<=_s_) ? 0 : ((0x10+_i_-(size_t)_s_)/2*5); \
        printf("%p  ", (((uint8_t*)_b_)+_i_)); \
         \
        for ( size_t _j_ = _i_; _j_ < _end_; _j_+=2 ) \
        { \
            printf("%04x ", *(uint16_t*)&(((uint8_t*)_b_)[_j_])); \
        } \
        for ( uint32_t _j_ = 0; _j_ < _gap_; _j_++ ) \
        { \
            printf(" "); \
        } \
        printf("  "); \
        for ( size_t _j_ = _i_; _j_ < _end_; _j_+=2 ) \
        { \
            printf("%wc", *(uint16_t*)&(((uint8_t*)_b_)[_j_])); \
        } \
        printf("\n"); \
    }
#define DPrintMemCol32(_b_, _s_) \
    if ( _s_ % 4 != 0 ) _s_ = _s_ - (_s_ % 4); \
    \
    for ( size_t _i_ = 0; _i_ < (size_t)_s_; _i_+=0x10 ) \
    { \
        size_t _end_ = (_i_+0x10<_s_)?(_i_+0x10):((size_t)_s_); \
        printf("%p  ", (((uint8_t*)_b_)+_i_)); \
         \
        for ( size_t _j_ = _i_; _j_ < _end_; _j_+=4 ) \
        { \
            printf("%08x ", *(uint32_t*)&(((uint8_t*)_b_)[_j_])); \
        } \
        printf("\n"); \
    }
#define DPrintMemCol64(_b_, _s_) \
    if ( _s_ % 8 != 0 ) _s_ = _s_ - (_s_ % 8); \
    \
    for ( size_t _i_ = 0; _i_ < (size_t)_s_; _i_+=0x10 ) \
    { \
        size_t _end_ = (_i_+0x10<_s_)?(_i_+0x10):((size_t)_s_); \
        printf("%p  ", (((uint8_t*)_b_)+_i_)); \
         \
        for ( size_t _j_ = _i_; _j_ < _end_; _j_+=8 ) \
        { \
            printf("%016llx ", *(uint64_t*)&(((uint8_t*)_b_)[_j_])); \
        } \
        printf("\n"); \
    }
#define DPrintBytes(_b_, _s_) \
{ \
    for ( size_t _i_ = 0; _i_ < (size_t)_s_; _i_+=0x10 ) \
    { \
        size_t _end_ = (_i_+0x10<_s_)?(_i_+0x10):((size_t)_s_); \
        printf("%p  ", (((uint8_t*)_b_)+_i_)); \
         \
        for ( size_t _j_ = _i_; _j_ < _end_; _j_++ ) \
        { \
            printf("%02x ", ((uint8_t*)_b_)[_j_]); \
        } \
        printf("\n"); \
    } \
}
#define DPrintUUID(__prefix__, __uuid__) DPrint("%s: %08x-%04x-%04x-%02x%02-x%02x%02x%02x%02x%02x%02x\n", __prefix__, __uuid__.Data1, __uuid__.Data2, __uuid__.Data3, __uuid__.Data4[0], __uuid__.Data4[1], __uuid__.Data4[2], __uuid__.Data4[3], __uuid__.Data4[4], __uuid__.Data4[5], __uuid__.Data4[6], __uuid__.Data4[7]);

#define DPrint_D(__value__, __prefix__) \
     printf("%s%s: %llu\n", __prefix__, #__value__, (size_t)__value__);

#define DPrint_H(__value__, __prefix__) \
     printf("%s%s: 0x%llx\n", __prefix__, #__value__, (size_t)__value__);

#define DPrint_HD(__value__, __prefix__) \
     printf("%s%s: 0x%llx (%llu)\n", __prefix__, #__value__, (size_t)__value__, (size_t)__value__);

#define DPrint_P(__value__, __prefix__) \
     printf("%s%s: %p\n", __prefix__, #__value__, (PVOID)__value__);

#define DPrint_A(__value__, __prefix__) \
     printf("%s%s: %s\n", __prefix__, #__value__, (PCHAR)__value__);

#define DPrint_Ax(__value__, __size__, __prefix__) \
     printf("%s%s: %.*s\n", __prefix__, #__value__, __size__, (PCHAR)__value__);
#else
#define DPrint(...)
#define DPrintMemCol8(...)
#define DPrintMemCol16(...)
#define DPrintMemCol32(...)
#define DPrintMemCol64(...)
#define DPrintBytes(...)
#define DPrintUUID(...)
#define DPrint_D(...)
#define DPrint_H(...)
#define DPrint_HD(...)
#define DPrint_A(...)
#define DPrint_Ax(...)
#endif

#if ERROR_PRINT
#define EPrint(_s_, ...) \
                {fprintf(stderr, "ERROR (0x%x): ", _s_); \
                 fprintf(stderr, __VA_ARGS__);}
#define EPrintNl() {fprintf(stderr, "\n");}
#define EPrintCr() {fprintf(stderr, "\r");}
#else
#define EPrint(_s_, ...)
#define EPrintNl()
#define EPrintCr()
#endif

#define HEX_CHAR_WIDTH(__hcw_v__, __hcw_w__) \
{ \
    uint8_t _hcw_w_ = 0x10; \
    for ( uint8_t _i_ = 0x38; _i_ > 0; _i_-=8 ) \
    { \
        if ( ! ((uint8_t)(__hcw_v__ >> _i_)) ) \
            _hcw_w_ -= 2; \
        else \
            break; \
    } \
    __hcw_w__ = _hcw_w_; \
}

#define PrintMemCol8(_b_, _s_, _a_) \
{ \
    uint64_t _hw_v_ = (size_t)_a_ + (size_t)_s_; \
    uint8_t _hw_w_ = 0x10; \
    HEX_CHAR_WIDTH(_hw_v_, _hw_w_); \
    \
    for ( size_t _i_ = 0; _i_ < (size_t)_s_; _i_+=0x10 ) \
    { \
        size_t _end_ = (_i_+0x10<_s_) ? (_i_+0x10) : ((size_t)_s_); \
        uint32_t _gap_ = (_i_+0x10<=_s_) ? 0 : (uint32_t)((0x10+_i_-(size_t)_s_)*3); \
        printf("%.*zx  ", _hw_w_, (((size_t)_a_)+_i_)); \
         \
        for ( size_t _j_ = _i_, _k_=0; _j_ < _end_; _j_++, _k_++ ) \
        { \
            printf("%02x", ((uint8_t*)_b_)[_j_]); \
            printf("%c", (_k_==7?'-':' ')); \
        } \
        for ( uint32_t _j_ = 0; _j_ < _gap_; _j_++ ) \
        { \
            printf(" "); \
        } \
        printf("  "); \
        for ( size_t _k_ = _i_; _k_ < _end_; _k_++ ) \
        { \
            if ( ((uint8_t*)_b_)[_k_] < 0x20 || ((uint8_t*)_b_)[_k_] > 0x7E || ((uint8_t*)_b_)[_k_] == 0x25 ) \
            { \
                printf("."); \
            }  \
            else \
            { \
                printf("%c", ((uint8_t*)_b_)[_k_]); \
            } \
        } \
        printf("\n"); \
    } \
}

#define PrintMemCol16(_b_, _s_, _a_) \
{\
    uint64_t _hw_v_ = (size_t)_a_ + (size_t)_s_; \
    uint8_t _hw_w_ = 0x10; \
    HEX_CHAR_WIDTH(_hw_v_, _hw_w_); \
    \
    if ( _s_ % 2 != 0 ) _s_ = _s_ - 1; \
    \
    for ( size_t _i_ = 0; _i_ < (size_t)_s_; _i_+=0x10 ) \
    { \
        size_t _end_ = (_i_+0x10<_s_)?(_i_+0x10):((size_t)_s_); \
        uint32_t _gap_ = (_i_+0x10<=_s_) ? 0 : ((0x10+_i_-(size_t)_s_)/2*5); \
        printf("%.*zx  ", _hw_w_, (((size_t)_a_)+_i_)); \
         \
        for ( size_t _j_ = _i_; _j_ < _end_; _j_+=2 ) \
        { \
            printf("%04x ", *(uint16_t*)&(((uint8_t*)_b_)[_j_])); \
        } \
        for ( uint32_t _j_ = 0; _j_ < _gap_; _j_++ ) \
        { \
            printf(" "); \
        } \
        printf("  "); \
        for ( size_t _j_ = _i_; _j_ < _end_; _j_+=2 ) \
        { \
            printf("%wc", *(uint16_t*)&(((uint8_t*)_b_)[_j_])); \
        } \
        printf("\n"); \
    } \
}

#define PrintMemCol32(_b_, _s_, _a_) \
{\
    uint64_t _hw_v_ = (size_t)_a_ + (size_t)_s_; \
    uint8_t _hw_w_ = 0x10; \
    HEX_CHAR_WIDTH(_hw_v_, _hw_w_); \
    if ( _s_ % 4 != 0 ) _s_ = _s_ - (_s_ % 4); \
    \
    \
    for ( size_t _i_ = 0; _i_ < (size_t)_s_; _i_+=0x10 ) \
    { \
        size_t _end_ = (_i_+0x10<_s_)?(_i_+0x10):((size_t)_s_); \
        printf("%.*zx  ", _hw_w_, (((size_t)_a_)+_i_)); \
         \
        for ( size_t _j_ = _i_; _j_ < _end_; _j_+=4 ) \
        { \
            printf("%08x ", *(uint32_t*)&(((uint8_t*)_b_)[_j_])); \
        } \
        printf("\n"); \
    } \
}

#define PrintMemCol64(_b_, _s_, _a_) \
{\
    uint64_t _hw_v_ = (size_t)_a_ + (size_t)_s_; \
    uint8_t _hw_w_ = 0x10; \
    HEX_CHAR_WIDTH(_hw_v_, _hw_w_); \
    if ( _s_ % 8 != 0 ) _s_ = _s_ - (_s_ % 8); \
    \
    \
    for ( size_t _i_ = 0; _i_ < (size_t)_s_; _i_+=0x10 ) \
    { \
        size_t _end_ = (_i_+0x10<_s_)?(_i_+0x10):((size_t)_s_); \
        printf("%.*zx  ", _hw_w_, (((size_t)_a_)+_i_)); \
         \
        for ( size_t _j_ = _i_; _j_ < _end_; _j_+=8 ) \
        { \
            printf("%016llx ", *(uint64_t*)&(((uint8_t*)_b_)[_j_])); \
        } \
        printf("\n"); \
    } \
}

#define PrintMemBytes(_b_, _s_) \
{ \
    for ( size_t _i_ = 0; _i_ < (size_t)_s_; _i_++ ) \
    { \
        printf("%02x ", ((uint8_t*)_b_)[_i_]); \
    } \
    printf("\n"); \
}

#endif
