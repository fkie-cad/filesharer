#ifndef PRINT_H
#define PRINT_H

#if DEBUG_PRINT
#define DPrint(...) \
                {fprintf(stdout, "[d] ");\
                 fprintf(stdout, __VA_ARGS__);}

#else
#define DPrint(...)
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

#endif
