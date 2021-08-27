#ifndef SHARED_ARGS_H
#define SHARED_ARGS_H

#include <stdio.h>

#include "types.h"

bool isAskForHelp(int argc, char** argv)
{
    char* arg;
    if (argc < 2)
        return false;
    arg = argv[1];
    return (arg[0] == LIN_PARAM_IDENTIFIER || arg[0] == WIN_PARAM_IDENTIFIER) && 
           (arg[1] == 'h' || arg[1] == '?') && 
            arg[2] == 0;
}

#endif
