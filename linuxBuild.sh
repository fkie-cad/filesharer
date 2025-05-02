#!/bin/bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

release_build_dir="${ROOT}/build"
debug_build_dir="${ROOT}/build/debug"

MODE_DEBUG=1
MODE_RELEASE=2

DP_FLAG=1
EP_FLAG=2

name=FShare
def_target=app
pos_targets="${def_target}"
target=
mode=$MODE_RELEASE
help=0
debug_print=$EP_FLAG
clean=0


# Clean build directory from meta files
# or all files

# @param $1 build directory
# @param $2 flag: 1= all files
function clean() {
    local dir=$1
    local flag=$2

    echo "cleaning build dir: $dir"

    if [[ ${dir} != "${release_build_dir}" ]] && [[ ${dir} != "${debug_build_dir}" ]]; then
        echo [e] Invalid clean dir!
        return
    fi

    cd ${dir} || return 1

    if [[ ${flag} == "1" ]]; then
        rm -r ./*
        return
    fi

    rm -r ./CMakeFiles 2> /dev/null
    rm -r ./CTestTestfile.cmake 2> /dev/null
    rm -r ./CMakeCache.txt 2> /dev/null
    rm -r ./cmake_install.cmake 2> /dev/null
    rm -rf ./tests 2> /dev/null
    rm -f ./*.cbp 2> /dev/null
    rm -r ./Makefile 2> /dev/null
    rm -rf ./debug 2> /dev/null

    rm -f ./*.o 2> /dev/null

    cd - || return 2

    return 0
}

# CMake build a target
#
# @param $1 cmake target
# @param $2 build directory
# @param $3 build mode
function buildTarget() {
    local target=$1
    local dir=$2
    local mode=$3
    local dp=$4
    local ep=0

    if ! mkdir -p ${dir}; then
        return 1
    fi

    if [[ $((dp & $EP_FLAG)) == $EP_FLAG ]]; then
        ep=1
    fi
    dp=$((dp & ~$EP_FLAG))

    if [[ ${mode} == $MODE_DEBUG ]]; then
        local flags="-Wall -pedantic -Wextra -ggdb -O0 -Werror=return-type -Werror=overflow -Werror=format"
    else
        local flags="-Wall -pedantic -Wextra -Ofast -Werror=return-type -Werror=overflow -Werror=format"
    fi

    local dpf=
    if [[ $dp > 0 ]]; then
        dpf=-DDEBUG_PRINT=$dp
    fi

    local epf=
    if [[ $ep > 0 ]]; then
        epf=-DERROR_PRINT
    fi

    gcc -o ${dir}/FShare -Wl,-z,relro,-z,now -D_FILE_OFFSET_BITS=64 $flags $dpf $epf -L/usr/lib -lcrypto src/fshare.c src/client.c src/server.c shared/*.c shared/collections/*.c shared/crypto/linux/*.c shared/files/Files.c shared/files/FilesL.c shared/net/sock.c shared/net/linSock.c src/FsHeader.c -Ishared

    return $?
}

function printUsage() {
    echo "Usage: $0 [-t ${pos_targets}] [-d|-r] [-h]"
    echo "Default: $0 [-t ${def_target}] [-r]"
    return 0;
}

function printHelp() {
    printUsage
    echo ""
    echo "-t A possible target: ${pos_targets}"
    echo "-d Build in debug mode"
    echo "-r Build in release mode"
    echo "-p Set debug printing <level>"
    echo "-h Print this."
    return 0;
}

while (("$#")); do
    case "$1" in
        -c | -cln | --clean)
            clean=1
            shift 1
            ;;
        -d | --debug)
            mode=$MODE_DEBUG
            shift 1
            ;;
        -r | --release)
            mode=$MODE_RELEASE
            shift 1
            ;;
        -p | -dp | --debug-print)
            debug_print=$2
            shift 2
            ;;
        -t | --target)
            target=$2
            shift 2
            ;;
        -h | --help)
            help=1
            break
            ;;
        -* | --usage)
            usage=1
            break
            ;;
        *) # No more options
            break
            ;;
    esac
done

if [[ ${usage} == 1 ]]; then
    printUsage
    exit $?
fi

if [[ ${help} == 1 ]]; then
    printHelp
    exit $?
fi

if [[ ${mode} == $MODE_DEBUG || ${mode} == $MODE_DEBUG ]]; then
    build_dir=${debug_build_dir}
else
    build_dir=${release_build_dir}
fi

if [[ -z ${target} ]] && [[ ${clean} == 0 ]]; then
    target=$def_target
fi

echo "clean: "${clean}
echo "target: "${target}
echo "mode: "${mode}
echo "build_dir: "${build_dir}
echo -e


if [[ ${clean} == 1 ]]; then
    clean ${build_dir}
elif [[ ${clean} == 2 ]]; then
    clean ${build_dir} 1
fi

if [[ -n ${target} ]]; then
    buildTarget ${target} ${build_dir} ${mode} ${dp}
fi

exit $?
