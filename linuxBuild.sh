#!/bin/bash

name=FShare
def_target=app
pos_targets="${def_target}|cln"
target=${def_target}
def_mode=Release
mode=${def_mode}
help=0
vb=0
dp=0


# Clean build directory from meta files
# or all files

# @param $1 build directory
# @param $2 flag: 1= all files
function clean() {
    local dir=$1
    local flag=$2

    if [[ ${dir} == "${ROOT}" ]]; then
        return
    fi

    cd ${dir} || return 1

    if [[ ${flag} == "1" ]]; then
        rm -r ./*
        return
    fi

    rm -r ./CMakeFiles
    rm -r ./CTestTestfile.cmake
    rm -r ./CMakeCache.txt
    rm -r ./cmake_install.cmake
    rm -rf ./tests
    rm -f ./*.cbp
    rm -r ./Makefile
    rm -rf ./debug

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
    local vb=$4
    local dp=$5

    if ! mkdir -p ${dir}; then
        return 1
    fi

    # if no space at -B..., older cmake (ubuntu 18) will not build
    if ! cmake -S ${ROOT} -B${dir} -DCMAKE_BUILD_TYPE=${mode} -DVERBOSE_BUILD=${vb} -DDEBUG_PRINT=${dp} -DERROR_PRINT=1; then
        return 2
    fi

    if ! cmake --build ${dir} --target ${target}; then
        return 3
    fi

    return 0
}

# Build a clean runnable package without metafiles.
#
# @param $1 cmake target
# @param $2 build directory
# @param $3 build mode
function buildPackage()
{
    local dir=$2
    local mode=$3
    local vb=$4
    local dp=$5

    if ! buildTarget ${name} ${dir} ${mode} ${vb} ${dp}; then
        return 1
    fi

    if ! clean ${dir}; then
        return 4
    fi

    return 0
}

function printUsage() {
    echo "Usage: $0 [-t ${pos_targets}] [-m Debug|Release] [-h]"
    echo "Default: $0 [-t ${def_target}] [-m ${def_mode}]"
    return 0;
}

function printHelp() {
    printUsage
    echo ""
    echo "-t A possible target: ${pos_targets}"
    echo "-m A compile mode: Release|Debug"
    echo "-p Turn on debug printing"
    echo "-h Print this."
    return 0;
}

while getopts ":m:t:hvp" opt; do
    case $opt in
    h)
        help=1
        ;;
    m)
        mode="$OPTARG"
        ;;
    t)
        target="$OPTARG"
        ;;
    v)
        vb=1
        ;;
    p)
        dp=1
        ;;
    \?)
        echo "Invalid option -$OPTARG" >&2
        ;;
    esac
done

if [[ ${help} == 1 ]]; then
    printHelp
    exit $?
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

release_build_dir="${ROOT}/build"
debug_build_dir="${ROOT}/build/debug"
if [[ ${mode} == "Debug" || ${mode} == "debug" ]]; then
    build_dir=${debug_build_dir}
else
    build_dir=${release_build_dir}
fi

echo "target: "${target}
echo "mode: "${mode}
echo "build_dir: "${build_dir}

if [[ ${target} == "cln" || ${target} == "clean" || ${target} == "Clean" ]]; then
    clean ${build_dir} 0
    exit $?
elif [[ ${target} == "clr" ]]; then
    clean ${build_dir} 1
    exit $?
elif [[ ${target} == "pck" ]]; then
    buildPackage ${name} ${release_build_dir} Release ${vb} ${dp}
    exit $?
elif [[ ${target} == "app" ]]; then
    buildTarget ${name} ${build_dir} ${mode} ${vb} ${dp}
    exit $?
else
    buildTarget ${target} ${build_dir} ${mode} ${vb} ${dp}
    exit $?
fi

exit $?
