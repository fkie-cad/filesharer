cmake_minimum_required(VERSION 3.10)
project(Filesharer VERSION 1.3.15 DESCRIPTION "A file share client server." LANGUAGES C)


if (WIN32)
    message("No cmake support on Windows. Use msbuild and winBuild.bat.")
    return()
endif()

set(LANGUAGE C)
set(CMAKE_C_STANDARD 99)
# D_FILE_OFFSET_BITS using 64 bit version of file functions
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -pedantic -Werror -Werror=return-type -Werror=overflow -D_FILE_OFFSET_BITS=64")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Wl,-z,relro,-z,now -fno-builtin -Wall -pedantic -Werror -Werror=return-type -Werror=overflow -D_FILE_OFFSET_BITS=64")

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address -fsanitize=leak -fno-omit-frame-pointer")
#set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=undefined")

set (CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=leak -fsanitize=address")
#set (CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fsanitize=undefined")

message("VERBOSE_BUILD : ${VERBOSE_BUILD}")
if (VERBOSE_BUILD)
    set( CMAKE_VERBOSE_MAKEFILE on )
endif()

message("DEBUG_PRINT : ${DEBUG_PRINT}")
if (DEBUG_PRINT)
    add_definitions(-DDEBUG_PRINT)
    add_definitions(-DDEBUG_PRINT_INFO=1)
else()
    add_definitions(-DDEBUG_PRINT_INFO=0)
endif()

message("ERROR_PRINT : ${ERROR_PRINT}")
if (ERROR_PRINT)
    add_definitions(-DERROR_PRINT)
endif()

message("CMAKE_FLAGS_DEBUG : ${CMAKE_FLAGS_DEBUG}")
message("CMAKE_C_FLAGS_DEBUG : ${CMAKE_C_FLAGS_DEBUG}")
message("CMAKE_C_FLAGS_RELEASE : ${CMAKE_C_FLAGS_RELEASE}")
message("CMAKE_FLAGS_RELEASE : ${CMAKE_FLAGS_RELEASE}")
message("CMAKE_EXE_LINKER_FLAGS : ${CMAKE_EXE_LINKER_FLAGS}")

include_directories("shared")

include(cmake.inc/Libs.cmake)
include(cmake.inc/FsClient.cmake)
include(cmake.inc/FsServer.cmake)



# tests
if ( ${GTEST_FOUND} )
    enable_language(CXX)
    include(cmake.inc/Tests.cmake)
endif()
