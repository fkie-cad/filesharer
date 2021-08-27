@echo off

set target=all
set ct=Application
set /a bitness=64
set platform=x64
set mode=Release
set buildTools="C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools"
set verbose=1
set mt=no
set /a dp=0

set prog_name=%~n0
set user_dir="%~dp0"
set verbose=1



GOTO ParseParams

:ParseParams

    REM IF "%~1"=="" GOTO Main
    if [%1]==[/?] goto help
    if /i [%1]==[/h] goto help
    if /i [%1]==[/help] goto help

    IF /i "%~1"=="/t" (
        SET target=%2
        SHIFT
        goto reParseParams
    )
    IF /i "%~1"=="/b" (
        SET bitness=%~2
        SHIFT
        goto reParseParams
    )
    IF /i "%~1"=="/m" (
        SET mode=%~2
        SHIFT
        goto reParseParams
    )
    IF /i "%~1"=="/bt" (
        SET buildTools=%~2
        SHIFT
        goto reParseParams
    )
    IF /i "%~1"=="/mt" (
        SET mt=%~2
        SHIFT
        goto reParseParams
    )
    IF /i "%~1"=="/dp" (
        SET dp=1
        goto reParseParams
    )
    
    :reParseParams
        SHIFT
        if [%1]==[] goto main

GOTO :ParseParams


:main

set build_dir=build\%bitness%
if /i [%mode%]==[debug] set build_dir=build\debug\%bitness%

if [%bitness%] == [32] (
    set platform=x86
) else (
    if [%bitness%] == [64] (
        set platform=x64
    ) else (
        echo Unknown bitness "%bitness%"
        goto usage
    )
)

if [%verbose%] == [1] (
    echo target=%target%
    echo ConfigurationType=%ct%
    echo bitness=%bitness%
    echo platform=%platform%
    echo mode=%mode%
    echo build_dir=%build_dir%
    echo buildTools=%buildTools%
    echo debug print=%dp%
)

rem vcvarsall.bat [architecture] [platform_type] [winsdk_version] [ -vcvars_ver= vcversion]
rem architecture = x86, x86_x64, ... 

set vcvars="%buildTools:~1,-1%\VC\Auxiliary\Build\vcvars%bitness%.bat"


if /i [%target%]==[all] (
    call :buildAll
) else (
    call :build
)
exit /B 0

:buildAll
    SET target="FsServer"
    call :build
    SET target="FsClient"
    call :build
    exit /B 0

:build
   cmd /k "%vcvars% & msbuild %target%.vcxproj /p:Platform=%platform% /p:Configuration=%mode% /p:RuntimeLib=%mt% /p:PDB=%pdb% /p:ConfigurationType=%ct% /p:DebugPrint=%dp% & exit"
   exit /B 0

:usage
    @echo Usage: %prog_name% [/t all^|FsServer^|FsClient] [/b 32^|64] [/m Debug^|Release] [/bt C:\Build\Tools\] [/mt=no^|Debug^|Release] [/dp] [/h]
    @echo Default: %prog_name% [/t all /b %bitness% /m %mode% /bt %buildTools%]
    exit /B 0

:help
    call :usage
    echo /t The target name to build (all^|FsServer^|FsClient). Default: all.
    echo /b The target bitness (32^|64). Default: 64.
    echo /m The mode (Debug^|Release) to build in. Default: Release.
    echo /dp Compile with verbose debug print output.
    echo /mt Statically include LIBCMT.lib. Increases file size but may be needed if a "VCRUNTIMExxx.dll not found Error" occurs on the target system. Default: no.
    echo /bt Custom path to Microsoft Visual Studio BuildTools
    exit /B 0
