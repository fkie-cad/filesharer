@echo off
setlocal

set my_name=%~n0
set my_dir="%~dp0"

set /a app=0
set /a cln=0

set ct=Application
set /a bitness=64
set platform=x64
set mode=Release
set /a rtl=0

set /a dp=0
set /a ep=1

set /a verbose=0

set buildTools="C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools"
set pts=v142


:: default
if [%1]==[] goto main

GOTO ParseParams

:ParseParams

    REM IF "%~1"=="" GOTO Main
    if [%1]==[/?] goto help
    if /i [%1]==[/h] goto help
    if /i [%1]==[/help] goto help
    
    IF /i "%~1"=="/app" (
        SET /a app=1
        goto reParseParams
    )
    IF /i "%~1"=="/cln" (
        SET /a cln=1
        goto reParseParams
    )

    IF /i "%~1"=="/b" (
        SET /a bitness=%~2
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
    IF /i "%~1"=="/pts" (
        SET pts=%~2
        SHIFT
        goto reParseParams
    )
    IF /i "%~1"=="/rtl" (
        SET /a rtl=1
        goto reParseParams
    )
    IF /i "%~1"=="/pdb" (
        SET /a pdb=1
        goto reParseParams
    )
    IF /i "%~1"=="/dp" (
        SET /a dp=1
        goto reParseParams
    )
    
    IF /i "%~1"=="/v" (
        SET verbose=1
        goto reParseParams
    ) ELSE (
        echo Unknown option : "%~1"
    )
    
    :reParseParams
        SHIFT
        if [%1]==[] goto main

GOTO :ParseParams


:main

    :: set platform
    set /a valid=0
    if %bitness% == 32 (
        set platform=x86
        set /a valid=1
    ) else (
        if %bitness% == 64 (
            set platform=x64
            set /a valid=1
        )
    )
    if %valid% == 0 (
        goto help
    )


    :: test valid targets
    set /a "valid=%app%+%cln%"
    if %valid% == 0 (
        set /a app=1
    )

    
    :: set runtime lib
    set rtlib=No
    set /a valid=0
    if /i [%mode%] == [debug] (
        if %rtl% == 1 (
            set rtlib=Debug
        )
        set /a pdb=1
        set /a valid=1
    ) else (
        if /i [%mode%] == [release] (
            if %rtl% == 1 (
                set rtlib=Release
            )
            set /a valid=1
        )
    )
    if %valid% == 0 (
        goto help
    )
    
    if %verbose% == 1 (
        echo target=%target%
        echo ConfigurationType=%ct%
        echo bitness=%bitness%
        echo platform=%platform%
        echo mode=%mode%
        echo build_dir=%build_dir%
        echo debug print=%dp%
        echo buildTools=%buildTools%
        echo pts=%pts%
    )
    

    :: set vcvars if neccessary
    :: pseudo nop command to prevent if else bug in :build
    set vcvars=call
    if [%VisualStudioVersion%] EQU [] (
        if not exist %buildTools% (
            echo [e] No build tools found in %buildTools%!
            echo     Please set the correct path in this script or with the /bt option.
            exit /b -1
        )
        set vcvars="%buildTools:~1,-1%\VC\Auxiliary\Build\vcvars%bitness%.bat"
    )
    

    :: build targets
    if %cln% == 1 (
        rmdir /s /q build
    )
    if %app% == 1 (
        call :build FShare.vcxproj Application
    ) 
    
    endlocal
    exit /B 0


:build
    setlocal
        set proj=%1
        set ct=%2
    
        cmd /k "%vcvars% & msbuild %proj% /p:Platform=%platform% /p:PlatformToolset=%pts% /p:Configuration=%mode% /p:RuntimeLib=%rtlib% /p:PDB=%pdb% /p:ConfigurationType=%ct% /p:DebugPrint=%dp% /p:ErrorPrint=%ep% & exit"

    endlocal
    exit /B 0


:usage
    echo Usage: %my_name% [/app] [/b ^<bitness^>] [/m ^<mode^>] [/rtl] [/pdb] [/pts ^<toolset^>] [/bt ^<path^>] [/v] [/h]
    echo Default: %my_name% [/t app /b %bitness% /m %mode% /bt %buildTools% /pts %pts%]
    exit /B 0

:help
    call :usage
    echo.
    echo Targets:
    echo /app Build FShare.exe application.
    echo /cln Clean up build dir.
    echo.
    echo Options:
    echo /b Target bitness: 32^|64. Default: 64.
    echo /m Build mode: Debug^|Release. Default: Release.
    echo /rtl Statically include runtime libs. May be needed if a "VCRUNTIMExxx.dll not found Error" occurs on the target system.
    echo /pdb Include pdb symbols into release build. Default in debug mode. 
    echo /bt Custom path to Microsoft Visual Studio BuildTools.
    echo /pts MsBuild platform toolset. Defaults to "v142".
    echo.
    echo /v more verbose output
    echo /h print this
    
    endlocal
    exit /B 0
