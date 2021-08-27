@echo off

set prog_name=%~n0
set user_dir="%~dp0"
set /a verbose=1

set /a server=0
set /a client=0
set /a test=0
set /a debug=0
set /a release=0
set /a debug_print=0
set /a rtl=0
set /a bitness=64
set platform=x64
set configuration=Debug

set server_proj=FsServer.vcxproj
set client_proj=FsClient.vcxproj
set test_proj=tests\test.vcxproj


set msb=msbuild

WHERE %msbuild% >nul 2>nul
IF %ERRORLEVEL% NEQ 0 set msb="C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\MSBuild.exe"



GOTO :ParseParams

:ParseParams

    REM IF "%~1"=="" GOTO Main
    if [%1]==[/?] goto help
    if [%1]==[/h] goto help
    if [%1]==[/help] goto help

    IF "%~1"=="/s" (
        SET /a server=1
        goto reParseParams
    )
    IF "%~1"=="/c" (
        SET /a client=1
        goto reParseParams
    )
    IF "%~1"=="/t" (
        SET /a test=1
        goto reParseParams
    )
    IF "%~1"=="/d" (
        SET /a debug=1
        goto reParseParams
    )
    IF "%~1"=="/r" (
        SET /a release=1
        goto reParseParams
    )
    IF "%~1"=="/dp" (
        SET /a debug_print=1
        goto reParseParams
    )
    IF "%~1"=="/b" (
        SET bitness=%~2
        SHIFT
        goto reParseParams
    )
    IF "%~1"=="/rtl" (
        SET /a rtl=1
        goto reParseParams
    )
    
    :reParseParams
    SHIFT
    if [%1]==[] goto main

GOTO :ParseParams


:main

set /a "s=%debug%+%release%"
if [%s%]==[0] (
    set /a debug=0
    set /a release=1
)
set /a "s=%server%+%client%+%test%"
if [%s%]==[0] (
    set /a server=1
    set /a client=1
)

if [%bitness%]==[64] (
    set platform=x64
)
if [%bitness%]==[32] (
    set platform=x86
)
if not [%bitness%]==[32] (
    if not [%bitness%]==[64] (
        echo ERROR: Bitness /b has to be 32 or 64!
        EXIT /B 1
    )
)

if [%server%]==[1] call :build %server_proj%
if [%client%]==[1] call :build %client_proj%
if [%test%]==[1] call :build %test_proj%

exit /B 0


:build
    SETLOCAL
        set proj=%~1
        if [%debug%]==[1] call :buildEx %proj%,%platform%,Debug,%debug_print%,%rtl%
        if [%release%]==[1] call :buildEx %proj%,%platform%,Release,%debug_print%,%rtl%
    ENDLOCAL
    
    EXIT /B %ERRORLEVEL%
    
:buildEx
    SETLOCAL
        set proj=%~1
        set platform=%~2
        set conf=%~3
        set dp=%~4
        set rtl=%~5
        
        if %rtl% == 1 (
            set rtl=%conf%
        ) else (
            set rtl=None
        )
        
        echo build
        echo  - Project=%proj%
        echo  - Platform=%platform%
        echo  - Configuration=%conf%
        echo  - DebugPrint=%dp%
        echo  - RuntimeLib=%rtl%
        echo.
        
        msbuild %proj% /p:Platform=%platform% /p:Configuration=%conf% /p:DebugPrint=%dp% /p:RuntimeLib=%rtl%
        echo.
        echo ----------------------------------------------------
        echo.
        echo.
    ENDLOCAL
    
    EXIT /B %ERRORLEVEL%


:usage
    echo Usage: %prog_name% [/s] [/c] [/d] [/r] [/dp] [/rtl] [/b 32^|64]
    echo Default: %prog_name% /s /c /d /r /b 64
    exit /B 0
    
:help
    call :usage
    echo.
    echo Options:
    echo /s: Build server.
    echo /c: Build client.
    echo /d: Build in debug mode.
    echo /r: Build in release mode.
    echo /dp: Debug print output.
    echo /rtl: Build with runtime libs.
    echo /b: Bitness of exe. 32^|64. Default: 64.
    echo /h: Print this.
    echo.
    echo Info:
    echo If no options (of a pair (/s,/c)) are passed, all variations are build (client and server).
    exit /B 0
    