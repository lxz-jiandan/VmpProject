@echo off
setlocal

set "ROOT_DIR=%~dp0"
if "%ROOT_DIR:~-1%"=="\" set "ROOT_DIR=%ROOT_DIR:~0,-1%"
pushd "%ROOT_DIR%"

set "CMAKE_EXE=D:\Clion2022\bin\cmake\win\bin\cmake.exe"
set "NINJA_EXE=D:/Clion2022/bin/ninja/win/ninja.exe"
set "BUILD_DIR=%ROOT_DIR%\cmake-build-debug"
set "TARGET=VmProtect"
set "ASSET_DIR=%ROOT_DIR%\..\VmEngine\app\src\main\assets"

set "RUN_ARG=%~1"
if "%RUN_ARG%"=="" set "RUN_ARG=fun_for_add"

set "PATH=D:\Clion2022\bin\mingw\bin;%PATH%"

if not exist "%BUILD_DIR%" (
    mkdir "%BUILD_DIR%"
    if errorlevel 1 (
        popd
        exit /b 1
    )
)

if not exist "%BUILD_DIR%\build.ninja" (
    "%CMAKE_EXE%" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_MAKE_PROGRAM=%NINJA_EXE% -G Ninja -S "%ROOT_DIR%" -B "%BUILD_DIR%"
    if errorlevel 1 (
        popd
        exit /b 1
    )
) else (
    echo [INFO] reuse existing build files: %BUILD_DIR%
)

"%CMAKE_EXE%" --build "%BUILD_DIR%" --target %TARGET% -j 12
if errorlevel 1 (
    popd
    exit /b 1
)

pushd "%BUILD_DIR%"
".\%TARGET%.exe" "%RUN_ARG%"
set "RET=%ERRORLEVEL%"
popd

if not "%RET%"=="0" (
    popd
    exit /b %RET%
)

if not exist "%ASSET_DIR%" (
    echo [WARN] asset dir not found: %ASSET_DIR%
) else (
    if not exist "%BUILD_DIR%\fun_for_add.txt" (
        echo [ERROR] missing exported file: %BUILD_DIR%\fun_for_add.txt
        popd
        exit /b 1
    )
    if not exist "%BUILD_DIR%\fun_for_add.bin" (
        echo [ERROR] missing exported file: %BUILD_DIR%\fun_for_add.bin
        popd
        exit /b 1
    )

    copy /Y "%BUILD_DIR%\fun_for_add.txt" "%ASSET_DIR%\fun_for_add.txt" >nul
    if errorlevel 1 (
        echo [ERROR] failed to copy fun_for_add.txt to assets
        popd
        exit /b 1
    )

    copy /Y "%BUILD_DIR%\fun_for_add.bin" "%ASSET_DIR%\fun_for_add.bin" >nul
    if errorlevel 1 (
        echo [ERROR] failed to copy fun_for_add.bin to assets
        popd
        exit /b 1
    )

    echo [OK] exported fun_for_add.txt and fun_for_add.bin to %ASSET_DIR%
)

popd
exit /b %RET%
