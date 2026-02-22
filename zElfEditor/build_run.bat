@echo off
setlocal

set "ROOT_DIR=%~dp0"
if "%ROOT_DIR:~-1%"=="\" set "ROOT_DIR=%ROOT_DIR:~0,-1%"
pushd "%ROOT_DIR%"

set "CMAKE_EXE=D:\Clion2022\bin\cmake\win\bin\cmake.exe"
set "NINJA_EXE=D:/Clion2022/bin/ninja/win/ninja.exe"
set "BUILD_DIR=%ROOT_DIR%\cmake-build-debug"
set "TARGET=zElfEditor"

set "RUN_ARGS=%*"
if "%~1"=="" set "RUN_ARGS=fun_for_add"

set "PATH=D:\Clion2022\bin\mingw\bin;%PATH%"

if exist "%BUILD_DIR%" rd /s /q "%BUILD_DIR%"
if errorlevel 1 (
    popd
    exit /b 1
)

"%CMAKE_EXE%" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_MAKE_PROGRAM=%NINJA_EXE% -G Ninja -S "%ROOT_DIR%" -B "%BUILD_DIR%"
if errorlevel 1 (
    popd
    exit /b 1
)

"%CMAKE_EXE%" --build "%BUILD_DIR%" --target %TARGET% -j 12
if errorlevel 1 (
    popd
    exit /b 1
)

pushd "%BUILD_DIR%"
".\%TARGET%.exe" %RUN_ARGS%
set "RET=%ERRORLEVEL%"
popd

popd
exit /b %RET%
