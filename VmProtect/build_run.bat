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

set "RUN_ARGS=%*"
if "%RUN_ARGS%"=="" set "RUN_ARGS=fun_for fun_add fun_for_add fun_if_sub fun_countdown_muladd fun_loop_call_mix fun_call_chain fun_branch_call fun_cpp_make_string fun_cpp_string_len fun_cpp_vector_sum fun_cpp_virtual_mix"

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
".\%TARGET%.exe" %RUN_ARGS%
set "RET=%ERRORLEVEL%"
popd

if not "%RET%"=="0" (
    popd
    exit /b %RET%
)

if not exist "%ASSET_DIR%" (
    echo [WARN] asset dir not found: %ASSET_DIR%
) else (
    if not exist "%BUILD_DIR%\libdemo_expand.so" (
        echo [ERROR] missing exported file: %BUILD_DIR%\libdemo_expand.so
        popd
        exit /b 1
    )

    if not exist "%BUILD_DIR%\branch_addr_list.txt" (
        echo [ERROR] missing exported file: %BUILD_DIR%\branch_addr_list.txt
        popd
        exit /b 1
    )

    copy /Y "%BUILD_DIR%\libdemo_expand.so" "%ASSET_DIR%\libdemo_expand.so" >nul
    if errorlevel 1 (
        echo [ERROR] failed to copy libdemo_expand.so to assets
        popd
        exit /b 1
    )

    copy /Y "%BUILD_DIR%\branch_addr_list.txt" "%ASSET_DIR%\branch_addr_list.txt" >nul
    if errorlevel 1 (
        echo [ERROR] failed to copy branch_addr_list.txt to assets
        popd
        exit /b 1
    )

    for %%F in (%RUN_ARGS%) do (
        if not exist "%BUILD_DIR%\%%F.txt" (
            echo [ERROR] missing exported file: %BUILD_DIR%\%%F.txt
            popd
            exit /b 1
        )
        if not exist "%BUILD_DIR%\%%F.bin" (
            echo [ERROR] missing exported file: %BUILD_DIR%\%%F.bin
            popd
            exit /b 1
        )

        copy /Y "%BUILD_DIR%\%%F.txt" "%ASSET_DIR%\%%F.txt" >nul
        if errorlevel 1 (
            echo [ERROR] failed to copy %%F.txt to assets
            popd
            exit /b 1
        )

        copy /Y "%BUILD_DIR%\%%F.bin" "%ASSET_DIR%\%%F.bin" >nul
        if errorlevel 1 (
            echo [ERROR] failed to copy %%F.bin to assets
            popd
            exit /b 1
        )
    )

    echo [OK] exported libdemo_expand.so + branch_addr_list.txt + function txt/bin to %ASSET_DIR%
)

popd
exit /b %RET%
