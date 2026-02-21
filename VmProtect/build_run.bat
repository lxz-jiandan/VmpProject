@echo off
setlocal EnableExtensions

set "ROOT_DIR=%~dp0"
if "%ROOT_DIR:~-1%"=="\" set "ROOT_DIR=%ROOT_DIR:~0,-1%"
pushd "%ROOT_DIR%"

set "BUILD_DIR=%ROOT_DIR%\cmake-build-debug"
set "TARGET=VmProtect"
set "ASSET_DIR=%ROOT_DIR%\..\VmEngine\app\src\main\assets"

set "RUN_ARGS=%*"
if "%RUN_ARGS%"=="" set "RUN_ARGS=fun_for fun_add fun_for_add fun_if_sub fun_countdown_muladd fun_loop_call_mix fun_call_chain fun_branch_call fun_cpp_make_string fun_cpp_string_len fun_cpp_vector_sum fun_cpp_virtual_mix fun_global_data_mix fun_static_local_table fun_global_struct_acc fun_class_static_member fun_multi_branch_path fun_switch_dispatch fun_bitmask_branch fun_global_table_rw fun_global_mutable_state"

call :pick_tool CMAKE_EXE "C:\Program Files\JetBrains\CLion 2022.2.5\bin\cmake\win\bin\cmake.exe" "D:\Clion2022\bin\cmake\win\bin\cmake.exe" cmake
if errorlevel 1 goto :fail
call :pick_tool NINJA_EXE "C:\Program Files\JetBrains\CLion 2022.2.5\bin\ninja\win\ninja.exe" "D:\Clion2022\bin\ninja\win\ninja.exe" ninja
if errorlevel 1 goto :fail

set "GCC_EXE="
set "GPP_EXE="
if exist "C:\Program Files\JetBrains\CLion 2022.2.5\bin\mingw\bin\gcc.exe" (
    set "GCC_EXE=C:\Program Files\JetBrains\CLion 2022.2.5\bin\mingw\bin\gcc.exe"
    set "GPP_EXE=C:\Program Files\JetBrains\CLion 2022.2.5\bin\mingw\bin\g++.exe"
) else if exist "D:\Clion2022\bin\mingw\bin\gcc.exe" (
    set "GCC_EXE=D:\Clion2022\bin\mingw\bin\gcc.exe"
    set "GPP_EXE=D:\Clion2022\bin\mingw\bin\g++.exe"
) else (
    for /f "delims=" %%I in ('where gcc 2^>nul') do (
        if not defined GCC_EXE set "GCC_EXE=%%I"
    )
    for /f "delims=" %%I in ('where g++ 2^>nul') do (
        if not defined GPP_EXE set "GPP_EXE=%%I"
    )
)

if defined GCC_EXE (
    for %%I in ("%GCC_EXE%") do set "MINGW_BIN=%%~dpI"
    set "PATH=%MINGW_BIN%;%PATH%"
)

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
if errorlevel 1 goto :fail

rem Clear stale CMake cache to avoid compiler path parse issues.
if exist "%BUILD_DIR%\CMakeCache.txt" del /F /Q "%BUILD_DIR%\CMakeCache.txt" >nul 2>nul
if exist "%BUILD_DIR%\CMakeFiles" rmdir /S /Q "%BUILD_DIR%\CMakeFiles" >nul 2>nul

set "ROOT_DIR_CMAKE=%ROOT_DIR:\=/%"
set "BUILD_DIR_CMAKE=%BUILD_DIR:\=/%"
set "NINJA_EXE_CMAKE=%NINJA_EXE:\=/%"
set "GCC_EXE_CMAKE=%GCC_EXE:\=/%"
set "GPP_EXE_CMAKE=%GPP_EXE:\=/%"

echo [INFO] cmake: %CMAKE_EXE%
echo [INFO] ninja: %NINJA_EXE%
if defined GCC_EXE echo [INFO] gcc: %GCC_EXE%
if defined GPP_EXE echo [INFO] g++: %GPP_EXE%

if defined GCC_EXE if defined GPP_EXE (
    call "%CMAKE_EXE%" -G Ninja -S "%ROOT_DIR_CMAKE%" -B "%BUILD_DIR_CMAKE%" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_MAKE_PROGRAM="%NINJA_EXE_CMAKE%" -DCMAKE_C_COMPILER="%GCC_EXE_CMAKE%" -DCMAKE_CXX_COMPILER="%GPP_EXE_CMAKE%"
) else (
    call "%CMAKE_EXE%" -G Ninja -S "%ROOT_DIR_CMAKE%" -B "%BUILD_DIR_CMAKE%" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_MAKE_PROGRAM="%NINJA_EXE_CMAKE%"
)
if errorlevel 1 goto :fail

call "%CMAKE_EXE%" --build "%BUILD_DIR%" --target %TARGET% -j 12
if errorlevel 1 goto :fail

pushd "%BUILD_DIR%"
call ".\%TARGET%.exe" %RUN_ARGS%
set "RET=%ERRORLEVEL%"
popd
if not "%RET%"=="0" goto :done

if not exist "%ASSET_DIR%" (
    echo [WARN] asset dir not found: %ASSET_DIR%
    goto :done
)

if not exist "%BUILD_DIR%\libdemo_expand.so" (
    echo [ERROR] missing exported file: %BUILD_DIR%\libdemo_expand.so
    set "RET=1"
    goto :done
)

if not exist "%BUILD_DIR%\branch_addr_list.txt" (
    echo [ERROR] missing exported file: %BUILD_DIR%\branch_addr_list.txt
    set "RET=1"
    goto :done
)

copy /Y "%BUILD_DIR%\libdemo_expand.so" "%ASSET_DIR%\libdemo_expand.so" >nul
if errorlevel 1 (
    echo [ERROR] failed to copy libdemo_expand.so to assets
    set "RET=1"
    goto :done
)

copy /Y "%BUILD_DIR%\branch_addr_list.txt" "%ASSET_DIR%\branch_addr_list.txt" >nul
if errorlevel 1 (
    echo [ERROR] failed to copy branch_addr_list.txt to assets
    set "RET=1"
    goto :done
)

for %%F in (%RUN_ARGS%) do (
    if not exist "%BUILD_DIR%\%%F.txt" (
        echo [ERROR] missing exported file: %BUILD_DIR%\%%F.txt
        set "RET=1"
        goto :done
    )
    if not exist "%BUILD_DIR%\%%F.bin" (
        echo [ERROR] missing exported file: %BUILD_DIR%\%%F.bin
        set "RET=1"
        goto :done
    )

    copy /Y "%BUILD_DIR%\%%F.txt" "%ASSET_DIR%\%%F.txt" >nul
    if errorlevel 1 (
        echo [ERROR] failed to copy %%F.txt to assets
        set "RET=1"
        goto :done
    )

    copy /Y "%BUILD_DIR%\%%F.bin" "%ASSET_DIR%\%%F.bin" >nul
    if errorlevel 1 (
        echo [ERROR] failed to copy %%F.bin to assets
        set "RET=1"
        goto :done
    )
)

echo [OK] exported libdemo_expand.so + branch_addr_list.txt + function txt/bin to %ASSET_DIR%
goto :done

:pick_tool
set "%~1="
if exist "%~2" set "%~1=%~2"
if not defined %~1 if exist "%~3" set "%~1=%~3"
if not defined %~1 (
    for /f "delims=" %%I in ('where %~4 2^>nul') do (
        if not defined %~1 set "%~1=%%I"
    )
)
if not defined %~1 (
    echo [ERROR] %~4 not found.
    exit /b 1
)
exit /b 0

:fail
set "RET=1"

:done
popd
exit /b %RET%
