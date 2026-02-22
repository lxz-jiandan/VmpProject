@echo off
REM Android NDK 交叉编译脚本

set NDK_PATH=C:\Users\lxz\AppData\Local\Android\Sdk\ndk\27.2.12479018
set BUILD_DIR=build-android
set TARGET_NAME=demo1
set ARCH=arm64-v8a
set API_LEVEL=21

REM 检查 NDK 路径是否存在
if not exist "%NDK_PATH%" (
    echo Error: NDK path not found: %NDK_PATH%
    exit /b 1
)

REM 清理旧的构建目录
if exist %BUILD_DIR% rmdir /s /q %BUILD_DIR%

REM 创建构建目录
mkdir %BUILD_DIR%
cd %BUILD_DIR%

REM 尝试使用 Ninja 生成器（如果可用），否则使用默认生成器
where ninja >nul 2>&1
if %ERRORLEVEL% == 0 (
    set GENERATOR=-G "Ninja"
    echo Using Ninja generator
) else (
    set GENERATOR=
    echo Using default generator
)

REM 配置 CMake，使用 Android NDK 工具链
cmake %GENERATOR% ^
    -DCMAKE_TOOLCHAIN_FILE=%NDK_PATH%\build\cmake\android.toolchain.cmake ^
    -DANDROID_ABI=%ARCH% ^
    -DANDROID_PLATFORM=android-%API_LEVEL% ^
    -DANDROID_NDK=%NDK_PATH% ^
    -DCMAKE_BUILD_TYPE=Release ^
    ..

if %ERRORLEVEL% neq 0 (
    echo.
    echo CMake configuration failed!
    exit /b 1
)

REM 编译
cmake --build . --config Release

if %ERRORLEVEL% neq 0 (
    echo.
    echo Build failed!
    exit /b 1
)

echo.
echo Build completed successfully!
if exist Release\%TARGET_NAME%.exe (
    echo Output: %CD%\Release\%TARGET_NAME%.exe
) else if exist Release\%TARGET_NAME% (
    echo Output: %CD%\Release\%TARGET_NAME%
) else if exist %TARGET_NAME%.exe (
    echo Output: %CD%\%TARGET_NAME%.exe
) else if exist %TARGET_NAME% (
    echo Output: %CD%\%TARGET_NAME%
) else (
    echo Warning: Could not find output executable for %TARGET_NAME%
)

