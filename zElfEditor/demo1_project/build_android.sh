#!/bin/bash
# Android NDK 交叉编译脚本

NDK_PATH="C:/Users/lxz/AppData/Local/Android/Sdk/ndk/27.2.12479018"
BUILD_DIR="build-android"
ARCH="arm64-v8a"
API_LEVEL=21

# 清理旧的构建目录
if [ -d "$BUILD_DIR" ]; then
    rm -rf "$BUILD_DIR"
fi

# 创建构建目录
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# 配置 CMake，使用 Android NDK 工具链
cmake \
    -DCMAKE_TOOLCHAIN_FILE="$NDK_PATH/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI="$ARCH" \
    -DANDROID_PLATFORM=android-$API_LEVEL \
    -DANDROID_NDK="$NDK_PATH" \
    -DCMAKE_BUILD_TYPE=Release \
    ..

# 编译
cmake --build . --config Release

echo ""
echo "Build completed! Output: $BUILD_DIR/Release/demo1"

