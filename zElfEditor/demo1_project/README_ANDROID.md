# Android NDK 交叉编译说明

## 使用 Android NDK 交叉编译 demo1

### 方法 1: 使用批处理脚本（Windows）

```bash
build_android.bat
```

### 方法 2: 手动配置 CMake

```bash
mkdir build-android
cd build-android

cmake ^
    -DCMAKE_TOOLCHAIN_FILE=C:\Users\lxz\AppData\Local\Android\Sdk\ndk\27.2.12479018\build\cmake\android.toolchain.cmake ^
    -DANDROID_ABI=arm64-v8a ^
    -DANDROID_PLATFORM=android-21 ^
    -DANDROID_NDK=C:\Users\lxz\AppData\Local\Android\Sdk\ndk\27.2.12479018 ^
    -DCMAKE_BUILD_TYPE=Release ^
    ..

cmake --build . --config Release
```

### 支持的架构

- `arm64-v8a` - ARM 64位（默认）
- `armeabi-v7a` - ARM 32位
- `x86` - x86 32位
- `x86_64` - x86 64位

修改 `build_android.bat` 中的 `ARCH` 变量来切换架构。

### 输出

编译完成后，可执行文件位于：
- `build-android/Release/demo1.exe` (Windows)
- `build-android/Release/demo1` (Linux/Mac)

### 注意事项

1. 确保已安装 CMake 3.23 或更高版本
2. 确保 Android NDK 路径正确
3. Android NDK 自带 elf.h，无需额外配置

