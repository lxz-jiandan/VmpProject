Capstone 精简集成：仅头文件 + 静态库（仅 AArch64）
- include/  头文件（供 #include <capstone/capstone.h>）
- lib/libcapstone.a  MinGW/GCC 静态库，仅启用 AArch64 架构（约 7MB）

构建说明（仓库内 capstone 源码）：
- 生成器：Ninja
- CMake：D:\Clion2022\bin\cmake\win\bin\cmake.exe
- Ninja：D:/Clion2022/bin/ninja/win/ninja.exe
- 关键选项：
  -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF
  -DCAPSTONE_AARCH64_SUPPORT=ON
  -DCAPSTONE_BUILD_SHARED_LIBS=OFF
  -DCAPSTONE_BUILD_STATIC_LIBS=ON
