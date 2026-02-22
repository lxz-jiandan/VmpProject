cmake_minimum_required(VERSION 3.18)
project(demo1)

set(CMAKE_CXX_STANDARD 14)

# 添加父目录到头文件搜索路径，以便包含 elf.h
include_directories(${CMAKE_SOURCE_DIR}/..)

# 添加编译选项防止函数内联（可选，代码中已有 noinline 属性）
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-fno-inline-functions-called-once)
endif()

add_executable(demo1 main.cpp)
