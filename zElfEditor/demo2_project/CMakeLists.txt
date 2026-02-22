cmake_minimum_required(VERSION 3.18)
project(demo2)

set(CMAKE_CXX_STANDARD 14)

# 添加父目录到头文件搜索路径，以便包含 elf.h
include_directories(${CMAKE_SOURCE_DIR}/..)

add_executable(demo2 main.cpp)
