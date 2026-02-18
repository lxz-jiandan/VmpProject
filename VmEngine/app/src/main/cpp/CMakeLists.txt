cmake_minimum_required(VERSION 3.22.1)

project("vmengine")

# VM 热路径追踪开关：默认关闭，避免解释器每条指令产生日志开销。
option(VM_TRACE "Enable verbose VM trace logs" OFF)

# vmengine 为 JNI 入口动态库：
# Java 层通过 System.loadLibrary("vmengine") 加载它，
# JNI_OnLoad 中会初始化 VM 执行链路。
add_library(${CMAKE_PROJECT_NAME} SHARED
        zNativeLib.cpp
        zLinker.cpp
        zTypeManager.cpp
        zVmEngine.cpp
        zVmOpcodes.cpp
        zFunctionData.cpp
        zAssetManager.cpp
        zFunction.cpp
        zLog.cpp)

# 当前目录头文件作为私有 include，供本模块内部源码互相引用。
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR})

# Android NDK 依赖：
# - android: AAssetManager 等 NDK Android API
# - dl: dlopen/dlsym（zLinker 兜底符号解析）
# - log: __android_log_print
target_link_libraries(${CMAKE_PROJECT_NAME}
        android
        dl
        log)

if (VM_TRACE)
    target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE VM_TRACE=1)
else ()
    target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE VM_TRACE=0)
endif ()

# Release 版本强制降级日志级别，避免 DEBUG 日志触发格式化和分配开销。
target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE
        $<$<CONFIG:Release>:CURRENT_LOG_LEVEL=LOG_LEVEL_INFO>)
