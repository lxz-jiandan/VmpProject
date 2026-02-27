# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html.
# For more examples on how to use CMake, see https://github.com/android/ndk-samples.

# Sets the minimum CMake version required for this project.
cmake_minimum_required(VERSION 3.22.1)

project("demo")

# demo 业务库：导出 fun_* 供加固与 bridge 调用。
add_library(demo SHARED
        native-lib.cpp
        native-lib-ref.cpp)
target_link_libraries(demo
        android
        log)

# 桥接库：JNI 入口库，链接期直接依赖 demo。
add_library(bridge SHARED
        zVmpBridge.cpp)

target_include_directories(bridge PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(bridge
        demo
        android
        dl
        log)
