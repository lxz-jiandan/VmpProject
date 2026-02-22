# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html.
# For more examples on how to use CMake, see https://github.com/android/ndk-samples.

# Sets the minimum CMake version required for this project.
cmake_minimum_required(VERSION 3.22.1)

project("demo")

add_library(demo_jni SHARED
        vmp-bridge.cpp)

target_link_libraries(demo_jni
        android
        log
        dl)
