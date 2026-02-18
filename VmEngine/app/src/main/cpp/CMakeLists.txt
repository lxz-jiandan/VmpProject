cmake_minimum_required(VERSION 3.22.1)

project("vmengine")

add_library(${CMAKE_PROJECT_NAME} SHARED
        zNativeLib.cpp
        zLinker.cpp
        zTypeManager.cpp
        zVmEngine.cpp
        zVmOpcodes.cpp
        zByteCodeReader.cpp
        zAssetManager.cpp
        zFunction.cpp
        zLog.cpp)

target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(${CMAKE_PROJECT_NAME}
        android
        dl
        log)
