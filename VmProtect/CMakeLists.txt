cmake_minimum_required(VERSION 3.18)
project(VmProtect)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CAPSTONE_SDK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/capstone_sdk")
set(CAPSTONE_INCLUDE_DIR "${CAPSTONE_SDK_DIR}/include")
set(CAPSTONE_LIB_PATH "${CAPSTONE_SDK_DIR}/lib/capstone.lib")

add_library(capstone_static STATIC IMPORTED GLOBAL)
set_target_properties(capstone_static PROPERTIES
    IMPORTED_LOCATION "${CAPSTONE_LIB_PATH}"
    INTERFACE_INCLUDE_DIRECTORIES "${CAPSTONE_INCLUDE_DIR}"
)

add_executable(VmProtect
    main.cpp
    zElf.cpp
    zLog.cpp
    zInst.cpp
    zFunctionData.cpp
    zFunction.cpp
)
target_link_libraries(VmProtect PRIVATE capstone_static)
