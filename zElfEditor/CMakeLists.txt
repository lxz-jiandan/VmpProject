cmake_minimum_required(VERSION 3.10)
project(zElfEditor)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(SOURCES
    main.cpp
    zElf.cpp
    zElfHeader.cpp
    zProgramTableElement.cpp
    zElfProgramHeaderTable.cpp
    zSectionTableElement.cpp
    zElfSectionHeaderTable.cpp
    zElfUtils.cpp
    zElfValidator.cpp
    zElfReconstruction.cpp
    zElfInject.cpp
    zElfLoader.cpp
    zElfAddressRewriter.cpp
    zElfPcRelativePatcher.cpp
    zLog.cpp
)

add_executable(zElfEditor ${SOURCES})

set(CAPSTONE_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/capstone_sdk)

target_include_directories(zElfEditor
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CAPSTONE_ROOT}/include
)

target_link_libraries(zElfEditor
    PRIVATE
    ${CAPSTONE_ROOT}/lib/libcapstone.a
)
