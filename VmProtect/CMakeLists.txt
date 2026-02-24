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
    zSoBinBundle.cpp
    zFunctionData.cpp
    zFunction.cpp
)
set(PATCHBAY_TOOL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/patchbay_tool")
set(PATCHBAY_SOURCES
    ${PATCHBAY_TOOL_DIR}/main.cpp
    ${PATCHBAY_TOOL_DIR}/zElf.cpp
    ${PATCHBAY_TOOL_DIR}/zElfHeader.cpp
    ${PATCHBAY_TOOL_DIR}/zProgramTableElement.cpp
    ${PATCHBAY_TOOL_DIR}/zElfProgramHeaderTable.cpp
    ${PATCHBAY_TOOL_DIR}/zSectionTableElement.cpp
    ${PATCHBAY_TOOL_DIR}/zElfSectionHeaderTable.cpp
    ${PATCHBAY_TOOL_DIR}/zElfUtils.cpp
    ${PATCHBAY_TOOL_DIR}/zElfValidator.cpp
    ${PATCHBAY_TOOL_DIR}/zElfLoader.cpp
)

# Compile patchbay implementation into VmProtect and rename its zElf class
# to avoid symbol collision with VmProtect's existing zElf implementation.
set_source_files_properties(${PATCHBAY_SOURCES} PROPERTIES
    COMPILE_DEFINITIONS "zElf=PatchbayElf"
)
target_sources(VmProtect PRIVATE ${PATCHBAY_SOURCES})

target_include_directories(VmProtect PRIVATE
    ${PATCHBAY_TOOL_DIR}
)
target_link_libraries(VmProtect PRIVATE capstone_static)
