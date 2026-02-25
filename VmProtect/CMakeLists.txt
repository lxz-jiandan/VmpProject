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

set(VMP_APP_DIR "${CMAKE_CURRENT_SOURCE_DIR}/app")
set(VMP_FOUNDATION_DIR "${CMAKE_CURRENT_SOURCE_DIR}/modules/foundation")
set(VMP_FOUNDATION_SRC_DIR "${VMP_FOUNDATION_DIR}/core")
set(VMP_PIPELINE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/modules/pipeline")
set(VMP_PIPELINE_SRC_DIR "${VMP_PIPELINE_DIR}/core")
set(VMP_BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/modules/base")
set(VMP_BASE_SRC_DIR "${VMP_BASE_DIR}/core")
set(VMP_ELFKIT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/modules/elfkit")
set(VMP_ELFKIT_CORE_DIR "${VMP_ELFKIT_DIR}/core")
set(VMP_ELFKIT_SRC_DIR "${VMP_ELFKIT_DIR}/api")
set(VMP_ELFKIT_PATCHBAY_MODEL_DIR "${VMP_ELFKIT_DIR}/patchbayModel")
set(VMP_PATCHBAY_DIR "${CMAKE_CURRENT_SOURCE_DIR}/modules/patchbay")

set(VM_PROTECT_BASE_SOURCES
    ${VMP_BASE_SRC_DIR}/zIo.cpp
    ${VMP_BASE_SRC_DIR}/zChecksum.cpp
    ${VMP_BASE_SRC_DIR}/zCodec.cpp
    ${VMP_BASE_SRC_DIR}/zBitCodec.cpp
    ${VMP_BASE_SRC_DIR}/zBytes.cpp
    ${VMP_BASE_SRC_DIR}/zHash.cpp
)

set(VM_PROTECT_FOUNDATION_SOURCES
    ${VMP_FOUNDATION_SRC_DIR}/zLog.cpp
    ${VMP_FOUNDATION_SRC_DIR}/zIoUtils.cpp
)

set(VM_PROTECT_FORMAT_SOURCES
    ${VMP_ELFKIT_CORE_DIR}/zElf.cpp
    ${VMP_ELFKIT_CORE_DIR}/zElfLayout.cpp
    ${VMP_ELFKIT_CORE_DIR}/zElfSymbols.cpp
    ${VMP_ELFKIT_CORE_DIR}/zInst.cpp
    ${VMP_ELFKIT_CORE_DIR}/zSoBinBundle.cpp
    ${VMP_ELFKIT_CORE_DIR}/zFunctionData.cpp
    ${VMP_ELFKIT_CORE_DIR}/zFunction.cpp
    ${VMP_ELFKIT_CORE_DIR}/zFunctionAsm.cpp
    ${VMP_ELFKIT_CORE_DIR}/zFunctionDump.cpp
    ${VMP_ELFKIT_CORE_DIR}/zFunctionFacade.cpp
)

set(VM_PROTECT_PIPELINE_SOURCES
    ${VMP_PIPELINE_SRC_DIR}/zPipelineTypes.cpp
    ${VMP_PIPELINE_SRC_DIR}/zPipelineCli.cpp
    ${VMP_PIPELINE_SRC_DIR}/zPipelinePatch.cpp
    ${VMP_PIPELINE_SRC_DIR}/zPipelineCoverage.cpp
    ${VMP_PIPELINE_SRC_DIR}/zPipelineExport.cpp
)

set(VM_PROTECT_INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${VMP_BASE_SRC_DIR}
    ${VMP_FOUNDATION_SRC_DIR}
    ${VMP_ELFKIT_CORE_DIR}
    ${VMP_ELFKIT_SRC_DIR}
    ${VMP_ELFKIT_PATCHBAY_MODEL_DIR}
    ${VMP_PATCHBAY_DIR}/app
    ${VMP_PATCHBAY_DIR}/domain
    ${VMP_PATCHBAY_DIR}/format
    ${VMP_PATCHBAY_DIR}/foundation
    ${VMP_PIPELINE_SRC_DIR}
)

add_library(vmprotect_base STATIC ${VM_PROTECT_BASE_SOURCES})
target_include_directories(vmprotect_base PUBLIC
    ${VM_PROTECT_INCLUDE_DIRS}
)

add_library(vmprotect_foundation STATIC ${VM_PROTECT_FOUNDATION_SOURCES})
target_include_directories(vmprotect_foundation PUBLIC
    ${VM_PROTECT_INCLUDE_DIRS}
)
target_link_libraries(vmprotect_foundation PUBLIC
    vmprotect_base
)

add_library(vmprotect_format STATIC ${VM_PROTECT_FORMAT_SOURCES})
target_include_directories(vmprotect_format PUBLIC
    ${VM_PROTECT_INCLUDE_DIRS}
)
target_link_libraries(vmprotect_format PUBLIC
    capstone_static
    vmprotect_foundation
)

add_library(vmprotect_elfkit STATIC
    ${VMP_ELFKIT_DIR}/api/zElfKit.cpp
)
target_include_directories(vmprotect_elfkit PUBLIC
    ${VM_PROTECT_INCLUDE_DIRS}
)
target_link_libraries(vmprotect_elfkit PUBLIC
    vmprotect_format
)

set(PATCHBAY_TOOL_DIR "${VMP_PATCHBAY_DIR}")
set(PATCHBAY_FOUNDATION_SOURCES
    ${PATCHBAY_TOOL_DIR}/foundation/zPatchbayIo.cpp
    ${PATCHBAY_TOOL_DIR}/foundation/zPatchbayCrc.cpp
)

set(PATCHBAY_FORMAT_SOURCES
    ${VMP_ELFKIT_DIR}/patchbayModel/zPatchElf.cpp
    ${VMP_ELFKIT_DIR}/patchbayModel/zPatchElfLayout.cpp
    ${VMP_ELFKIT_DIR}/patchbayModel/zPatchElfModel.cpp
    ${VMP_ELFKIT_DIR}/patchbayModel/zPatchElfHeader.cpp
    ${VMP_ELFKIT_DIR}/patchbayModel/zProgramEntry.cpp
    ${VMP_ELFKIT_DIR}/patchbayModel/zProgramTable.cpp
    ${VMP_ELFKIT_DIR}/patchbayModel/zSectionEntry.cpp
    ${VMP_ELFKIT_DIR}/patchbayModel/zSectionTable.cpp
    ${VMP_ELFKIT_DIR}/patchbayModel/zPatchElfUtils.cpp
    ${VMP_ELFKIT_DIR}/patchbayModel/zPatchElfValidator.cpp
    ${VMP_ELFKIT_DIR}/patchbayModel/zPatchElfValidatorBase.cpp
    ${VMP_ELFKIT_DIR}/patchbayModel/zPatchElfValidatorSegment.cpp
    ${VMP_ELFKIT_DIR}/patchbayModel/zPatchElfValidatorSymbol.cpp
    ${VMP_ELFKIT_DIR}/patchbayModel/zPatchElfValidatorDynamic.cpp
    ${VMP_ELFKIT_DIR}/patchbayModel/zPatchElfLoader.cpp
    ${PATCHBAY_TOOL_DIR}/format/zPatchbayHash.cpp
    ${PATCHBAY_TOOL_DIR}/format/zPatchbayLayout.cpp
)

set(PATCHBAY_DOMAIN_SOURCES
    ${PATCHBAY_TOOL_DIR}/domain/zPatchbayAliasTables.cpp
    ${VMP_ELFKIT_DIR}/api/zPatchbayApi.cpp
    ${PATCHBAY_TOOL_DIR}/domain/zPatchbayRules.cpp
    ${PATCHBAY_TOOL_DIR}/domain/zPatchbayPatchApply.cpp
    ${PATCHBAY_TOOL_DIR}/domain/zPatchbayExport.cpp
)

set(PATCHBAY_APP_SOURCES
    ${PATCHBAY_TOOL_DIR}/app/zMain.cpp
)

add_library(patchbay_foundation_obj OBJECT ${PATCHBAY_FOUNDATION_SOURCES})
add_library(patchbay_format_obj OBJECT ${PATCHBAY_FORMAT_SOURCES})
add_library(patchbay_domain_obj OBJECT ${PATCHBAY_DOMAIN_SOURCES})
add_library(patchbay_app_obj OBJECT ${PATCHBAY_APP_SOURCES})

foreach(patchbay_obj_target
        patchbay_foundation_obj
        patchbay_format_obj
        patchbay_domain_obj
        patchbay_app_obj)
    target_include_directories(${patchbay_obj_target} PRIVATE
        ${VMP_BASE_SRC_DIR}
        ${VMP_FOUNDATION_SRC_DIR}
        ${VMP_ELFKIT_CORE_DIR}
        ${VMP_ELFKIT_SRC_DIR}
        ${VMP_ELFKIT_PATCHBAY_MODEL_DIR}
        ${VMP_PATCHBAY_DIR}/app
        ${VMP_PATCHBAY_DIR}/domain
        ${VMP_PATCHBAY_DIR}/format
        ${VMP_PATCHBAY_DIR}/foundation
    )
    set_target_properties(${patchbay_obj_target} PROPERTIES
        POSITION_INDEPENDENT_CODE ON
    )
endforeach()

add_library(vmp_patchbay STATIC
    $<TARGET_OBJECTS:patchbay_foundation_obj>
    $<TARGET_OBJECTS:patchbay_format_obj>
    $<TARGET_OBJECTS:patchbay_domain_obj>
    $<TARGET_OBJECTS:patchbay_app_obj>
)
target_link_libraries(vmp_patchbay PUBLIC
    vmprotect_base
    vmprotect_foundation
)

add_library(vmprotect_pipeline STATIC ${VM_PROTECT_PIPELINE_SOURCES})
target_include_directories(vmprotect_pipeline PUBLIC
    ${VM_PROTECT_INCLUDE_DIRS}
)
target_link_libraries(vmprotect_pipeline PUBLIC
    vmprotect_foundation
    vmprotect_format
    vmprotect_elfkit
    vmp_patchbay
)

add_executable(VmProtect
    ${VMP_APP_DIR}/zMain.cpp
)
target_include_directories(VmProtect PRIVATE
    ${VM_PROTECT_INCLUDE_DIRS}
)
target_link_libraries(VmProtect PRIVATE
    vmprotect_pipeline
)


