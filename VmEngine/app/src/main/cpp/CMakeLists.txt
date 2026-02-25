cmake_minimum_required(VERSION 3.22.1)

project("vmengine" C CXX ASM)
set(VMPROJECT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../../..")

# VM 热路径追踪开关：默认关闭，避免解释器每条指令产生日志开销。
option(VM_TRACE "Enable verbose VM trace logs" OFF)
# route4 L1：构建 vmengine 后自动把 libdemo_expand.so 追加到 libvmengine.so 尾部。
option(VMENGINE_ROUTE4_EMBED_PAYLOAD "Embed libdemo_expand.so payload into libvmengine.so" ON)

# route4 L2.5：生成通用槽位桩（不绑定具体业务符号名）。
set(TAKEOVER_SLOT_COUNT 128)
set(TAKEOVER_GEN_SCRIPT "${VMPROJECT_ROOT}/tools/gen_takeover_stubs.py")
set(TAKEOVER_GEN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/generated")
set(TAKEOVER_STUB_ASM "${TAKEOVER_GEN_DIR}/zTakeoverStubs.generated.S")
set(TAKEOVER_STUB_HEADER "${TAKEOVER_GEN_DIR}/zTakeoverSymbols.generated.h")
find_program(PYTHON_FOR_BUILD NAMES python py)

if (PYTHON_FOR_BUILD AND EXISTS "${TAKEOVER_GEN_SCRIPT}")
    execute_process(
            COMMAND "${PYTHON_FOR_BUILD}" "${TAKEOVER_GEN_SCRIPT}"
            --slot-count "${TAKEOVER_SLOT_COUNT}"
            --source-label "slot-count=${TAKEOVER_SLOT_COUNT}"
            --out-asm "${TAKEOVER_STUB_ASM}"
            --out-header "${TAKEOVER_STUB_HEADER}"
            RESULT_VARIABLE TAKEOVER_GEN_RESULT
            OUTPUT_VARIABLE TAKEOVER_GEN_STDOUT
            ERROR_VARIABLE TAKEOVER_GEN_STDERR)
    if (NOT TAKEOVER_GEN_RESULT EQUAL 0)
        message(FATAL_ERROR "route4 takeover stub generation failed:\n${TAKEOVER_GEN_STDOUT}\n${TAKEOVER_GEN_STDERR}")
    endif ()
else ()
    if (NOT EXISTS "${TAKEOVER_STUB_ASM}" OR NOT EXISTS "${TAKEOVER_STUB_HEADER}")
        message(FATAL_ERROR "route4 takeover generated files are missing and generator is unavailable.")
    endif ()
    message(WARNING "Route4 takeover generator unavailable, using existing generated files.")
endif ()

# L0 基础层：日志、资产读取、动态符号解析。
set(VM_L0_FOUNDATION_SOURCES
        zLog.cpp
        zAssetManager.cpp
        zLinker.cpp
        zFileBytes.cpp)

# L1 格式与解析层：函数模型、bundle、ELF payload/patchbay 元信息。
set(VM_L1_FORMAT_SOURCES
        zFunction.cpp
        zFunctionData.cpp
        zSoBinBundle.cpp
        zEmbeddedPayload.cpp
        zElfTakeoverDynsym.cpp
        zPatchBay.cpp)

# L2 领域能力层：VM 执行、指令集、类型系统、导出接管。
set(VM_L2_DOMAIN_SOURCES
        zTypeManager.cpp
        zVmEngine.cpp
        zVmOpcodes.cpp
        zSymbolTakeover.cpp)

# L3 流程编排层：route4 初始化与 JNI 入口。
set(VM_L3_PIPELINE_SOURCES
        zPipelineConfig.cpp
        zVmInitCore.cpp
        zVmInitLifecycle.cpp
        ${TAKEOVER_STUB_ASM})

add_library(vm_l0_foundation OBJECT ${VM_L0_FOUNDATION_SOURCES})
add_library(vm_l1_format OBJECT ${VM_L1_FORMAT_SOURCES})
add_library(vm_l2_domain OBJECT ${VM_L2_DOMAIN_SOURCES})
add_library(vm_l3_pipeline OBJECT ${VM_L3_PIPELINE_SOURCES})

foreach (layer_target
        vm_l0_foundation
        vm_l1_format
        vm_l2_domain
        vm_l3_pipeline)
    target_include_directories(${layer_target} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_definitions(${layer_target} PRIVATE
            $<$<BOOL:${VM_TRACE}>:VM_TRACE=1>
            $<$<NOT:$<BOOL:${VM_TRACE}>>:VM_TRACE=0>
            $<$<CONFIG:Release>:CURRENT_LOG_LEVEL=LOG_LEVEL_INFO>)
    set_target_properties(${layer_target} PROPERTIES
            POSITION_INDEPENDENT_CODE ON)
endforeach ()

add_library(${CMAKE_PROJECT_NAME} SHARED
        $<TARGET_OBJECTS:vm_l0_foundation>
        $<TARGET_OBJECTS:vm_l1_format>
        $<TARGET_OBJECTS:vm_l2_domain>
        $<TARGET_OBJECTS:vm_l3_pipeline>)

# 对 vmengine 采用默认隐藏导出策略：
# 1) 业务内部 C/C++ 符号默认不进动态导出表；
# 2) 仅显式可见符号（如 JNIEXPORT）保留导出；
# 3) 静态库符号不向外再导出，避免把 libc++ 模板实例暴露到 dynsym。
set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES
        C_VISIBILITY_PRESET hidden
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN YES)
target_link_options(${CMAKE_PROJECT_NAME} PRIVATE
        "-Wl,--exclude-libs,ALL"
        "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/vmengine.exports.map")

# Android NDK 依赖：
# - android: AAssetManager 等 NDK Android API
# - dl: dlopen/dlsym（zLinker 兜底符号解析）
# - log: __android_log_print
target_link_libraries(${CMAKE_PROJECT_NAME}
        android
        dl
        log)

if (VMENGINE_ROUTE4_EMBED_PAYLOAD)
    set(EMBED_SCRIPT "${VMPROJECT_ROOT}/tools/embed_expand_into_vmengine.py")
    set(EMBED_PAYLOAD_SO "${CMAKE_CURRENT_SOURCE_DIR}/../assets/libdemo_expand.so")
    set(PYTHON_FOR_EMBED "${PYTHON_FOR_BUILD}")

    if (PYTHON_FOR_EMBED AND EXISTS "${EMBED_SCRIPT}")
        add_custom_command(TARGET ${CMAKE_PROJECT_NAME} POST_BUILD
                COMMAND "${PYTHON_FOR_EMBED}" "${EMBED_SCRIPT}"
                --host-so "$<TARGET_FILE:${CMAKE_PROJECT_NAME}>"
                --payload-so "${EMBED_PAYLOAD_SO}"
                COMMENT "Embedding route4 payload into libvmengine.so"
                VERBATIM)
    else ()
        message(WARNING "Route4 embed skipped: python or embed script not found.")
    endif ()
endif ()
