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

# vmengine 为 JNI 入口动态库：
# Java 层通过 System.loadLibrary("vmengine") 加载它，
# vm_init 构造期会初始化 VM 执行链路。
add_library(${CMAKE_PROJECT_NAME} SHARED
        zNativeLib.cpp
        zLinker.cpp
        zEmbeddedPayload.cpp
        zPatchBay.cpp
        zTypeManager.cpp
        zVmEngine.cpp
        zVmOpcodes.cpp
        zSymbolTakeover.cpp
        ${TAKEOVER_STUB_ASM}
        zFunctionData.cpp
        zAssetManager.cpp
        zFunction.cpp
        zSoBinBundle.cpp
        zLog.cpp)

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
