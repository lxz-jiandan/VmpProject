#include "zVmInitCore.h"

// dladdr / Dl_info。
#include <dlfcn.h>
// unique_ptr。
#include <memory>
// std::string。
#include <string>
// std::vector。
#include <vector>

// 从 so 中提取 takeover 元数据。
#include "zElfTakeoverDynsym.h"
// 读取嵌入 payload 的工具。
#include "zEmbeddedPayload.h"
// zFunction 编码载体。
#include "zFunction.h"
// 日志。
#include "zLog.h"
// 全局路径/常量配置。
#include "zPipelineConfig.h"
// expand so 的 payload 读取器。
#include "zSoBinBundle.h"
// 符号接管初始化。
#include "zSymbolTakeover.h"
// VM 引擎单例。
#include "zVmEngine.h"

namespace {

// 嵌入 expand so 路由状态。
enum class EmbeddedExpandRouteStatus {
    // 路由成功。
    kPass = 0,
    // 路由失败。
    kFail = 1,
};

// 根据当前进程内符号地址反查所在 so 文件路径。
bool resolveCurrentLibraryPath(void* symbol, std::string& out_path) {
    // 先清空输出，避免调用方误用旧值。
    out_path.clear();
    // 传入符号为空时无法定位库路径。
    if (symbol == nullptr) {
        return false;
    }

    // dladdr 输出结构体。
    Dl_info info{};
    // 查询失败或文件名无效都判失败。
    if (dladdr(symbol, &info) == 0 || info.dli_fname == nullptr || info.dli_fname[0] == '\0') {
        return false;
    }
    // 写回解析到的真实 so 路径。
    out_path = info.dli_fname;
    return true;
}

// 把 expand so 中的已编码函数批量预加载到 VM 引擎缓存。
bool preloadExpandedSoBundle(
    zVmEngine& engine,
    const char* so_name,
    const char* route_tag,
    const uint8_t* expand_so_bytes,
    size_t expand_so_size
) {
    // expand so 里导出的函数条目。
    std::vector<zSoBinEntry> entries;
    // 共享分支地址表（用于 OP_BL 目标映射）。
    std::vector<uint64_t> shared_branch_addrs;
    // 先读取 expand so 容器。
    if (!zSoBinBundleReader::readFromExpandedSoBytes(
            expand_so_bytes,
            expand_so_size,
            entries,
            shared_branch_addrs)) {
        LOGE("[%s] preload readFromExpandedSoBytes failed", route_tag);
        return false;
    }
    // 空容器通常表示构建链路异常。
    if (entries.empty()) {
        LOGE("[%s] preload failed: empty payload list", route_tag);
        return false;
    }

    // 先把共享分支表挂到引擎，后续函数执行按 so 名称取表。
    engine.setSharedBranchAddrs(so_name, std::move(shared_branch_addrs));

    // 逐条 payload 反序列化并写入引擎缓存。
    for (const zSoBinEntry& entry : entries) {
        // 每条 payload 对应一个 zFunction 实例。
        std::unique_ptr<zFunction> function = std::make_unique<zFunction>();
        // 载入编码数据。
        if (!function->loadEncodedData(entry.encoded_data.data(), entry.encoded_data.size())) {
            LOGE("[%s] preload loadEncodedData failed: fun_addr=0x%llx",
                 route_tag,
                 static_cast<unsigned long long>(entry.fun_addr));
            return false;
        }
        // 记录函数原始地址，用于 dispatch 时定位。
        function->setFunctionAddress(entry.fun_addr);
        // 放入引擎缓存，后续可按地址命中。
        if (!engine.cacheFunction(std::move(function))) {
            LOGE("[%s] preload cacheFunction failed: fun_addr=0x%llx",
                 route_tag,
                 static_cast<unsigned long long>(entry.fun_addr));
            return false;
        }
    }
    // 打印加载成功统计。
    LOGI("[%s] preload success: cached_entries=%llu",
         route_tag,
         static_cast<unsigned long long>(entries.size()));
    return true;
}

// route_embedded_expand_so: 从 vmengine so 中提取嵌入 payload 并激活。
EmbeddedExpandRouteStatus test_loadEmbeddedExpandedSo(JNIEnv* env, zVmEngine& engine) {
    // 当前内存直装路线不再依赖 JNI files 目录路径。
    (void)env;
    // 先定位当前 vmengine so 路径。
    std::string vmengine_path;
    if (!resolveCurrentLibraryPath(reinterpret_cast<void*>(&test_loadEmbeddedExpandedSo), vmengine_path)) {
        LOGE("[route_embedded_expand_so] resolveCurrentLibraryPath failed");
        return EmbeddedExpandRouteStatus::kFail;
    }

    // 读取嵌入 payload 原始字节。
    std::vector<uint8_t> embedded_payload;
    // 读取状态用于区分“未找到”和“格式错误”。
    zEmbeddedPayloadReadStatus read_status = zEmbeddedPayloadReadStatus::kInvalid;
    if (!zEmbeddedPayload::readEmbeddedPayloadFromHostSo(vmengine_path, embedded_payload, &read_status)) {
        LOGE("[route_embedded_expand_so] readEmbeddedPayloadFromHostSo failed: %s", vmengine_path.c_str());
        return EmbeddedExpandRouteStatus::kFail;
    }
    // 明确区分 payload 缺失。
    if (read_status == zEmbeddedPayloadReadStatus::kNotFound) {
        LOGE("[route_embedded_expand_so] embedded payload not found in %s", vmengine_path.c_str());
        return EmbeddedExpandRouteStatus::kFail;
    }
    // 防御：读取成功但内容为空也视为失败。
    if (embedded_payload.empty()) {
        LOGE("[route_embedded_expand_so] embedded payload is empty");
        return EmbeddedExpandRouteStatus::kFail;
    }

    // 记录内存加载标识，便于调试定位 route4 数据源。
    g_libdemo_expand_embedded_so_path = std::string("<memory>:") + kEmbeddedExpandSoName;

    // 直接从内存字节加载该 so，避免“先落盘再加载”。
    if (!engine.LoadLibraryFromMemory(kEmbeddedExpandSoName,
                                      embedded_payload.data(),
                                      embedded_payload.size())) {
        LOGE("[route_embedded_expand_so] custom linker load from memory failed: %s",
             kEmbeddedExpandSoName);
        return EmbeddedExpandRouteStatus::kFail;
    }

    // 把 expand so 的函数 payload 预热进 VM 缓存。
    if (!preloadExpandedSoBundle(
            engine,
            kEmbeddedExpandSoName,
            "route_embedded_expand_so",
            embedded_payload.data(),
            embedded_payload.size())) {
        return EmbeddedExpandRouteStatus::kFail;
    }
    // 全流程成功。
    return EmbeddedExpandRouteStatus::kPass;
}

// 初始化符号 takeover 表。
bool initSymbolTakeover(const std::string& vmengine_path) {
    // 从已补丁 vmengine so 里恢复 takeover 条目。
    std::vector<zTakeoverSymbolEntry> entries;
    if (!zElfRecoverTakeoverEntriesFromPatchedSo(vmengine_path, entries)) {
        return false;
    }
    // 初始化运行时 takeover 映射。
    return zSymbolTakeoverInit(kEmbeddedExpandSoName, entries.data(), entries.size());
}

} // namespace

// route4 初始化核心入口。
bool runVmInitCore(JNIEnv* env) {
    // JNI 环境必须有效。
    if (env == nullptr) {
        LOGE("vm_init failed: env is null");
        return false;
    }

    // 获取 VM 引擎单例。
    zVmEngine& engine = zVmEngine::getInstance();
    // 清理旧缓存，避免二次初始化残留。
    engine.clearCache();
    // 清理各 so 的共享分支地址表。
    engine.clearSharedBranchAddrs(kAssetBaseSo);
    engine.clearSharedBranchAddrs(kAssetExpandSo);
    engine.clearSharedBranchAddrs(kEmbeddedExpandSoName);
    // 清空 takeover 全局表。
    zSymbolTakeoverClear();

    // 先执行 embedded expand so 路由。
    const EmbeddedExpandRouteStatus embedded_status = test_loadEmbeddedExpandedSo(env, engine);
    // 转为 bool 便于组合判断。
    const bool ok_embedded_expand = (embedded_status == EmbeddedExpandRouteStatus::kPass);
    LOGI("route_embedded_expand_so result=%d state=%d",
         ok_embedded_expand ? 1 : 0,
         static_cast<int>(embedded_status));

    // 再解析 vmengine 自身路径，用于 takeover 初始化。
    std::string vmengine_path_for_takeover;
    const bool ok_vmengine_path = resolveCurrentLibraryPath(reinterpret_cast<void*>(&runVmInitCore),
                                                            vmengine_path_for_takeover);
    if (!ok_vmengine_path) {
        LOGE("vm_init route4 init failed: resolve vmengine path for takeover");
    }
    // takeover 成功依赖于前置路由和路径解析都成功。
    const bool ok_takeover_init = ok_embedded_expand &&
                                  ok_vmengine_path &&
                                  initSymbolTakeover(vmengine_path_for_takeover);
    LOGI("route_symbol_takeover result=%d", ok_takeover_init ? 1 : 0);

    // 任一关键路由失败都返回 false。
    if (!(ok_embedded_expand && ok_takeover_init)) {
        LOGE("vm_init route4 init failed: embedded_expand=%d embedded_state=%d symbol_takeover=%d takeover_init=%d",
             ok_embedded_expand ? 1 : 0,
             static_cast<int>(embedded_status),
             ok_takeover_init ? 1 : 0,
             ok_takeover_init ? 1 : 0);
        return false;
    }
    // 初始化完成。
    return true;
}
