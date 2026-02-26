/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - 导出符号接管实现：entry 跳板 -> vm_takeover_dispatch_by_id -> VM 执行。
 * - 加固链路位置：route4 L2（符号接管层）。
 * - 输入：entryId + (a,b) 参数。
 * - 输出：对应 VM 函数执行结果。
 */
#include "zSymbolTakeover.h"

// 互斥锁。
#include <mutex>
// std::string。
#include <string>
// 哈希映射。
#include <unordered_map>

// 日志。
#include "zLog.h"
// VM 引擎执行入口。
#include "zVmEngine.h"

// 由 zVmInitLifecycle.cpp 导出的 C 接口。
extern "C" int vm_init();
extern "C" int vm_get_init_state();

namespace {

// vm_init 就绪状态值（与生命周期模块保持一致）。
constexpr int kVmInitStateReady = 2;

// 接管模块的全局运行状态。
struct zTakeoverState {
    // 状态锁：保护以下成员的并发访问。
    std::mutex mutex;
    // entryId -> funAddr 映射。
    std::unordered_map<uint32_t, uint64_t> funAddrByEntry;
    // 当前激活的 so 名称（例如 libdemo_expand_embedded.so）。
    std::string activeSoName;
    // 初始化完成标记。
    bool ready = false;
};

// 访问单例状态对象。
zTakeoverState& getTakeoverState() {
    // 函数静态对象：进程内仅一份。
    static zTakeoverState state;
    return state;
}

// 判断 C 字符串是否为非空有效文本。
bool isValidText(const char* value) {
    return value != nullptr && value[0] != '\0';
}

// 把 int 参数转换成 VM 约定的 uint64 参数。
uint64_t toVmArg(int value) {
    // 经 int64_t 中转，确保负数符号位语义保持。
    return static_cast<uint64_t>(static_cast<int64_t>(value));
}

// 按 entryId 分发执行；失败统一返回 0。
int dispatchByEntryOrZero(uint32_t entryId, int a, int b) {
    // 先在锁内取快照，减少锁持有时间。
    uint64_t funAddr = 0;
    std::string soName;
    {
        // 拿到全局状态对象。
        zTakeoverState& state = getTakeoverState();
        // 加锁读取。
        std::lock_guard<std::mutex> lock(state.mutex);
        // 未初始化直接失败。
        if (!state.ready) {
            LOGE("[route_symbol_takeover] dispatch failed: takeover not ready, entry=%u", entryId);
            return 0;
        }
        // 查找 entry 对应函数地址。
        auto it = state.funAddrByEntry.find(entryId);
        if (it == state.funAddrByEntry.end() || it->second == 0) {
            LOGE("[route_symbol_takeover] dispatch failed: entry not found, entry=%u", entryId);
            return 0;
        }
        // 拷贝快照到栈变量。
        funAddr = it->second;
        soName = state.activeSoName;
    }

    // 快照校验：so 名称必须非空。
    if (soName.empty()) {
        LOGE("[route_symbol_takeover] dispatch failed: empty active so, entry=%u", entryId);
        return 0;
    }

    // 进入 VM 执行路径。
    zVmEngine& engine = zVmEngine::getInstance();
    // VM 返回值缓冲。
    uint64_t vm_result = 0;
    // 组装二元参数列表。
    const zParams params({toVmArg(a), toVmArg(b)});
    // 执行对应 VM 函数。
    vm_result = engine.execute(&vm_result, soName.c_str(), funAddr, params);
    // 约定以 int 返回给 native 调用方。
    return static_cast<int>(vm_result);
}

} // namespace

// 初始化接管映射（entryId -> funAddr）与激活 so。
bool zSymbolTakeoverInit(
    const char* primarySoName,
    const zTakeoverSymbolEntry* entries,
    size_t entryCount
) {
    // 必须提供有效映射数组。
    if (entries == nullptr || entryCount == 0) {
        LOGE("[route_symbol_takeover] init failed: empty entry mapping");
        return false;
    }

    // 先构建临时映射，校验通过后再一次性提交到全局状态。
    std::unordered_map<uint32_t, uint64_t> funMap;
    funMap.reserve(entryCount);
    for (size_t i = 0; i < entryCount; ++i) {
        // 当前条目引用。
        const zTakeoverSymbolEntry& entry = entries[i];
        // 地址不能为 0。
        if (entry.funAddr == 0) {
            LOGE("[route_symbol_takeover] init failed: invalid funAddr, index=%llu",
                 static_cast<unsigned long long>(i));
            return false;
        }
        // entryId 不允许重复。
        if (funMap.find(entry.entryId) != funMap.end()) {
            LOGE("[route_symbol_takeover] init failed: duplicated entry id=%u", entry.entryId);
            return false;
        }
        // 写入临时映射。
        funMap[entry.entryId] = entry.funAddr;
    }

    // 校验 primary so 必须存在并已被链接器感知。
    zVmEngine& engine = zVmEngine::getInstance();
    if (!isValidText(primarySoName) || engine.GetSoinfo(primarySoName) == nullptr) {
        LOGE("[route_symbol_takeover] init failed: invalid or unavailable primary_so=%s",
             primarySoName == nullptr ? "(null)" : primarySoName);
        return false;
    }
    // route4 当前只使用 primary so。
    const std::string selectedSoName = primarySoName;

    // 提交到全局状态。
    zTakeoverState& state = getTakeoverState();
    std::lock_guard<std::mutex> lock(state.mutex);
    state.funAddrByEntry = std::move(funMap);
    state.activeSoName = selectedSoName;
    state.ready = true;
    LOGI("[route_symbol_takeover] init ready: so=%s entry_count=%llu",
         state.activeSoName.c_str(),
         static_cast<unsigned long long>(state.funAddrByEntry.size()));
    return true;
}

// 清理接管状态，支持重复初始化与回归测试。
void zSymbolTakeoverClear() {
    zTakeoverState& state = getTakeoverState();
    std::lock_guard<std::mutex> lock(state.mutex);
    // 清空映射。
    state.funAddrByEntry.clear();
    // 清空目标 so。
    state.activeSoName.clear();
    // 回到未就绪状态。
    state.ready = false;
}

// 所有通用 entry 跳板最终都调用该入口。
extern "C" __attribute__((visibility("default"))) int vm_takeover_dispatch_by_id(int a, int b, uint32_t symbol_id) {
    // 若 vmengine 未就绪，先尝试惰性初始化。
    if (vm_get_init_state() != kVmInitStateReady) {
        const int init_ok = vm_init();
        if (init_ok == 0) {
            LOGE("[route_symbol_takeover] vm_init failed before dispatch: entry=%u state=%d",
                 symbol_id,
                 vm_get_init_state());
            return 0;
        }
    }
    // symbol_id 在此语义即 entryId。
    return dispatchByEntryOrZero(symbol_id, a, b);
}
