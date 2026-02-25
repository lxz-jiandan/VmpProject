/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - 导出符号接管实现：slot 跳板 -> vm_takeover_dispatch_by_id -> VM 执行。
 * - 加固链路位置：route4 L2（符号接管层）。
 * - 输入：slot_id + (a,b) 参数。
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
    // slot_id -> fun_addr 映射。
    std::unordered_map<uint32_t, uint64_t> fun_addr_by_slot;
    // 当前激活的 so 名称（例如 libdemo_expand_embedded.so）。
    std::string active_so_name;
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

// 按 slot_id 分发执行；失败统一返回 0。
int dispatchBySlotOrZero(uint32_t slot_id, int a, int b) {
    // 先在锁内取快照，减少锁持有时间。
    uint64_t fun_addr = 0;
    std::string so_name;
    {
        // 拿到全局状态对象。
        zTakeoverState& state = getTakeoverState();
        // 加锁读取。
        std::lock_guard<std::mutex> lock(state.mutex);
        // 未初始化直接失败。
        if (!state.ready) {
            LOGE("[route_symbol_takeover] dispatch failed: takeover not ready, slot=%u", slot_id);
            return 0;
        }
        // 查找 slot 对应函数地址。
        auto it = state.fun_addr_by_slot.find(slot_id);
        if (it == state.fun_addr_by_slot.end() || it->second == 0) {
            LOGE("[route_symbol_takeover] dispatch failed: slot not found, slot=%u", slot_id);
            return 0;
        }
        // 拷贝快照到栈变量。
        fun_addr = it->second;
        so_name = state.active_so_name;
    }

    // 快照校验：so 名称必须非空。
    if (so_name.empty()) {
        LOGE("[route_symbol_takeover] dispatch failed: empty active so, slot=%u", slot_id);
        return 0;
    }

    // 进入 VM 执行路径。
    zVmEngine& engine = zVmEngine::getInstance();
    // VM 返回值缓冲。
    uint64_t vm_result = 0;
    // 组装二元参数列表。
    const zParams params({toVmArg(a), toVmArg(b)});
    // 执行对应 VM 函数。
    vm_result = engine.execute(&vm_result, so_name.c_str(), fun_addr, params);
    // 约定以 int 返回给 native 调用方。
    return static_cast<int>(vm_result);
}

} // namespace

// 初始化接管映射（slot_id -> fun_addr）与激活 so。
bool zSymbolTakeoverInit(
    const char* primary_so_name,
    const zTakeoverSymbolEntry* entries,
    size_t entry_count
) {
    // 必须提供有效映射数组。
    if (entries == nullptr || entry_count == 0) {
        LOGE("[route_symbol_takeover] init failed: empty slot mapping");
        return false;
    }

    // 先构建临时映射，校验通过后再一次性提交到全局状态。
    std::unordered_map<uint32_t, uint64_t> fun_map;
    fun_map.reserve(entry_count);
    for (size_t i = 0; i < entry_count; ++i) {
        // 当前条目引用。
        const zTakeoverSymbolEntry& entry = entries[i];
        // 地址不能为 0。
        if (entry.fun_addr == 0) {
            LOGE("[route_symbol_takeover] init failed: invalid fun_addr, index=%llu",
                 static_cast<unsigned long long>(i));
            return false;
        }
        // slot_id 不允许重复。
        if (fun_map.find(entry.slot_id) != fun_map.end()) {
            LOGE("[route_symbol_takeover] init failed: duplicated slot id=%u", entry.slot_id);
            return false;
        }
        // 写入临时映射。
        fun_map[entry.slot_id] = entry.fun_addr;
    }

    // 校验 primary so 必须存在并已被链接器感知。
    zVmEngine& engine = zVmEngine::getInstance();
    if (!isValidText(primary_so_name) || engine.GetSoinfo(primary_so_name) == nullptr) {
        LOGE("[route_symbol_takeover] init failed: invalid or unavailable primary_so=%s",
             primary_so_name == nullptr ? "(null)" : primary_so_name);
        return false;
    }
    // route4 当前只使用 primary so。
    const std::string selected_so_name = primary_so_name;

    // 提交到全局状态。
    zTakeoverState& state = getTakeoverState();
    std::lock_guard<std::mutex> lock(state.mutex);
    state.fun_addr_by_slot = std::move(fun_map);
    state.active_so_name = selected_so_name;
    state.ready = true;
    LOGI("[route_symbol_takeover] init ready: so=%s slot_count=%llu",
         state.active_so_name.c_str(),
         static_cast<unsigned long long>(state.fun_addr_by_slot.size()));
    return true;
}

// 清理接管状态，支持重复初始化与回归测试。
void zSymbolTakeoverClear() {
    zTakeoverState& state = getTakeoverState();
    std::lock_guard<std::mutex> lock(state.mutex);
    // 清空映射。
    state.fun_addr_by_slot.clear();
    // 清空目标 so。
    state.active_so_name.clear();
    // 回到未就绪状态。
    state.ready = false;
}

// 所有通用 slot 跳板最终都调用该入口。
extern "C" __attribute__((visibility("default"))) int vm_takeover_dispatch_by_id(int a, int b, uint32_t symbol_id) {
    // 若 vmengine 未就绪，先尝试惰性初始化。
    if (vm_get_init_state() != kVmInitStateReady) {
        const int init_ok = vm_init();
        if (init_ok == 0) {
            LOGE("[route_symbol_takeover] vm_init failed before dispatch: slot=%u state=%d",
                 symbol_id,
                 vm_get_init_state());
            return 0;
        }
    }
    // symbol_id 在此语义即 slot_id。
    return dispatchBySlotOrZero(symbol_id, a, b);
}
