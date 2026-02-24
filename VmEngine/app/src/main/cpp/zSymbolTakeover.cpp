/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - 导出符号接管实现：通用槽位桩 -> vm_takeover_dispatch_by_id -> VM 执行。
 * - 加固链路位置：第四路线 L2（符号接管）。
 * - 输入：slot_id 与二元参数（a,b）。
 * - 输出：VM 执行结果。
 */
#include "zSymbolTakeover.h"

#include <mutex>
#include <string>
#include <unordered_map>

#include "zLog.h"
#include "zVmEngine.h"

extern "C" int vm_init();
extern "C" int vm_get_init_state();

namespace {

constexpr int kVmInitStateReady = 2;

struct zTakeoverState {
    // 全局状态锁，保护槽位映射与当前活动 so。
    std::mutex mutex;
    // slot_id -> fun_addr（VM 函数地址）映射。
    std::unordered_map<uint32_t, uint64_t> fun_addr_by_slot;
    // 当前用于执行 VM 函数的 so 名称（如 libdemo_expand_embedded.so）。
    std::string active_so_name;
    // 初始化是否完成。
    bool ready = false;
};

zTakeoverState& getTakeoverState() {
    // 函数静态对象：进程内唯一状态实例，首次调用时初始化。
    static zTakeoverState state;
    return state;
}

bool isValidText(const char* value) {
    return value != nullptr && value[0] != '\0';
}

uint64_t toVmArg(int value) {
    // 先转 int64 再转 uint64，保留负数位模式，匹配 VM 参数约定。
    return static_cast<uint64_t>(static_cast<int64_t>(value));
}

int dispatchBySlotOrZero(uint32_t slot_id, int a, int b) {
    // 先在锁内读取快照：fun_addr + active_so_name。
    uint64_t fun_addr = 0;
    std::string so_name;
    {
        zTakeoverState& state = getTakeoverState();
        std::lock_guard<std::mutex> lock(state.mutex);
        if (!state.ready) {
            LOGE("[route_symbol_takeover] dispatch failed: takeover not ready, slot=%u", slot_id);
            return 0;
        }
        auto it = state.fun_addr_by_slot.find(slot_id);
        if (it == state.fun_addr_by_slot.end() || it->second == 0) {
            LOGE("[route_symbol_takeover] dispatch failed: slot not found, slot=%u", slot_id);
            return 0;
        }
        fun_addr = it->second;
        so_name = state.active_so_name;
    }

    if (so_name.empty()) {
        LOGE("[route_symbol_takeover] dispatch failed: empty active so, slot=%u", slot_id);
        return 0;
    }

    // 走 VM 执行路径。
    zVmEngine& engine = zVmEngine::getInstance();
    uint64_t vm_result = 0;
    const zParams params({toVmArg(a), toVmArg(b)});
    vm_result = engine.execute(&vm_result, so_name.c_str(), fun_addr, params);
    return static_cast<int>(vm_result);
}

} // namespace

bool zSymbolTakeoverInit(
    const char* primary_so_name,
    const zTakeoverSymbolEntry* entries,
    size_t entry_count
) {
    // route4-only：必须提供至少一条有效 slot->fun_addr 映射。
    if (entries == nullptr || entry_count == 0) {
        LOGE("[route_symbol_takeover] init failed: empty slot mapping");
        return false;
    }

    std::unordered_map<uint32_t, uint64_t> fun_map;
    fun_map.reserve(entry_count);
    for (size_t i = 0; i < entry_count; ++i) {
        const zTakeoverSymbolEntry& entry = entries[i];
        if (entry.fun_addr == 0) {
            LOGE("[route_symbol_takeover] init failed: invalid fun_addr, index=%llu",
                 static_cast<unsigned long long>(i));
            return false;
        }
        if (fun_map.find(entry.slot_id) != fun_map.end()) {
            LOGE("[route_symbol_takeover] init failed: duplicated slot id=%u", entry.slot_id);
            return false;
        }
        fun_map[entry.slot_id] = entry.fun_addr;
    }

    // route4-only：当前执行目标只允许 primary_so_name。
    zVmEngine& engine = zVmEngine::getInstance();
    if (!isValidText(primary_so_name) || engine.GetSoinfo(primary_so_name) == nullptr) {
        LOGE("[route_symbol_takeover] init failed: invalid or unavailable primary_so=%s",
             primary_so_name == nullptr ? "(null)" : primary_so_name);
        return false;
    }
    const std::string selected_so_name = primary_so_name;

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

void zSymbolTakeoverClear() {
    zTakeoverState& state = getTakeoverState();
    std::lock_guard<std::mutex> lock(state.mutex);
    state.fun_addr_by_slot.clear();
    state.active_so_name.clear();
    state.ready = false;
}

extern "C" __attribute__((visibility("default"))) int vm_takeover_dispatch_by_id(int a, int b, uint32_t symbol_id) {
    // 跳板入口先确保 vmengine 初始化完成；未就绪时尝试惰性初始化。
    if (vm_get_init_state() != kVmInitStateReady) {
        const int init_ok = vm_init();
        if (init_ok == 0) {
            LOGE("[route_symbol_takeover] vm_init failed before dispatch: slot=%u state=%d",
                 symbol_id,
                 vm_get_init_state());
            return 0;
        }
    }
    // 所有通用槽位最终都跳到该函数，symbol_id 语义为 slot_id。
    return dispatchBySlotOrZero(symbol_id, a, b);
}
