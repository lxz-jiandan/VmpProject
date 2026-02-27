/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - 导出符号接管实现：key 跳板 -> vm_takeover_dispatch_by_key -> VM 执行。
 * - 加固链路位置：route4 L2（符号接管层）。
 * - 输入：soId + symbolKey + (a,b) 参数。
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
    // soId -> soName 映射。
    std::unordered_map<uint32_t, std::string> soNameById;
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

// 按 (soId, symbolKey) 分发执行；失败统一返回 0。
int dispatchByKeyOrZero(uint64_t symbolKey, uint32_t soId, int a, int b) {
    // 参数快速校验。
    if (symbolKey == 0 || soId == 0) {
        LOGE("[route_symbol_takeover] dispatch failed: invalid route key, so_id=%u key=0x%llx",
             soId,
             static_cast<unsigned long long>(symbolKey));
        return 0;
    }

    // 先在锁内取快照，减少锁持有时间。
    std::string soName;
    {
        // 拿到全局状态对象。
        zTakeoverState& state = getTakeoverState();
        // 加锁读取。
        std::lock_guard<std::mutex> lock(state.mutex);
        // 未初始化直接失败。
        if (!state.ready) {
            LOGE("[route_symbol_takeover] dispatch failed: takeover not ready, so_id=%u", soId);
            return 0;
        }
        // 查找模块 soName。
        auto it = state.soNameById.find(soId);
        if (it == state.soNameById.end() || it->second.empty()) {
            LOGE("[route_symbol_takeover] dispatch failed: so_id not registered, so_id=%u", soId);
            return 0;
        }
        // 拷贝快照到栈变量。
        soName = it->second;
    }

    // 快照校验：so 名称必须非空。
    if (soName.empty()) {
        LOGE("[route_symbol_takeover] dispatch failed: empty so name, so_id=%u", soId);
        return 0;
    }

    // 进入 VM 执行路径。
    zVmEngine& engine = zVmEngine::getInstance();
    // VM 返回值缓冲。
    uint64_t vmResult = 0;
    // 组装二元参数列表。
    const zParams params({toVmArg(a), toVmArg(b)});
    // 执行对应 VM 函数。
    vmResult = engine.execute(&vmResult, soName.c_str(), symbolKey, params);
    // 约定以 int 返回给 native 调用方。
    return static_cast<int>(vmResult);
}

} // namespace

// 注册接管模块（soId -> soName）。
bool zSymbolTakeoverRegisterModule(uint32_t soId, const char* soName) {
    // 参数必须有效。
    if (soId == 0 || !isValidText(soName)) {
        LOGE("[route_symbol_takeover] register failed: invalid args so_id=%u so_name=%s",
             soId,
             soName == nullptr ? "(null)" : soName);
        return false;
    }

    // 校验 so 必须存在并已被链接器感知。
    zVmEngine& engine = zVmEngine::getInstance();
    if (engine.GetSoinfo(soName) == nullptr) {
        LOGE("[route_symbol_takeover] register failed: so unavailable so_id=%u so_name=%s",
             soId,
             soName);
        return false;
    }

    // 提交到全局状态。
    zTakeoverState& state = getTakeoverState();
    std::lock_guard<std::mutex> lock(state.mutex);
    state.soNameById[soId] = soName;
    state.ready = !state.soNameById.empty();
    LOGI("[route_symbol_takeover] register ready: so_id=%u so_name=%s module_count=%llu",
         soId,
         soName,
         static_cast<unsigned long long>(state.soNameById.size()));
    return true;
}

// 清理接管状态，支持重复初始化与回归测试。
void zSymbolTakeoverClear() {
    zTakeoverState& state = getTakeoverState();
    std::lock_guard<std::mutex> lock(state.mutex);
    // 清空模块映射。
    state.soNameById.clear();
    // 回到未就绪状态。
    state.ready = false;
}

// 所有通用 key 跳板最终都调用该入口。
extern "C" __attribute__((visibility("default"))) int vm_takeover_dispatch_by_key(int a,
                                                                                     int b,
                                                                                     uint64_t symbolKey,
                                                                                     uint32_t soId) {
    // 若 vmengine 未就绪，先尝试惰性初始化。
    if (vm_get_init_state() != kVmInitStateReady) {
        const int initOk = vm_init();
        if (initOk == 0) {
            LOGE("[route_symbol_takeover] vm_init failed before dispatch: so_id=%u key=0x%llx state=%d",
                 soId,
                 static_cast<unsigned long long>(symbolKey),
                 vm_get_init_state());
            return 0;
        }
    }
    return dispatchByKeyOrZero(symbolKey, soId, a, b);
}
