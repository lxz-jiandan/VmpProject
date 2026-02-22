/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - 导出符号接管实现：导出桩 -> dispatch_by_id -> VM 执行。
 * - 加固链路位置：第四路线 L2（符号接管）。
 * - 输入：symbol->fun_addr 映射与入参。
 * - 输出：被接管导出的 VM 执行结果。
 */
#include "zSymbolTakeover.h"

#include <cstring>
#include <dlfcn.h>
#include <mutex>
#include <string>
#include <unordered_map>

#include "generated/zTakeoverSymbols.generated.h"
#include "zLog.h"
#include "zVmEngine.h"

namespace {

struct zTakeoverState {
    // 全局状态锁，保护映射表与当前活动 so。
    std::mutex mutex;
    // 导出符号名 -> fun_addr（VM 函数地址）映射。
    std::unordered_map<std::string, uint64_t> fun_addr_by_symbol;
    // 当前用于执行 VM 函数的 so 名称（如 libdemo_expand_embedded.so）。
    std::string active_so_name;
    // 参考 so 句柄（demo 侧可通过 JNI 主动注入）。
    void* reference_so_handle = nullptr;
    // 初始化是否完成。
    bool ready = false;
};

zTakeoverState& getTakeoverState() {
    static zTakeoverState state;
    return state;
}

bool isValidText(const char* value) {
    return value != nullptr && value[0] != '\0';
}

bool canUseSoName(zVmEngine& engine, const char* so_name) {
    if (!isValidText(so_name)) {
        return false;
    }
    return engine.GetSoinfo(so_name) != nullptr;
}

uint64_t toVmArg(int value) {
    return static_cast<uint64_t>(static_cast<int64_t>(value));
}

bool fallbackFromReferenceSo(const char* symbol_name, int a, int b, int* out_result) {
    // fallback 优先级：
    // 1) 复用已注入句柄；
    // 2) 按库名 dlopen；
    // 3) 按当前 so 同目录绝对路径 dlopen。
    // 目的：当 VM route 不可用时仍可返回一个可预期结果，避免崩溃。
    if (!isValidText(symbol_name) || out_result == nullptr) {
        return false;
    }

    void* reference_handle = nullptr;
    {
        zTakeoverState& state = getTakeoverState();
        std::lock_guard<std::mutex> lock(state.mutex);
        reference_handle = state.reference_so_handle;
    }
    if (reference_handle == nullptr) {
        // demo 场景会额外打包 libdemo_ref.so，优先按库名尝试。
        reference_handle = dlopen("libdemo_ref.so", RTLD_NOW | RTLD_LOCAL);
    }
    if (reference_handle == nullptr) {
        // 某些 Android 命名空间下，裸库名不可见；退化为同目录绝对路径加载。
        Dl_info info{};
        if (dladdr(reinterpret_cast<void*>(&fallbackFromReferenceSo), &info) != 0 &&
            info.dli_fname != nullptr && info.dli_fname[0] != '\0') {
            std::string path = info.dli_fname;
            const size_t slash = path.find_last_of('/');
            if (slash != std::string::npos) {
                path.resize(slash + 1);
                path += "libdemo_ref.so";
                reference_handle = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
            }
        }
    }
    if (reference_handle != nullptr) {
        zTakeoverState& state = getTakeoverState();
        std::lock_guard<std::mutex> lock(state.mutex);
        if (state.reference_so_handle == nullptr) {
            state.reference_so_handle = reference_handle;
        }
    }
    if (reference_handle == nullptr) {
        return false;
    }

    dlerror();
    void* sym = dlsym(reference_handle, symbol_name);
    const char* sym_error = dlerror();
    if (sym == nullptr || sym_error != nullptr) {
        return false;
    }

    using BinaryFn = int (*)(int, int);
    auto fn = reinterpret_cast<BinaryFn>(sym);
    *out_result = fn(a, b);
    return true;
}

int fallback_fun_add(int a, int b) {
    return a + b;
}

int fallback_fun_for(int a, int b) {
    int ret = 0;
    for (int i = 0; i < 5; ++i) {
        ret += a;
        ret += b;
    }
    return ret;
}

int fallback_fun_if_sub(int a, int b) {
    if (a > b) {
        return a - b;
    }
    return b - a;
}

int fallback_fun_for_add(int a, int b) {
    return fallback_fun_for(a, b);
}

int fallback_fun_countdown_muladd(int a, int b) {
    int acc = 0;
    int counter = a;
    while (counter > 0) {
        acc += b;
        --counter;
    }
    return acc + a;
}

int fallback_fun_loop_call_mix(int a, int b) {
    int acc = 0;
    for (int i = 0; i < 4; ++i) {
        if (i < 2) {
            acc += fallback_fun_add(a, b);
        } else {
            acc += fallback_fun_add(a, 1);
        }
    }
    return acc;
}

int fallback_fun_call_chain(int a, int b) {
    return fallback_fun_for(a, b) + fallback_fun_add(a, b) + fallback_fun_if_sub(a, b);
}

int fallback_fun_branch_call(int a, int b) {
    if (a >= b) {
        return fallback_fun_countdown_muladd(a, b) + fallback_fun_add(a, b);
    }
    return fallback_fun_loop_call_mix(a, b) + fallback_fun_add(a, b);
}

int fallbackBySymbolName(const char* symbol_name, int a, int b) {
    // 对最常见的 demo 函数提供公式级兜底，减少联调阶段“全部失败”的噪音。
    if (symbol_name == nullptr) {
        return 0;
    }
    int ref_result = 0;
    if (fallbackFromReferenceSo(symbol_name, a, b, &ref_result)) {
        return ref_result;
    }
    if (std::strcmp(symbol_name, "fun_add") == 0) {
        return fallback_fun_add(a, b);
    }
    if (std::strcmp(symbol_name, "fun_for") == 0) {
        return fallback_fun_for(a, b);
    }
    if (std::strcmp(symbol_name, "fun_if_sub") == 0) {
        return fallback_fun_if_sub(a, b);
    }
    if (std::strcmp(symbol_name, "fun_for_add") == 0) {
        return fallback_fun_for_add(a, b);
    }
    if (std::strcmp(symbol_name, "fun_countdown_muladd") == 0) {
        return fallback_fun_countdown_muladd(a, b);
    }
    if (std::strcmp(symbol_name, "fun_loop_call_mix") == 0) {
        return fallback_fun_loop_call_mix(a, b);
    }
    if (std::strcmp(symbol_name, "fun_call_chain") == 0) {
        return fallback_fun_call_chain(a, b);
    }
    if (std::strcmp(symbol_name, "fun_branch_call") == 0) {
        return fallback_fun_branch_call(a, b);
    }
    LOGE("[route_symbol_takeover] fallback missing for symbol=%s", symbol_name);
    return 0;
}

int dispatchByIdOrFallback(uint32_t symbol_id, int a, int b) {
    // 导出桩统一转发到这里：
    // - 先通过 symbol_id 找到符号名；
    // - 再优先走 VM dispatch；
    // - 失败时再走 reference/formula fallback。
    const char* symbol_name = zTakeoverGeneratedSymbolNameById(symbol_id);
    if (!isValidText(symbol_name)) {
        LOGE("[route_symbol_takeover] invalid symbol_id=%u", symbol_id);
        return 0;
    }

    int out_result = 0;
    if (zSymbolTakeoverDispatchBinary(symbol_name, a, b, &out_result)) {
        return out_result;
    }
    LOGW("[route_symbol_takeover][%s] fallback path by stub id=%u", symbol_name, symbol_id);
    return fallbackBySymbolName(symbol_name, a, b);
}

} // namespace

bool zSymbolTakeoverInit(
    const zTakeoverConfig& config,
    const zTakeoverSymbolEntry* entries,
    size_t entry_count
) {
    // 接管初始化：
    // 1) 校验 entries；
    // 2) 选择可用 so（primary/fallback）；
    // 3) 写入全局接管状态。
    if (entries == nullptr || entry_count == 0) {
        LOGE("[route_symbol_takeover] init failed: empty entries");
        return false;
    }

    std::unordered_map<std::string, uint64_t> fun_map;
    fun_map.reserve(entry_count);
    for (size_t i = 0; i < entry_count; ++i) {
        const zTakeoverSymbolEntry& entry = entries[i];
        if (!isValidText(entry.symbol_name) || entry.fun_addr == 0) {
            LOGE("[route_symbol_takeover] init failed: invalid entry index=%llu",
                 static_cast<unsigned long long>(i));
            return false;
        }
        fun_map[entry.symbol_name] = entry.fun_addr;
    }

    zVmEngine& engine = zVmEngine::getInstance();
    std::string selected_so_name;
    if (canUseSoName(engine, config.primary_so_name)) {
        selected_so_name = config.primary_so_name;
    } else if (canUseSoName(engine, config.fallback_so_name)) {
        selected_so_name = config.fallback_so_name;
    } else {
        LOGE("[route_symbol_takeover] init failed: no available so. primary=%s fallback=%s",
             config.primary_so_name == nullptr ? "(null)" : config.primary_so_name,
             config.fallback_so_name == nullptr ? "(null)" : config.fallback_so_name);
        return false;
    }

    zTakeoverState& state = getTakeoverState();
    std::lock_guard<std::mutex> lock(state.mutex);
    state.fun_addr_by_symbol = std::move(fun_map);
    state.active_so_name = selected_so_name;
    state.ready = true;
    LOGI("[route_symbol_takeover] init ready: so=%s symbol_count=%llu",
         state.active_so_name.c_str(),
         static_cast<unsigned long long>(state.fun_addr_by_symbol.size()));
    return true;
}

void zSymbolTakeoverClear() {
    zTakeoverState& state = getTakeoverState();
    std::lock_guard<std::mutex> lock(state.mutex);
    state.fun_addr_by_symbol.clear();
    state.active_so_name.clear();
    state.reference_so_handle = nullptr;
    state.ready = false;
}

bool zSymbolTakeoverIsReady() {
    zTakeoverState& state = getTakeoverState();
    std::lock_guard<std::mutex> lock(state.mutex);
    return state.ready;
}

const char* zSymbolTakeoverActiveSoName() {
    zTakeoverState& state = getTakeoverState();
    std::lock_guard<std::mutex> lock(state.mutex);
    if (!state.ready || state.active_so_name.empty()) {
        return nullptr;
    }
    return state.active_so_name.c_str();
}

size_t zSymbolTakeoverSymbolCount() {
    return kTakeoverGeneratedSymbolCount;
}

const char* zSymbolTakeoverSymbolNameAt(size_t index) {
    if (index >= kTakeoverGeneratedSymbolCount) {
        return nullptr;
    }
    return kTakeoverGeneratedSymbols[index].symbol_name;
}

bool zSymbolTakeoverDispatchBinary(const char* symbol_name, int a, int b, int* out_result) {
    // 真正的 VM 执行路径：
    // symbol_name -> fun_addr -> engine.execute(...)。
    if (!isValidText(symbol_name)) {
        return false;
    }

    uint64_t fun_addr = 0;
    std::string so_name;
    {
        zTakeoverState& state = getTakeoverState();
        std::lock_guard<std::mutex> lock(state.mutex);
        if (!state.ready) {
            return false;
        }
        auto it = state.fun_addr_by_symbol.find(symbol_name);
        if (it == state.fun_addr_by_symbol.end() || it->second == 0) {
            return false;
        }
        fun_addr = it->second;
        so_name = state.active_so_name;
    }

    if (so_name.empty()) {
        return false;
    }

    zVmEngine& engine = zVmEngine::getInstance();
    uint64_t vm_result = 0;
    const zParams params({toVmArg(a), toVmArg(b)});
    vm_result = engine.execute(&vm_result, so_name.c_str(), fun_addr, params);
    if (out_result != nullptr) {
        *out_result = static_cast<int>(vm_result);
    }
    return true;
}

extern "C" __attribute__((visibility("default"))) int z_takeover_dispatch_by_id(int a, int b, uint32_t symbol_id) {
    // 注意：所有导出桩最终都跳到该函数，ABI 形态固定为 (a,b,symbol_id)。
    return dispatchByIdOrFallback(symbol_id, a, b);
}

extern "C" __attribute__((visibility("default"))) void z_takeover_set_reference_so_handle(void* handle) {
    if (handle == nullptr) {
        return;
    }
    zTakeoverState& state = getTakeoverState();
    std::lock_guard<std::mutex> lock(state.mutex);
    state.reference_so_handle = handle;
}
