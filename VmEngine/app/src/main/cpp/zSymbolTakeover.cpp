#include "zSymbolTakeover.h"

#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>

#include "generated/zTakeoverSymbols.generated.h"
#include "zLog.h"
#include "zVmEngine.h"

namespace {

struct zTakeoverState {
    std::mutex mutex;
    std::unordered_map<std::string, uint64_t> fun_addr_by_symbol;
    std::string active_so_name;
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

int fallbackBySymbolName(const char* symbol_name, int a, int b) {
    if (symbol_name == nullptr) {
        return 0;
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
    LOGE("[route_symbol_takeover] fallback missing for symbol=%s", symbol_name);
    return 0;
}

int dispatchByIdOrFallback(uint32_t symbol_id, int a, int b) {
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
    return dispatchByIdOrFallback(symbol_id, a, b);
}
