#ifndef Z_SYMBOL_TAKEOVER_H
#define Z_SYMBOL_TAKEOVER_H

#include <cstddef>
#include <cstdint>

struct zTakeoverSymbolEntry {
    const char* symbol_name = nullptr;
    uint64_t fun_addr = 0;
};

struct zTakeoverConfig {
    const char* primary_so_name = nullptr;
    const char* fallback_so_name = nullptr;
};

bool zSymbolTakeoverInit(
    const zTakeoverConfig& config,
    const zTakeoverSymbolEntry* entries,
    size_t entry_count
);

void zSymbolTakeoverClear();

bool zSymbolTakeoverIsReady();

const char* zSymbolTakeoverActiveSoName();

size_t zSymbolTakeoverSymbolCount();

const char* zSymbolTakeoverSymbolNameAt(size_t index);

bool zSymbolTakeoverDispatchBinary(const char* symbol_name, int a, int b, int* out_result);

// 汇编符号桩统一跳转到该入口（a,b 保持在 x0/x1，symbol_id 走 w2）。
extern "C" int z_takeover_dispatch_by_id(int a, int b, uint32_t symbol_id);

#endif // Z_SYMBOL_TAKEOVER_H
