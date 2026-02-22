/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - 符号接管模块接口声明。
 * - 加固链路位置：route4 L2 接口层。
 * - 输入：接管配置与映射。
 * - 输出：dispatch 能力与状态查询。
 */
#ifndef Z_SYMBOL_TAKEOVER_H
#define Z_SYMBOL_TAKEOVER_H

#include <cstddef>
#include <cstdint>

struct zTakeoverSymbolEntry {
    const char* symbol_name = nullptr;  // 需要接管的导出符号名（如 fun_add）。
    uint64_t fun_addr = 0;              // 对应 VM 函数入口地址（离线阶段生成）。
};

struct zTakeoverConfig {
    const char* primary_so_name = nullptr;   // 主库名，通常是被替换后的 libdemo.so。
    const char* fallback_so_name = nullptr;  // 兜底库名，通常是 libdemo_ref.so。
};

// 初始化接管映射表。成功后汇编桩会通过 dispatch 路径转发到 VM 函数或 fallback。
bool zSymbolTakeoverInit(
    const zTakeoverConfig& config,
    const zTakeoverSymbolEntry* entries,
    size_t entry_count
);

// 清理运行态接管状态（映射、句柄、缓存），用于回归/重复初始化场景。
void zSymbolTakeoverClear();

// 当前接管模块是否已经初始化且可分发。
bool zSymbolTakeoverIsReady();

// 返回当前生效的 so 名称（主库或兜底库），便于日志与调试输出。
const char* zSymbolTakeoverActiveSoName();

// 返回当前接管符号数量。
size_t zSymbolTakeoverSymbolCount();

// 查询第 index 个接管符号名（用于 UI/日志枚举）。
const char* zSymbolTakeoverSymbolNameAt(size_t index);

// 以统一 ABI 分发二元整数函数调用（demo 回归阶段主要验证该路径）。
bool zSymbolTakeoverDispatchBinary(const char* symbol_name, int a, int b, int* out_result);

// 汇编符号桩统一跳转到该入口（a,b 保持在 x0/x1，symbol_id 走 w2）。
extern "C" int z_takeover_dispatch_by_id(int a, int b, uint32_t symbol_id);

#endif // Z_SYMBOL_TAKEOVER_H
