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
    uint32_t entryId = 0;   // 跳板 entry ID（由 vm_takeover_entry_xxxx 注入到 w2）。
    uint64_t funAddr = 0;   // 对应 VM 函数入口地址（route4 中等价于 origin 导出 st_value）。
};

// 初始化接管映射表：绑定主执行 so 与 entryId -> funAddr。
bool zSymbolTakeoverInit(
    const char* primarySoName,
    const zTakeoverSymbolEntry* entries,
    size_t entryCount
);

// 清理运行态接管状态（映射、句柄、缓存），用于回归/重复初始化场景。
void zSymbolTakeoverClear();

// 汇编符号桩统一跳转到该入口（a,b 保持在 x0/x1，symbol_id 走 w2）。
extern "C" int vm_takeover_dispatch_by_id(int a, int b, uint32_t symbol_id);

#endif // Z_SYMBOL_TAKEOVER_H

