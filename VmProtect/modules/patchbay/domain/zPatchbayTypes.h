#ifndef VMPROTECT_PATCHBAY_TYPES_H
#define VMPROTECT_PATCHBAY_TYPES_H

// 引入基础整型定义。
#include <cstdint>
// 引入字符串类型。
#include <string>

// alias 对：表示“新增导出名 -> 路由键”的映射。
struct AliasPair {
    // 需要新增/补齐的导出名（对外可见符号）。
    std::string exportName;
    // 业务 key（当前来源为 origin.st_value）。
    uint64_t exportKey = 0;
    // 业务模块 ID（用于多 so 分发）。
    uint32_t soId = 0;
};

// 待补全的 takeover 绑定：
// - symbolIndex 指向 dynsym 中某个需要后续写回 st_value 的条目；
// - symbolKey 为该导出对应的业务 key；
// - soId 为业务模块 ID。
struct PendingTakeoverSymbolBinding {
    uint32_t symbolIndex = 0;
    uint64_t symbolKey = 0;
    uint32_t soId = 0;
};

#endif // VMPROTECT_PATCHBAY_TYPES_H

