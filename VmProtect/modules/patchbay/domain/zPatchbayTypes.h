#ifndef VMPROTECT_PATCHBAY_TYPES_H
#define VMPROTECT_PATCHBAY_TYPES_H

// 引入基础整型定义。
#include <cstdint>
// 引入字符串类型。
#include <string>

// alias 对：表示“新增导出名 -> 实现符号名”的映射。
struct AliasPair {
    // 需要新增/补齐的导出名（对外可见符号）。
    std::string exportName;
    // exportName 最终要指向的实现符号名。
    std::string implName;
    // 若非 0，则写入新增符号 st_size（用于承载 key=origin.st_value）。
    uint64_t exportKey = 0;
};

// 待补全的 takeover 绑定：
// - symbolIndex 指向 dynsym 中某个需要后续写回 st_value 的条目；
// - entryId 表示该条目应绑定到哪个 takeover 槽位跳板地址。
struct PendingTakeoverSymbolBinding {
    uint32_t symbolIndex = 0;
    uint32_t entryId = 0;
};

#endif // VMPROTECT_PATCHBAY_TYPES_H

