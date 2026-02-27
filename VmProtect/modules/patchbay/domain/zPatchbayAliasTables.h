#ifndef VMPROTECT_PATCHBAY_ALIAS_TABLES_H
#define VMPROTECT_PATCHBAY_ALIAS_TABLES_H

// 引入 ELF 只读 facade（含 patchbay 所需类型）。
#include "zElfReadFacade.h"
// 引入 alias 对定义。
#include "zPatchbayTypes.h"

// 引入基础整型定义。
#include <cstdint>
// 引入错误描述字符串。
#include <string>
// 引入字节和符号数组容器。
#include <vector>

// alias 表构建输出结果。
struct AliasTableBuildResult {
    // 追加 alias 后的新 dynsym 条目数组。
    std::vector<Elf64_Sym> dynsymSymbols;
    // 追加 alias 名称后的新 dynstr 字节。
    std::vector<uint8_t> dynstrBytes;
    // 与 dynsym 对齐的新 versym 字节。
    std::vector<uint8_t> versymBytes;
    // dynsymSymbols 对应的原始字节串。
    std::vector<uint8_t> dynsymRawBytes;
    // 本次实际追加条目数。
    uint32_t appendedCount = 0;
    // dynsym 中需要在重构阶段回填 st_value 的条目绑定（symbolIndex -> symbolKey/soId）。
    std::vector<PendingTakeoverSymbolBinding> pendingTakeoverBindings;
    // 供合成跳板使用的 dispatch 目标地址（vm_takeover_dispatch_by_key）。
    uint64_t takeoverDispatchAddr = 0;
};

// 基于 aliasPairs 构建新 dynsym/dynstr/versym 表。
// 入参：
// - elf: 输入 ELF 访问对象。
// - required: 所需关键节信息。
// - aliasPairs: 需要追加的 alias 对。
// - out: 构建结果输出。
// - error: 可选错误描述输出。
// 返回：
// - true: 构建成功。
// - false: 构建失败。
bool buildPatchbayAliasTables(const vmp::elfkit::zElfReadFacade& elf,
                              const vmp::elfkit::PatchRequiredSections& required,
                              const std::vector<AliasPair>& aliasPairs,
                              AliasTableBuildResult* out,
                              std::string* error);

#endif // VMPROTECT_PATCHBAY_ALIAS_TABLES_H
