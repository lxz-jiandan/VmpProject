#ifndef VMPROTECT_PATCHBAY_EXPORT_H
#define VMPROTECT_PATCHBAY_EXPORT_H

// 引入 alias 对定义。
#include "zPatchbayTypes.h"

// 引入错误描述字符串。
#include <string>
// 引入 alias 列表容器。
#include <vector>

// 以 patchbay 流程导出 alias 符号。
// 入参：
// - inputPath: 输入 ELF 路径。
// - outputPath: 输出 ELF 路径。
// - aliasPairs: 需要追加的 alias 对列表。
// - error: 可选错误描述输出。
// 返回：
// - true: patch 成功。
// - false: 任一阶段失败。
bool exportAliasSymbolsPatchbay(const char* inputPath,
                                const char* outputPath,
                                const std::vector<AliasPair>& aliasPairs,
                                std::string* error);

#endif // VMPROTECT_PATCHBAY_EXPORT_H
