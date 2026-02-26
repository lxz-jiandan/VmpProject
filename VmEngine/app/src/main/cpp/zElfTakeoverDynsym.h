#pragma once

// std::string。
#include <string>
// std::vector。
#include <vector>

// zTakeoverSymbolEntry 定义。
#include "zSymbolTakeover.h"

// 从 patched vmengine so 的 dynsym/dynstr 中恢复 takeover 条目：
// - 输入：so 路径；
// - 输出：entryId -> key 的条目列表。
bool zElfRecoverTakeoverEntriesFromPatchedSo(
    const std::string& soPath,
    std::vector<zTakeoverSymbolEntry>& outEntries
);
