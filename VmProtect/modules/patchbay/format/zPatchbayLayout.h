#ifndef VMPROTECT_PATCHBAY_LAYOUT_H
#define VMPROTECT_PATCHBAY_LAYOUT_H

// 引入 ELF 结构定义（Elf64_Ehdr/Elf64_Phdr 等）。
#include "zPatchElf.h"

// 引入错误描述字符串。
#include <string>
// 引入文件字节容器。
#include <vector>

// 校验输出 ELF 的 Program/Section 表是否满足 Android 装载约束。
// 入参：
// - fileBytes: 待校验 ELF 全量字节。
// - error: 可选错误文本输出。
// 返回：
// - true: 关键布局合法。
// - false: 任一布局约束不满足。
bool validateElfTablesForAndroid(const std::vector<uint8_t>& fileBytes, std::string* error);

#endif // VMPROTECT_PATCHBAY_LAYOUT_H

