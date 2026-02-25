#ifndef VMPROTECT_PATCHBAY_PATCH_APPLY_H
#define VMPROTECT_PATCHBAY_PATCH_APPLY_H

// 引入 patchbay API 中的节信息定义。
#include "zPatchbayApi.h"

// 引入基础整型定义。
#include <cstdint>
// 引入错误描述字符串。
#include <string>
// 引入字节数组容器。
#include <vector>

// 将新构建的 dynsym/dynstr/hash 等表写入 patchbay 区并更新动态指针。
// 入参：
// - required: input ELF 中 patch 所需关键节信息。
// - inputPath: 输入 ELF 路径。
// - outputPath: 输出 ELF 路径。
// - newDynsymBytes: 新 dynsym 原始字节。
// - newDynstr: 新 dynstr 字节。
// - newVersym: 新 versym 字节。
// - newGnuHash: 新 gnu hash 字节。
// - newSysvHash: 新 sysv hash 字节（无 .hash 时可为空）。
// - slotUsedHint: 预计使用槽位数（用于更新头字段）。
// - allowValidateFail: 是否允许布局校验失败继续输出。
// - handled: 输出是否已由 patchbay 路径处理完成。
// - error: 可选错误描述输出。
// 返回：
// - true: 处理成功（无论 handled 为 true/false）。
// - false: 处理失败。
bool applyPatchbayAliasPayload(const vmp::elfkit::PatchRequiredSections& required,
                               const char* inputPath,
                               const char* outputPath,
                               const std::vector<uint8_t>& newDynsymBytes,
                               const std::vector<uint8_t>& newDynstr,
                               const std::vector<uint8_t>& newVersym,
                               const std::vector<uint8_t>& newGnuHash,
                               const std::vector<uint8_t>& newSysvHash,
                               uint32_t slotUsedHint,
                               bool allowValidateFail,
                               bool* handled,
                               std::string* error);

#endif // VMPROTECT_PATCHBAY_PATCH_APPLY_H

