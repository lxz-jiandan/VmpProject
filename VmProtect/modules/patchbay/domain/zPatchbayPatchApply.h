#ifndef VMPROTECT_PATCHBAY_PATCH_APPLY_H
#define VMPROTECT_PATCHBAY_PATCH_APPLY_H

// 引入 ELF 只读 facade（包含 patchbay 节快照类型定义）。
#include "zElfReadFacade.h"
// 引入 patchbay 领域类型（含 PendingTakeoverSymbolBinding）。
#include "zPatchbayTypes.h"

// 引入基础整型定义。
#include <cstdint>
// 引入错误描述字符串。
#include <string>
// 引入字节数组容器。
#include <vector>

// 将新构建的 dynsym/dynstr/hash 等表通过 ELF 重建路径落盘并更新动态指针。
// 入参：
// - required: input ELF 中 patch 所需关键节信息。
// - inputPath: 输入 ELF 路径。
// - outputPath: 输出 ELF 路径。
// - newDynsymBytes: 新 dynsym 原始字节。
// - newDynstr: 新 dynstr 字节。
// - newVersym: 新 versym 字节。
// - newGnuHash: 新 gnu hash 字节。
// - newSysvHash: 新 sysv hash 字节（无 .hash 时可为空）。
// - pendingTakeoverBindings: dynsym 中待回填槽位绑定（symbolIndex -> entryId）。
// - takeoverDispatchAddr: 合成槽位跳板的 dispatch 目标地址。
// - allowValidateFail: 是否允许布局校验失败继续输出。
// - error: 可选错误描述输出。
// 返回：
// - true: 处理成功。
// - false: 处理失败。
bool applyPatchbayAliasPayload(const vmp::elfkit::PatchRequiredSections& required,
                               const char* inputPath,
                               const char* outputPath,
                               const std::vector<uint8_t>& newDynsymBytes,
                               const std::vector<uint8_t>& newDynstr,
                               const std::vector<uint8_t>& newVersym,
                               const std::vector<uint8_t>& newGnuHash,
                               const std::vector<uint8_t>& newSysvHash,
                               const std::vector<PendingTakeoverSymbolBinding>& pendingTakeoverBindings,
                               uint64_t takeoverDispatchAddr,
                               bool allowValidateFail,
                               std::string* error);

#endif // VMPROTECT_PATCHBAY_PATCH_APPLY_H
