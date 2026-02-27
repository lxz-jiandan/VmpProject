#include "zPatchbayExport.h"

// 引入 patch ELF 访问 API。
#include "zElfReadFacade.h"
// 引入 alias 表构建器。
#include "zPatchbayAliasTables.h"
// 引入 hash 重建器。
#include "zPatchbayHash.h"
// 引入 patchbay 落盘执行器。
#include "zPatchbayPatchApply.h"
// 引入日志接口。
#include "zLog.h"

// 引入字符串类型。
#include <string>
// 引入数组容器。
#include <vector>

// patchbay 主流程：构建 alias 表并写回 ELF。
bool exportAliasSymbolsPatchbay(const char* inputPath,
                                const char* outputPath,
                                const std::vector<AliasPair>& aliasPairs,
                                std::string* error) {
    // 入参校验：输入路径、输出路径、alias 列表都必须有效。
    if (inputPath == nullptr || outputPath == nullptr || aliasPairs.empty()) {
        if (error != nullptr) {
            *error = "invalid input/output/alias list";
        }
        return false;
    }

    // 加载输入 ELF。
    vmp::elfkit::zElfReadFacade elf(inputPath);
    if (!elf.isLoaded()) {
        if (error != nullptr) {
            *error = "failed to load input elf";
        }
        return false;
    }

    // 查询 patch 所需关键节信息：dynsym/dynstr/versym/hash/dynamic。
    vmp::elfkit::PatchRequiredSections required;
    if (!elf.queryRequiredSections(&required, error)) {
        return false;
    }

    // 构建追加 alias 后的新 dynsym/dynstr/versym。
    AliasTableBuildResult buildResult;
    if (!buildPatchbayAliasTables(elf, required, aliasPairs, &buildResult, error)) {
        return false;
    }

    // 重建 gnu hash。
    std::vector<uint8_t> newGnuHash =
        buildGnuHashPayloadFromBytes(buildResult.dynsymSymbols, buildResult.dynstrBytes);
    if (newGnuHash.empty()) {
        if (error != nullptr) {
            *error = "failed to build .gnu.hash payload";
        }
        return false;
    }

    // 若输入 ELF 存在 .hash，则同步重建 sysv hash。
    std::vector<uint8_t> newSysvHash;
    if (required.hasHash) {
        newSysvHash = buildSysvHashPayloadFromBytes(buildResult.dynsymSymbols, buildResult.dynstrBytes);
        if (newSysvHash.empty()) {
            if (error != nullptr) {
                *error = "failed to build .hash payload";
            }
            return false;
        }
    }

    // 执行单一路径落盘（仅 ELF 重建）。
    if (!applyPatchbayAliasPayload(required,
                                   inputPath,
                                   outputPath,
                                   buildResult.dynsymRawBytes,
                                   buildResult.dynstrBytes,
                                   buildResult.versymBytes,
                                   newGnuHash,
                                   newSysvHash,
                                   buildResult.pendingTakeoverBindings,
                                   buildResult.takeoverDispatchAddr,
                                   error)) {
        return false;
    }
    return true;
}
