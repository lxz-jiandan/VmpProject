#include "zPatchbayOrigin.h"

// 引入 patch ELF 读取门面。
#include "zElfReadFacade.h"
// 引入 patchbay 主流程执行器。
#include "zPatchbayExport.h"
// 引入 patchbay 命名与槽位规则。
#include "zPatchbayRules.h"
// 引入文件存在性判断。
#include "zFile.h"
// 引入日志接口。
#include "zLog.h"

// 引入字符串与容器类型。
#include <algorithm>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

// 进入匿名命名空间，封装内部辅助函数。
namespace {

// 按状态映射 CLI 兼容退出码。
int mapPatchbayOriginExitCode(zPatchbayOriginStatus status) {
    // 成功返回 0。
    if (status == zPatchbayOriginStatus::ok) {
        return 0;
    }
    // 参数类错误返回 1。
    if (status == zPatchbayOriginStatus::invalidInput) {
        return 1;
    }
    // 加载/收集阶段错误返回 2。
    if (status == zPatchbayOriginStatus::loadFailed ||
        status == zPatchbayOriginStatus::collectFailed) {
        return 2;
    }
    // 其余规则/冲突/patch 错误返回 3。
    return 3;
}

// 统一写入结果结构。
void fillPatchbayOriginResult(zPatchbayOriginResult* outResult,
                             zPatchbayOriginStatus status,
                             const std::string& errorText,
                             size_t originExportCount,
                             size_t inputExportCount,
                             size_t appendCount,
                             bool keyMode) {
    // 调用方不关心结果时可传空指针。
    if (outResult == nullptr) {
        return;
    }
    // 回填状态与兼容退出码。
    outResult->status = status;
    outResult->exitCode = mapPatchbayOriginExitCode(status);
    // 回填错误文本与统计信息。
    outResult->error = errorText;
    outResult->originExportCount = originExportCount;
    outResult->inputExportCount = inputExportCount;
    outResult->appendCount = appendCount;
    outResult->keyMode = keyMode;
}

// 构建冲突摘要文本（限制输出条数，避免日志过长）。
std::string buildConflictSummary(const std::vector<std::string>& duplicateExports) {
    // 冲突为空时返回空串。
    if (duplicateExports.empty()) {
        return "";
    }
    // 先写入总数。
    std::string summary = "export conflict between origin and vmengine: count=" +
                          std::to_string(duplicateExports.size());
    // 最多拼接前 8 个样例名。
    constexpr size_t kDetailLimit = 8;
    const size_t detailCount =
        duplicateExports.size() < kDetailLimit ? duplicateExports.size() : kDetailLimit;
    for (size_t detailIndex = 0; detailIndex < detailCount; ++detailIndex) {
        summary += " [" + std::to_string(detailIndex) + "]=" + duplicateExports[detailIndex];
    }
    return summary;
}

// 对 origin 导出做稳定排序，避免 key 路由受 dynsym 原始顺序波动影响。
void sortOriginExportsForStableKeys(std::vector<vmp::elfkit::PatchDynamicExportInfo>* originExports) {
    if (originExports == nullptr || originExports->empty()) {
        return;
    }
    std::stable_sort(originExports->begin(),
                     originExports->end(),
                     [](const vmp::elfkit::PatchDynamicExportInfo& lhs,
                        const vmp::elfkit::PatchDynamicExportInfo& rhs) {
                         if (lhs.name != rhs.name) {
                             return lhs.name < rhs.name;
                         }
                         return lhs.value < rhs.value;
                     });
}

// 结束匿名命名空间。
}  // namespace

// 运行 origin 导出 patch 流程（领域 API）。
bool runPatchbayExportAliasFromOrigin(const zPatchbayOriginRequest& request,
                                     zPatchbayOriginResult* outResult) {
    // 先清空输出结果。
    fillPatchbayOriginResult(outResult,
                            zPatchbayOriginStatus::ok,
                            "",
                            0,
                            0,
                            0,
                            false);

    // 校验必填参数。
    if (request.inputSoPath.empty()) {
        fillPatchbayOriginResult(outResult,
                                zPatchbayOriginStatus::invalidInput,
                                "input so path is empty",
                                0,
                                0,
                                0,
                                false);
        return false;
    }
    if (request.originSoPath.empty()) {
        fillPatchbayOriginResult(outResult,
                                zPatchbayOriginStatus::invalidInput,
                                "origin so path is empty",
                                0,
                                0,
                                0,
                                false);
        return false;
    }
    if (request.outputSoPath.empty()) {
        fillPatchbayOriginResult(outResult,
                                zPatchbayOriginStatus::invalidInput,
                                "output so path is empty",
                                0,
                                0,
                                0,
                                false);
        return false;
    }
    // 输入文件不存在时直接失败。
    if (!vmp::base::file::fileExists(request.inputSoPath)) {
        fillPatchbayOriginResult(outResult,
                                zPatchbayOriginStatus::loadFailed,
                                "input so not found: " + request.inputSoPath,
                                0,
                                0,
                                0,
                                false);
        return false;
    }
    // origin 文件不存在时直接失败。
    if (!vmp::base::file::fileExists(request.originSoPath)) {
        fillPatchbayOriginResult(outResult,
                                zPatchbayOriginStatus::loadFailed,
                                "origin so not found: " + request.originSoPath,
                                0,
                                0,
                                0,
                                false);
        return false;
    }

    // 加载 origin ELF。
    vmp::elfkit::zElfReadFacade originElf(request.originSoPath.c_str());
    if (!originElf.isLoaded()) {
        fillPatchbayOriginResult(outResult,
                                zPatchbayOriginStatus::loadFailed,
                                "failed to load origin ELF: " + request.originSoPath,
                                0,
                                0,
                                0,
                                false);
        return false;
    }

    // 收集 origin 动态导出。
    std::vector<vmp::elfkit::PatchDynamicExportInfo> originExports;
    std::string collectError;
    if (!originElf.collectDefinedDynamicExportInfos(&originExports, &collectError)) {
        fillPatchbayOriginResult(outResult,
                                zPatchbayOriginStatus::collectFailed,
                                "collect origin exports failed: " +
                                    (collectError.empty() ? std::string("(unknown)") : collectError),
                                originExports.size(),
                                0,
                                0,
                                false);
        return false;
    }

    // 统一排序后再写入 alias，确保不同构建机/链接顺序下结果稳定。
    sortOriginExportsForStableKeys(&originExports);

    // origin 导出为空时直接失败。
    if (originExports.empty()) {
        fillPatchbayOriginResult(outResult,
                                zPatchbayOriginStatus::collectFailed,
                                "origin has no defined dynamic exports",
                                0,
                                0,
                                0,
                                false);
        return false;
    }

    // 加载 input ELF。
    vmp::elfkit::zElfReadFacade inputElf(request.inputSoPath.c_str());
    if (!inputElf.isLoaded()) {
        fillPatchbayOriginResult(outResult,
                                zPatchbayOriginStatus::loadFailed,
                                "failed to load input ELF: " + request.inputSoPath,
                                originExports.size(),
                                0,
                                0,
                                false);
        return false;
    }

    // 收集 input 动态导出集合（用于命名校验和冲突检测）。
    std::vector<vmp::elfkit::PatchDynamicExportInfo> inputExportInfos;
    collectError.clear();
    if (!inputElf.collectDefinedDynamicExportInfos(&inputExportInfos, &collectError)) {
        fillPatchbayOriginResult(outResult,
                                zPatchbayOriginStatus::collectFailed,
                                "collect input exports failed: " +
                                    (collectError.empty() ? std::string("(unknown)") : collectError),
                                originExports.size(),
                                0,
                                0,
                                false);
        return false;
    }

    // 投影 input 导出名列表。
    std::vector<std::string> inputExports;
    inputExports.reserve(inputExportInfos.size());
    for (const vmp::elfkit::PatchDynamicExportInfo& exportInfo : inputExportInfos) {
        inputExports.push_back(exportInfo.name);
    }

    // 校验 vmengine 现有导出命名规则。
    std::string ruleError;
    if (!validateVmengineExportNamingRules(inputExports, &ruleError)) {
        fillPatchbayOriginResult(outResult,
                                zPatchbayOriginStatus::namingRuleFailed,
                                ruleError.empty() ? std::string("(unknown)") : ruleError,
                                originExports.size(),
                                inputExports.size(),
                                0,
                                false);
        return false;
    }

    // 构建 input 导出名集合，用于 origin 冲突检测。
    std::unordered_set<std::string> inputExportSet;
    inputExportSet.reserve(inputExports.size());
    for (const std::string& exportName : inputExports) {
        inputExportSet.insert(exportName);
    }

    // 严格模式：存在重名导出时直接失败。
    std::vector<std::string> duplicateExports;
    duplicateExports.reserve(originExports.size());
    for (const vmp::elfkit::PatchDynamicExportInfo& originExport : originExports) {
        if (inputExportSet.find(originExport.name) != inputExportSet.end()) {
            duplicateExports.push_back(originExport.name);
        }
    }
    if (!duplicateExports.empty()) {
        fillPatchbayOriginResult(outResult,
                                zPatchbayOriginStatus::exportConflict,
                                buildConflictSummary(duplicateExports),
                                originExports.size(),
                                inputExports.size(),
                                0,
                                false);
        return false;
    }

    // 构建 alias 对列表。
    std::vector<AliasPair> aliasPairs;
    aliasPairs.reserve(originExports.size());
    const bool keyMode = true;
    constexpr uint32_t kDefaultTakeoverSoId = 1U;
    for (size_t exportIndex = 0; exportIndex < originExports.size(); ++exportIndex) {
        AliasPair pair;
        pair.exportName = originExports[exportIndex].name;
        // route4 约定：使用 origin st_value 作为导出 key。
        pair.exportKey = originExports[exportIndex].value;
        // 当前单模块默认 soId=1，后续多模块可在 pipeline 中分配独立 soId。
        pair.soId = kDefaultTakeoverSoId;
        aliasPairs.push_back(std::move(pair));
    }

    // 输出启动摘要日志。
    LOGI("patchbay origin start: originExports=%zu inputExports=%zu toAppend=%zu mode=%s",
         originExports.size(),
         inputExports.size(),
         aliasPairs.size(),
         keyMode ? "key" : "unknown");

    // 执行 patchbay 导出 patch。
    std::string patchError;
    if (!exportAliasSymbolsPatchbay(request.inputSoPath.c_str(),
                                    request.outputSoPath.c_str(),
                                    aliasPairs,
                                    &patchError)) {
        fillPatchbayOriginResult(outResult,
                                zPatchbayOriginStatus::patchApplyFailed,
                                patchError.empty() ? std::string("(unknown)") : patchError,
                                 originExports.size(),
                                 inputExports.size(),
                                 aliasPairs.size(),
                                 keyMode);
        return false;
    }

    // 落盘后检查输出是否存在。
    if (!vmp::base::file::fileExists(request.outputSoPath)) {
        fillPatchbayOriginResult(outResult,
                                zPatchbayOriginStatus::outputMissing,
                                "patch output not found: " + request.outputSoPath,
                                originExports.size(),
                                inputExports.size(),
                                aliasPairs.size(),
                                keyMode);
        return false;
    }

    // 输出成功日志。
    LOGI("patchbay origin success: input=%s origin=%s output=%s mode=%s append=%zu",
         request.inputSoPath.c_str(),
         request.originSoPath.c_str(),
         request.outputSoPath.c_str(),
         keyMode ? "key" : "unknown",
         aliasPairs.size());

    // 成功回填结果。
    fillPatchbayOriginResult(outResult,
                            zPatchbayOriginStatus::ok,
                            "",
                            originExports.size(),
                            inputExports.size(),
                            aliasPairs.size(),
                            keyMode);
    return true;
}

