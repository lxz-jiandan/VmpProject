#include "zPatchbayDonor.h"

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
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

// 进入匿名命名空间，封装内部辅助函数。
namespace {

// 按状态映射 CLI 兼容退出码。
int mapPatchbayDonorExitCode(zPatchbayDonorStatus status) {
    // 成功返回 0。
    if (status == zPatchbayDonorStatus::ok) {
        return 0;
    }
    // 参数类错误返回 1。
    if (status == zPatchbayDonorStatus::invalidInput) {
        return 1;
    }
    // 加载/收集阶段错误返回 2。
    if (status == zPatchbayDonorStatus::loadFailed ||
        status == zPatchbayDonorStatus::collectFailed) {
        return 2;
    }
    // 其余规则/冲突/patch 错误返回 3。
    return 3;
}

// 统一写入结果结构。
void fillPatchbayDonorResult(zPatchbayDonorResult* outResult,
                             zPatchbayDonorStatus status,
                             const std::string& errorText,
                             size_t donorExportCount,
                             size_t inputExportCount,
                             size_t appendCount,
                             bool entryMode) {
    // 调用方不关心结果时可传空指针。
    if (outResult == nullptr) {
        return;
    }
    // 回填状态与兼容退出码。
    outResult->status = status;
    outResult->exitCode = mapPatchbayDonorExitCode(status);
    // 回填错误文本与统计信息。
    outResult->error = errorText;
    outResult->donorExportCount = donorExportCount;
    outResult->inputExportCount = inputExportCount;
    outResult->appendCount = appendCount;
    outResult->entryMode = entryMode;
}

// 构建冲突摘要文本（限制输出条数，避免日志过长）。
std::string buildConflictSummary(const std::vector<std::string>& duplicateExports) {
    // 冲突为空时返回空串。
    if (duplicateExports.empty()) {
        return "";
    }
    // 先写入总数。
    std::string summary = "export conflict between donor and vmengine: count=" +
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

// 结束匿名命名空间。
}  // namespace

// 运行 donor 导出 patch 流程（领域 API）。
bool runPatchbayExportAliasFromDonor(const zPatchbayDonorRequest& request,
                                     zPatchbayDonorResult* outResult) {
    // 先清空输出结果。
    fillPatchbayDonorResult(outResult,
                            zPatchbayDonorStatus::ok,
                            "",
                            0,
                            0,
                            0,
                            false);

    // 校验必填参数。
    if (request.inputSoPath.empty()) {
        fillPatchbayDonorResult(outResult,
                                zPatchbayDonorStatus::invalidInput,
                                "input so path is empty",
                                0,
                                0,
                                0,
                                false);
        return false;
    }
    if (request.donorSoPath.empty()) {
        fillPatchbayDonorResult(outResult,
                                zPatchbayDonorStatus::invalidInput,
                                "donor so path is empty",
                                0,
                                0,
                                0,
                                false);
        return false;
    }
    if (request.outputSoPath.empty()) {
        fillPatchbayDonorResult(outResult,
                                zPatchbayDonorStatus::invalidInput,
                                "output so path is empty",
                                0,
                                0,
                                0,
                                false);
        return false;
    }
    if (request.implSymbol.empty()) {
        fillPatchbayDonorResult(outResult,
                                zPatchbayDonorStatus::invalidInput,
                                "impl symbol is empty",
                                0,
                                0,
                                0,
                                false);
        return false;
    }

    // 输入文件不存在时直接失败。
    if (!vmp::base::file::fileExists(request.inputSoPath)) {
        fillPatchbayDonorResult(outResult,
                                zPatchbayDonorStatus::loadFailed,
                                "input so not found: " + request.inputSoPath,
                                0,
                                0,
                                0,
                                false);
        return false;
    }
    // donor 文件不存在时直接失败。
    if (!vmp::base::file::fileExists(request.donorSoPath)) {
        fillPatchbayDonorResult(outResult,
                                zPatchbayDonorStatus::loadFailed,
                                "donor so not found: " + request.donorSoPath,
                                0,
                                0,
                                0,
                                false);
        return false;
    }

    // 加载 donor ELF。
    vmp::elfkit::zElfReadFacade donorElf(request.donorSoPath.c_str());
    if (!donorElf.isLoaded()) {
        fillPatchbayDonorResult(outResult,
                                zPatchbayDonorStatus::loadFailed,
                                "failed to load donor ELF: " + request.donorSoPath,
                                0,
                                0,
                                0,
                                false);
        return false;
    }

    // 收集 donor 动态导出。
    std::vector<vmp::elfkit::PatchDynamicExportInfo> donorExports;
    std::string collectError;
    if (!donorElf.collectDefinedDynamicExportInfos(&donorExports, &collectError)) {
        fillPatchbayDonorResult(outResult,
                                zPatchbayDonorStatus::collectFailed,
                                "collect donor exports failed: " +
                                    (collectError.empty() ? std::string("(unknown)") : collectError),
                                donorExports.size(),
                                0,
                                0,
                                false);
        return false;
    }

    // only_fun_java 模式下过滤 donor 导出集合。
    if (request.onlyFunJava) {
        std::vector<vmp::elfkit::PatchDynamicExportInfo> filteredExports;
        filteredExports.reserve(donorExports.size());
        for (const vmp::elfkit::PatchDynamicExportInfo& exportInfo : donorExports) {
            if (isFunOrJavaSymbol(exportInfo.name)) {
                filteredExports.push_back(exportInfo);
            }
        }
        donorExports.swap(filteredExports);
    }

    // donor 导出为空时直接失败。
    if (donorExports.empty()) {
        fillPatchbayDonorResult(outResult,
                                zPatchbayDonorStatus::collectFailed,
                                "donor has no defined dynamic exports",
                                0,
                                0,
                                0,
                                false);
        return false;
    }

    // 加载 input ELF。
    vmp::elfkit::zElfReadFacade inputElf(request.inputSoPath.c_str());
    if (!inputElf.isLoaded()) {
        fillPatchbayDonorResult(outResult,
                                zPatchbayDonorStatus::loadFailed,
                                "failed to load input ELF: " + request.inputSoPath,
                                donorExports.size(),
                                0,
                                0,
                                false);
        return false;
    }

    // 收集 input 动态导出集合（用于命名校验和冲突检测）。
    std::vector<vmp::elfkit::PatchDynamicExportInfo> inputExportInfos;
    collectError.clear();
    if (!inputElf.collectDefinedDynamicExportInfos(&inputExportInfos, &collectError)) {
        fillPatchbayDonorResult(outResult,
                                zPatchbayDonorStatus::collectFailed,
                                "collect input exports failed: " +
                                    (collectError.empty() ? std::string("(unknown)") : collectError),
                                donorExports.size(),
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
        fillPatchbayDonorResult(outResult,
                                zPatchbayDonorStatus::namingRuleFailed,
                                ruleError.empty() ? std::string("(unknown)") : ruleError,
                                donorExports.size(),
                                inputExports.size(),
                                0,
                                false);
        return false;
    }

    // 构建 input 导出名集合，用于 donor 冲突检测。
    std::unordered_set<std::string> inputExportSet;
    inputExportSet.reserve(inputExports.size());
    for (const std::string& exportName : inputExports) {
        inputExportSet.insert(exportName);
    }

    // 严格模式：存在重名导出时直接失败。
    std::vector<std::string> duplicateExports;
    duplicateExports.reserve(donorExports.size());
    for (const vmp::elfkit::PatchDynamicExportInfo& donorExport : donorExports) {
        if (inputExportSet.find(donorExport.name) != inputExportSet.end()) {
            duplicateExports.push_back(donorExport.name);
        }
    }
    if (!duplicateExports.empty()) {
        fillPatchbayDonorResult(outResult,
                                zPatchbayDonorStatus::exportConflict,
                                buildConflictSummary(duplicateExports),
                                donorExports.size(),
                                inputExports.size(),
                                0,
                                false);
        return false;
    }

    // 构建 alias 对列表。
    std::vector<AliasPair> aliasPairs;
    aliasPairs.reserve(donorExports.size());
    const bool entryMode = isTakeoverEntryModeImpl(request.implSymbol.c_str());
    for (size_t exportIndex = 0; exportIndex < donorExports.size(); ++exportIndex) {
        AliasPair pair;
        pair.exportName = donorExports[exportIndex].name;
        pair.implName = entryMode
                            ? buildTakeoverEntrySymbolName(static_cast<uint32_t>(exportIndex))
                            : request.implSymbol;
        // route4 约定：用 st_size 承载 donor st_value 作为 export key。
        pair.exportKey = donorExports[exportIndex].value;
        aliasPairs.push_back(std::move(pair));
    }

    // 输出启动摘要日志。
    LOGI("patchbay donor start: donorExports=%zu inputExports=%zu toAppend=%zu impl=%s onlyFunJava=%d",
         donorExports.size(),
         inputExports.size(),
         aliasPairs.size(),
         request.implSymbol.c_str(),
         request.onlyFunJava ? 1 : 0);

    // 执行 patchbay 导出 patch。
    std::string patchError;
    if (!exportAliasSymbolsPatchbay(request.inputSoPath.c_str(),
                                    request.outputSoPath.c_str(),
                                    aliasPairs,
                                    request.allowValidateFail,
                                    &patchError)) {
        fillPatchbayDonorResult(outResult,
                                zPatchbayDonorStatus::patchApplyFailed,
                                patchError.empty() ? std::string("(unknown)") : patchError,
                                donorExports.size(),
                                inputExports.size(),
                                aliasPairs.size(),
                                entryMode);
        return false;
    }

    // 落盘后检查输出是否存在。
    if (!vmp::base::file::fileExists(request.outputSoPath)) {
        fillPatchbayDonorResult(outResult,
                                zPatchbayDonorStatus::outputMissing,
                                "patch output not found: " + request.outputSoPath,
                                donorExports.size(),
                                inputExports.size(),
                                aliasPairs.size(),
                                entryMode);
        return false;
    }

    // 输出成功日志。
    LOGI("patchbay donor success: input=%s donor=%s output=%s impl=%s append=%zu",
         request.inputSoPath.c_str(),
         request.donorSoPath.c_str(),
         request.outputSoPath.c_str(),
         request.implSymbol.c_str(),
         aliasPairs.size());

    // 成功回填结果。
    fillPatchbayDonorResult(outResult,
                            zPatchbayDonorStatus::ok,
                            "",
                            donorExports.size(),
                            inputExports.size(),
                            aliasPairs.size(),
                            entryMode);
    return true;
}
