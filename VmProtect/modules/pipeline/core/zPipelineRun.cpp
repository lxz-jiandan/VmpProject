// 引入运行编排公共接口。
#include "zPipelineRun.h"

// 引入动态数组容器。
#include <vector>

// 引入文件工具（exists/mkdir/read/write）。
#include "zFile.h"
// 引入日志工具。
#include "zLog.h"
// 引入去重工具函数。
#include "zPipelineCli.h"

// 进入 pipeline 命名空间。
namespace vmp {

// 判断当前配置是否触发“加固路线”。
// 约定：vmengine/output/donor 任一参数存在，即进入加固模式。
bool isHardeningRoute(const VmProtectConfig& config) {
    return !config.vmengineSo.empty() ||
           !config.outputSo.empty() ||
           !config.patchDonorSo.empty();
}

// 初始化默认配置。
void initDefaultConfig(VmProtectConfig& config) {
    // 写入默认函数列表。
    config.functions = kDefaultFunctions;
    // 默认列表去重，保证顺序稳定。
    deduplicateKeepOrder(config.functions);
}

// 把 CLI 覆盖项合并到最终配置。
void applyCliOverrides(const CliOverrides& cli, VmProtectConfig& config) {
    // 输入 so 覆盖。
    if (!cli.inputSo.empty()) {
        config.inputSo = cli.inputSo;
    }
    // 输出目录覆盖。
    if (!cli.outputDir.empty()) {
        config.outputDir = cli.outputDir;
    }
    // expanded so 文件名覆盖。
    if (!cli.expandedSo.empty()) {
        config.expandedSo = cli.expandedSo;
    }
    // 共享 branch 文件名覆盖。
    if (!cli.sharedBranchFile.empty()) {
        config.sharedBranchFile = cli.sharedBranchFile;
    }
    // vmengine so 覆盖。
    if (!cli.vmengineSo.empty()) {
        config.vmengineSo = cli.vmengineSo;
    }
    // output so 覆盖。
    if (!cli.outputSo.empty()) {
        config.outputSo = cli.outputSo;
    }
    // donor so 覆盖。
    if (!cli.patchDonorSo.empty()) {
        config.patchDonorSo = cli.patchDonorSo;
    }
    // impl symbol 覆盖。
    if (!cli.patchImplSymbol.empty()) {
        config.patchImplSymbol = cli.patchImplSymbol;
    }
    // patchAllExports 显式覆盖。
    if (cli.patchAllExportsSet) {
        config.patchAllExports = cli.patchAllExports;
    }
    // patchAllowValidateFail 显式覆盖。
    if (cli.patchAllowValidateFailSet) {
        config.patchAllowValidateFail = cli.patchAllowValidateFail;
    }
    // coverage 报告文件名覆盖。
    if (!cli.coverageReport.empty()) {
        config.coverageReport = cli.coverageReport;
    }
    // 函数列表覆盖。
    if (!cli.functions.empty()) {
        config.functions = cli.functions;
    }
    // coverageOnly 模式覆盖。
    if (cli.coverageOnlySet) {
        config.coverageOnly = cli.coverageOnly;
    }
    // analyzeAll 覆盖。
    if (cli.analyzeAllSet) {
        config.analyzeAllFunctions = cli.analyzeAll;
    }
}

// 校验配置合法性。
bool validateConfig(const VmProtectConfig& config, const CliOverrides& cli) {
    // 根据最终配置判断是否为加固路线。
    const bool hardeningRoute = isHardeningRoute(config);
    // 输入 so 必填。
    if (config.inputSo.empty()) {
        LOGE("input so is empty (use --input-so)");
        return false;
    }
    // 加固路线：vmengine so 必须显式传入。
    if (hardeningRoute && config.vmengineSo.empty()) {
        LOGE("hardening route requires --vmengine-so (vmengine so path)");
        return false;
    }
    // 加固路线：output so 必须显式传入，不允许默认回写/推导。
    if (hardeningRoute && config.outputSo.empty()) {
        LOGE("hardening route requires --output-so (protected output so path)");
        return false;
    }
    // 加固路线：函数符号必须显式传入，不允许走内置默认函数集。
    if (hardeningRoute && cli.functions.empty()) {
        LOGE("hardening route requires explicit --function <symbol> (repeatable)");
        return false;
    }
    // 输入 so 必须存在。
    if (!base::file::fileExists(config.inputSo)) {
        LOGE("input so not found: %s", config.inputSo.c_str());
        return false;
    }
    // 指定 vmengine so 时必须存在。
    if (!config.vmengineSo.empty() && !base::file::fileExists(config.vmengineSo)) {
        LOGE("vmengine so not found: %s", config.vmengineSo.c_str());
        return false;
    }
    // 指定 donor 时必须同时指定 vmengine so。
    if (!config.patchDonorSo.empty() && config.vmengineSo.empty()) {
        LOGE("patch options require --vmengine-so");
        return false;
    }
    // donor so 必须存在。
    if (!config.patchDonorSo.empty() && !base::file::fileExists(config.patchDonorSo)) {
        LOGE("patch donor so not found: %s", config.patchDonorSo.c_str());
        return false;
    }
    // 输出目录不存在时尝试创建。
    if (!base::file::ensureDirectory(config.outputDir)) {
        LOGE("failed to create output dir: %s", config.outputDir.c_str());
        return false;
    }
    return true;
}

// 构建最终函数名列表。
std::vector<std::string> buildFunctionNameList(const VmProtectConfig& config,
                                               elfkit::ElfImage& elf) {
    // 输出函数名列表。
    std::vector<std::string> functionNames;
    // analyzeAll 模式：从 ELF 中抓取全部函数。
    if (config.analyzeAllFunctions) {
        // 获取函数视图列表。
        const std::vector<elfkit::FunctionView> functionViews = elf.getFunctions();
        // 预分配容量。
        functionNames.reserve(functionViews.size());
        // 按顺序提取非空函数名。
        for (const elfkit::FunctionView& function : functionViews) {
            if (!function.getName().empty()) {
                functionNames.push_back(function.getName());
            }
        }
    } else {
        // 否则直接使用配置中的函数列表。
        functionNames = config.functions;
    }
    // 去重且保留原顺序。
    deduplicateKeepOrder(functionNames);
    return functionNames;
}

// 结束命名空间。
}  // namespace vmp


