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
// 约定：由显式 mode 控制。
bool isProtectRoute(const VmProtectConfig& config) {
    return config.mode == PipelineMode::kProtect;
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
    // 路线模式显式覆盖。
    if (cli.modeSet) {
        config.mode = cli.mode;
    }
    // vmengine so 覆盖。
    if (!cli.vmengineSo.empty()) {
        config.vmengineSo = cli.vmengineSo;
    }
    // output so 覆盖。
    if (!cli.outputSo.empty()) {
        config.outputSo = cli.outputSo;
    }
    // origin so 覆盖。
    if (!cli.patchOriginSo.empty()) {
        config.patchOriginSo = cli.patchOriginSo;
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
        // 兼容旧参数：仅在未显式设置 --mode 时，把 --coverage-only 映射为 coverage 模式。
        if (cli.coverageOnly && !cli.modeSet) {
            config.mode = PipelineMode::kCoverage;
        }
    }
    // analyzeAll 覆盖。
    if (cli.analyzeAllSet) {
        config.analyzeAllFunctions = cli.analyzeAll;
    }
}

// 校验配置合法性。
bool validateConfig(const VmProtectConfig& config, const CliOverrides& cli) {
    // 是否携带了保护参数组（由参数内容判断，不代表实际运行模式）。
    const bool hasProtectArgs = !config.vmengineSo.empty() ||
                                !config.outputSo.empty() ||
                                !config.patchOriginSo.empty();
    // 输入 so 必填。
    if (config.inputSo.empty()) {
        LOGE("input so is empty (use --input-so)");
        return false;
    }

    // --mode 与 --coverage-only 同时出现时，要求语义一致。
    if (cli.modeSet && cli.coverageOnlySet && cli.coverageOnly &&
        cli.mode != PipelineMode::kCoverage) {
        LOGE("--coverage-only conflicts with --mode (use --mode coverage or remove --coverage-only)");
        return false;
    }

    // coverage/export 模式下，不接受加固参数，避免“参数触发路线”的隐式行为。
    if (config.mode == PipelineMode::kCoverage && hasProtectArgs) {
        LOGE("mode=coverage does not allow --vmengine-so/--output-so/--patch-origin-so");
        return false;
    }
    if (config.mode == PipelineMode::kExport && hasProtectArgs) {
        LOGE("mode=export does not allow protect args; use --mode protect");
        return false;
    }

    // protect 模式：关键参数必须显式给出。
    if (isProtectRoute(config) && config.vmengineSo.empty()) {
        LOGE("mode=protect requires --vmengine-so");
        return false;
    }
    if (isProtectRoute(config) && config.outputSo.empty()) {
        LOGE("mode=protect requires --output-so");
        return false;
    }
    if (isProtectRoute(config) && cli.functions.empty()) {
        LOGE("mode=protect requires explicit --function <symbol> (repeatable)");
        return false;
    }

    // 输入 so 必须存在。
    if (!base::file::fileExists(config.inputSo)) {
        LOGE("input so not found: %s", config.inputSo.c_str());
        return false;
    }
    // protect 模式下 vmengine so 必须存在。
    if (isProtectRoute(config) && !base::file::fileExists(config.vmengineSo)) {
        LOGE("vmengine so not found: %s", config.vmengineSo.c_str());
        return false;
    }

    // origin so（可选）存在性校验。
    if (!config.patchOriginSo.empty() && !base::file::fileExists(config.patchOriginSo)) {
        LOGE("patch origin so not found: %s", config.patchOriginSo.c_str());
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



