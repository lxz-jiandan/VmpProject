// 防止头文件重复包含。
#pragma once

// 引入固定宽度整数。
#include <cstdint>
// 引入有序映射容器。
#include <map>
// 引入字符串类型。
#include <string>
// 引入动态数组容器。
#include <vector>

// 进入 pipeline 顶层命名空间。
namespace vmp {

// 主流程路线模式。
enum class PipelineMode {
    // 仅执行覆盖率分析与报告。
    kCoverage = 0,
    // 执行覆盖率与导出（不做 vmengine embed/patch）。
    kExport = 1,
    // 执行完整保护（覆盖率 + 导出 + vmengine embed/patch）。
    kProtect = 2,
};

// VmProtect 主流程配置。
// 该结构体由“默认值 + CLI 覆盖”共同构成最终运行参数。
struct VmProtectConfig {
    // 待保护输入 so 路径。
    std::string inputSo;
    // 输出目录路径。
    std::string outputDir = ".";
    // expand so 输出文件名。
    std::string expandedSo = "libdemo_expand.so";
    // 共享 branch 地址清单文件名。
    std::string sharedBranchFile = "branch_addr_list.txt";
    // 覆盖率报告文件名。
    std::string coverageReport = "coverage_report.md";
    // 需要处理的函数列表。
    std::vector<std::string> functions;
    // 是否分析全部函数（忽略函数列表）。
    bool analyzeAllFunctions = false;
    // 是否仅执行覆盖率阶段。
    bool coverageOnly = false;
    // 主流程路线模式。
    PipelineMode mode = PipelineMode::kExport;
    // vmengine so 路径（用于 embed）。
    std::string vmengineSo;
    // 加固后输出 so 路径。
    std::string outputSo;
    // patch origin so 路径。
    std::string patchOriginSo;
    // patch 使用的实现符号名。
    std::string patchImplSymbol = "vm_takeover_entry_0000";
    // 是否 patch origin 全部导出。
    bool patchAllExports = false;
    // patch 后验证失败时是否允许放行（默认严格，不放行）。
    bool patchAllowValidateFail = false;
};

// CLI 覆盖项集合。
// 每个字段对应一个命令行参数，Set 字段用于区分“未传入”和“传入 false”。
struct CliOverrides {
    // 是否显示帮助信息。
    bool showHelp = false;
    // 覆盖 inputSo。
    std::string inputSo;
    // 覆盖 outputDir。
    std::string outputDir;
    // 覆盖 expandedSo。
    std::string expandedSo;
    // 覆盖 sharedBranchFile。
    std::string sharedBranchFile;
    // 覆盖 coverageReport。
    std::string coverageReport;
    // 覆盖函数列表。
    std::vector<std::string> functions;
    // coverageOnly 是否被显式设置。
    bool coverageOnlySet = false;
    // coverageOnly 目标值。
    bool coverageOnly = false;
    // analyzeAll 是否被显式设置。
    bool analyzeAllSet = false;
    // analyzeAll 目标值。
    bool analyzeAll = false;
    // mode 是否被显式设置。
    bool modeSet = false;
    // mode 目标值。
    PipelineMode mode = PipelineMode::kExport;
    // 覆盖 vmengineSo。
    std::string vmengineSo;
    // 覆盖 outputSo。
    std::string outputSo;
    // 覆盖 patchOriginSo。
    std::string patchOriginSo;
    // 覆盖 patchImplSymbol。
    std::string patchImplSymbol;
    // patchAllExports 是否被显式设置。
    bool patchAllExportsSet = false;
    // patchAllExports 目标值。
    bool patchAllExports = false;
    // patchAllowValidateFail 是否被显式设置。
    bool patchAllowValidateFailSet = false;
    // patchAllowValidateFail 目标值。
    bool patchAllowValidateFail = false;
};

// 单个函数覆盖率行。
struct FunctionCoverageRow {
    // 函数名。
    std::string functionName;
    // 总指令数。
    uint64_t totalInstructions = 0;
    // 可支持指令数。
    uint64_t supportedInstructions = 0;
    // 不支持指令数。
    uint64_t unsupportedInstructions = 0;
    // 翻译是否成功。
    bool translateOk = false;
    // 翻译错误信息。
    std::string translateError;
};

// 覆盖率总面板。
struct CoverageBoard {
    // 全局总指令数。
    uint64_t totalInstructions = 0;
    // 全局支持指令数。
    uint64_t supportedInstructions = 0;
    // 全局不支持指令数。
    uint64_t unsupportedInstructions = 0;
    // 支持指令直方图（指令名 -> 次数）。
    std::map<std::string, uint64_t> supportedHistogram;
    // 不支持指令直方图（指令名 -> 次数）。
    std::map<std::string, uint64_t> unsupportedHistogram;
    // 每个函数的覆盖率明细行。
    std::vector<FunctionCoverageRow> functionRows;
};

// 默认函数列表常量。
extern const std::vector<std::string> kDefaultFunctions;

// 结束命名空间。
}  // namespace vmp



