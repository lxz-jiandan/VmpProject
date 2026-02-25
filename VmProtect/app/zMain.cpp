/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - VmProtect CLI 主入口：解析参数、构建覆盖率、导出保护包、可选 host 注入/patch。
 * - 加固链路位置：离线阶段入口（route4 上游）。
 * - 输入：原始 arm64 so + 函数清单/命令行配置。
 * - 输出：coverage_report、函数 txt/bin、branch_addr_list、expanded/host so。
 */

// 文件系统工具（remove / path）。
#include <filesystem>
// 错误输出流。
#include <iostream>
// std::string。
#include <string>
// std::vector。
#include <vector>

// ELF 读取与函数视图。
#include "zElfKit.h"
// patchbay 子命令入口。
#include "zPatchbayEntry.h"
// 文件存在/目录创建等工具。
#include "zIoUtils.h"
// 日志。
#include "zLog.h"
// CLI 解析与 usage。
#include "zPipelineCli.h"
// 覆盖率构建/输出。
#include "zPipelineCoverage.h"
// 导出保护包。
#include "zPipelineExport.h"
// patch 相关流程。
#include "zPipelinePatch.h"
// 配置结构与常量。
#include "zPipelineTypes.h"

// 文件系统命名空间别名。
namespace fs = std::filesystem;

namespace vmp {

namespace {

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
    // host so 覆盖。
    if (!cli.hostSo.empty()) {
        config.hostSo = cli.hostSo;
    }
    // final so 覆盖。
    if (!cli.finalSo.empty()) {
        config.finalSo = cli.finalSo;
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
bool validateConfig(const VmProtectConfig& config) {
    // 输入 so 必填。
    if (config.inputSo.empty()) {
        LOGE("input so is empty (use --input-so)");
        return false;
    }
    // 输入 so 必须存在。
    if (!fileExists(config.inputSo)) {
        LOGE("input so not found: %s", config.inputSo.c_str());
        return false;
    }
    // 指定 host so 时必须存在。
    if (!config.hostSo.empty() && !fileExists(config.hostSo)) {
        LOGE("host so not found: %s", config.hostSo.c_str());
        return false;
    }
    // 指定 donor 时必须同时指定 host。
    if (!config.patchDonorSo.empty() && config.hostSo.empty()) {
        LOGE("patch options require hostSo (--host-so)");
        return false;
    }
    // donor so 必须存在。
    if (!config.patchDonorSo.empty() && !fileExists(config.patchDonorSo)) {
        LOGE("patch donor so not found: %s", config.patchDonorSo.c_str());
        return false;
    }
    // 输出目录不存在时尝试创建。
    if (!ensureDirectory(config.outputDir)) {
        LOGE("failed to create output dir: %s", config.outputDir.c_str());
        return false;
    }
    return true;
}

// 构建最终函数名列表。
std::vector<std::string> buildFunctionNameList(const VmProtectConfig& config, elfkit::ElfImage& elf) {
    // 输出函数名列表。
    std::vector<std::string> functionNames;
    // analyzeAll 模式：从 ELF 中抓取全部函数。
    if (config.analyzeAllFunctions) {
        // 获取函数视图列表。
        const std::vector<elfkit::FunctionView> list = elf.listFunctions();
        // 预分配容量。
        functionNames.reserve(list.size());
        // 按顺序提取非空函数名。
        for (const elfkit::FunctionView& function : list) {
            if (!function.name().empty()) {
                functionNames.push_back(function.name());
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

// 执行覆盖率流程并写出报告。
bool runCoverageFlow(const VmProtectConfig& config,
                     const std::vector<std::string>& functionNames,
                     const std::vector<elfkit::FunctionView>& functions) {
    // 覆盖率看板对象。
    CoverageBoard board;
    // 根据“请求函数名 + 实际解析结果”构建看板。
    if (!buildCoverageBoard(functionNames, functions, board)) {
        return false;
    }

    // 组合 coverage 报告输出路径。
    const std::string coverageReportPath = joinOutputPath(config, config.coverageReport);
    // 落盘覆盖率报告。
    if (!writeCoverageReport(coverageReportPath, board)) {
        LOGE("failed to write coverage report: %s", coverageReportPath.c_str());
        return false;
    }
    // 输出成功日志。
    LOGI("coverage report written: %s", coverageReportPath.c_str());
    return true;
}

// 执行 host 保护流程（可选）。
bool runHostProtectFlow(const VmProtectConfig& config) {
    // 未指定 host 时直接跳过。
    if (config.hostSo.empty()) {
        return true;
    }

    // expanded so 的完整路径。
    const std::string expandedSoPath = joinOutputPath(config, config.expandedSo);
    // 未指定 donor：仅做 embed。
    if (config.patchDonorSo.empty()) {
        // 若未指定 finalSo，则默认回写到 hostSo。
        const std::string finalSoPath =
            config.finalSo.empty() ? config.hostSo : config.finalSo;
        return embedExpandedSoIntoHost(config.hostSo, expandedSoPath, finalSoPath);
    }

    // 指定 donor：走 embed + patchbay 导出流程。
    const std::string finalSoPath =
        config.finalSo.empty() ? buildPatchSoDefaultPath(config.hostSo) : config.finalSo;
    // patch 前临时文件路径。
    const std::string embedTmpSoPath = finalSoPath + ".embed.tmp.so";
    // 先把 expanded so 注入临时 so。
    if (!embedExpandedSoIntoHost(config.hostSo, expandedSoPath, embedTmpSoPath)) {
        return false;
    }
    // 再执行 patchbay donor 导出流程。
    if (!runPatchbayExportFromDonor(embedTmpSoPath,
                                    finalSoPath,
                                    config.patchDonorSo,
                                    config.patchImplSymbol,
                                    config.patchAllExports,
                                    config.patchAllowValidateFail)) {
        return false;
    }

    // 清理临时文件（失败仅告警不阻断）。
    std::error_code ec;
    fs::remove(embedTmpSoPath, ec);
    if (ec) {
        LOGW("remove embed tmp so failed: %s", embedTmpSoPath.c_str());
    }
    return true;
}

}  // namespace

}  // namespace vmp

// 程序主入口。
int main(int argc, char* argv[]) {
    // 若首参数是 patchbay 子命令，直接分流到 patchbay 入口。
    if (argc >= 2 && vmprotectIsPatchbayCommand(argv[1])) {
        return vmprotectPatchbayEntry(argc, argv);
    }

    // CLI 覆盖项对象。
    vmp::CliOverrides cli;
    // CLI 解析错误文本。
    std::string cliError;
    // 解析命令行。
    if (!vmp::parseCommandLine(argc, argv, cli, cliError)) {
        std::cerr << cliError << "\n";
        vmp::printUsage();
        return 1;
    }
    // --help 直接打印并退出。
    if (cli.showHelp) {
        vmp::printUsage();
        return 0;
    }

    // 初始化默认配置。
    vmp::VmProtectConfig config;
    // 默认函数列表。
    config.functions = vmp::kDefaultFunctions;
    // 默认函数去重。
    vmp::deduplicateKeepOrder(config.functions);
    // 应用 CLI 覆盖项。
    vmp::applyCliOverrides(cli, config);
    // 再去重一次，确保 CLI 注入后的顺序稳定。
    vmp::deduplicateKeepOrder(config.functions);
    // 校验最终配置。
    if (!vmp::validateConfig(config)) {
        return 1;
    }

    // 加载输入 ELF。
    vmp::elfkit::ElfImage elf(config.inputSo.c_str());
    if (!elf.loaded()) {
        LOGE("failed to load input so: %s", config.inputSo.c_str());
        return 1;
    }
    // 生成最终函数名列表。
    std::vector<std::string> functionNames = vmp::buildFunctionNameList(config, elf);
    // 空列表直接失败。
    if (functionNames.empty()) {
        LOGE("function list is empty");
        return 1;
    }

    // 收集函数视图对象。
    std::vector<vmp::elfkit::FunctionView> functions;
    if (!vmp::collectFunctions(elf, functionNames, functions)) {
        return 1;
    }

    // 执行覆盖率流程。
    if (!vmp::runCoverageFlow(config, functionNames, functions)) {
        return 1;
    }
    // coverageOnly 模式到此结束。
    if (config.coverageOnly) {
        LOGI("coverage-only mode enabled, export skipped");
        return 0;
    }

    // 导出保护包（函数 txt/bin + expanded so 等）。
    if (!vmp::exportProtectedPackage(config, functionNames, functions)) {
        return 1;
    }
    // 可选 host 注入/patch 流程。
    if (!vmp::runHostProtectFlow(config)) {
        return 1;
    }

    // 全流程成功。
    return 0;
}
