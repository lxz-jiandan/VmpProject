/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - VmProtect CLI 主入口：解析参数、构建覆盖率、导出保护包、可选 vmengine 注入/patch。
 * - 加固链路位置：离线阶段入口（route4 上游）。
 * - 输入：原始 arm64 so + 函数清单/命令行配置。
 * - 输出：coverage_report、函数 txt/bin、branch_addr_list、expanded/vmengine so。
 */

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
// 主流程配置与函数列表构建。
#include "zPipelineRun.h"
// 配置结构与常量。
#include "zPipelineTypes.h"

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

    // 初始化默认配置（默认函数等）。
    vmp::VmProtectConfig config;
    vmp::initDefaultConfig(config);
    // 应用 CLI 覆盖项。
    vmp::applyCliOverrides(cli, config);
    // 再去重一次，确保 CLI 注入后的顺序稳定。
    vmp::deduplicateKeepOrder(config.functions);
    // 校验最终配置。
    if (!vmp::validateConfig(config, cli)) {
        return 1;
    }

    // 加载输入 ELF。
    vmp::elfkit::ElfImage elf(config.inputSo.c_str());
    if (!elf.isLoaded()) {
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
    vmp::CoverageBoard coverageBoard;
    if (!vmp::runCoverageFlow(config, functionNames, functions, &coverageBoard)) {
        return 1;
    }

    // coverageOnly 模式到此结束。
    if (config.coverageOnly) {
        LOGI("coverage-only mode enabled, export skipped");
        return 0;
    }

    // 导出保护包（函数 txt/bin + expanded so 等）。
    if (!vmp::exportProtectedPackage(config, functionNames, functions, &coverageBoard)) {
        return 1;
    }

    // 可选 vmengine 注入/patch 流程。
    if (!vmp::runVmengineProtectFlow(config)) {
        return 1;
    }

    // 全流程成功。
    return 0;
}
