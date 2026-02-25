// 防止头文件重复包含。
#pragma once

// 引入字符串类型。
#include <string>
// 引入动态数组容器。
#include <vector>

// 引入 ELF 抽象接口。
#include "zElfKit.h"
// 引入 pipeline 类型定义。
#include "zPipelineTypes.h"

// 进入 pipeline 命名空间。
namespace vmp {

// 构建覆盖率总面板。
bool buildCoverageBoard(const std::vector<std::string>& functionNames,
                        const std::vector<elfkit::FunctionView>& functions,
                        CoverageBoard& board);
// 填充翻译状态（会触发 prepareTranslation）。
bool fillTranslationStatus(const std::vector<elfkit::FunctionView>& functions,
                           CoverageBoard& board);
// 执行覆盖率分析阶段（统计 + 翻译状态采集）。
bool runCoverageAnalyzeFlow(const std::vector<std::string>& functionNames,
                            const std::vector<elfkit::FunctionView>& functions,
                            CoverageBoard& board);
// 将覆盖率面板写入报告文件。
bool runCoverageReportFlow(const VmProtectConfig& config, const CoverageBoard& board);
// 执行完整覆盖率流程（分析 + 报告写出），可选回传 board。
bool runCoverageFlow(const VmProtectConfig& config,
                     const std::vector<std::string>& functionNames,
                     const std::vector<elfkit::FunctionView>& functions,
                     CoverageBoard* outBoard);
// 将覆盖率面板输出为 markdown 报告。
bool writeCoverageReport(const std::string& reportPath, const CoverageBoard& board);

// 结束命名空间。
}  // namespace vmp




