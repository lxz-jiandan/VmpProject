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
// 将覆盖率面板输出为 markdown 报告。
bool writeCoverageReport(const std::string& reportPath, const CoverageBoard& board);

// 结束命名空间。
}  // namespace vmp




