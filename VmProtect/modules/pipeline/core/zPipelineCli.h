// 防止头文件重复包含。
#pragma once

// 引入字符串类型。
#include <string>
// 引入动态数组容器。
#include <vector>

// 引入 pipeline 类型定义。
#include "zPipelineTypes.h"

// 进入 pipeline 命名空间。
namespace vmp {

// 对字符串数组去重并保持原顺序。
void deduplicateKeepOrder(std::vector<std::string>& values);
// 解析命令行参数并输出覆盖项。
bool parseCommandLine(int argc, char* argv[], CliOverrides& cli, std::string& error);
// 打印命令行帮助。
void printUsage();
// 基于 outputDir 拼接输出文件路径。
std::string joinOutputPath(const VmProtectConfig& config, const std::string& fileName);

// 结束命名空间。
}  // namespace vmp



