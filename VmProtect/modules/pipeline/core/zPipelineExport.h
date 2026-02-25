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

// 按函数名收集函数视图对象。
bool collectFunctions(elfkit::ElfImage& elf,
                      const std::vector<std::string>& functionNames,
                      std::vector<elfkit::FunctionView>& functions);

// 导出保护包：函数 payload + branch 地址 + expand so。
bool exportProtectedPackage(const VmProtectConfig& config,
                            const std::vector<std::string>& functionNames,
                            const std::vector<elfkit::FunctionView>& functions);

// 结束命名空间。
}  // namespace vmp




