// 防止头文件重复包含。
#pragma once

// 引入字符串类型。
#include <string>
// 引入动态数组容器。
#include <vector>

// 引入 ELF 抽象接口。
#include "zElfKit.h"
// 引入 pipeline 配置结构。
#include "zPipelineTypes.h"

// 进入 pipeline 命名空间。
namespace vmp {

// 判断当前配置是否触发“加固路线”。
bool isHardeningRoute(const VmProtectConfig& config);
// 初始化默认配置（默认函数列表 + 去重）。
void initDefaultConfig(VmProtectConfig& config);
// 将 CLI 覆盖项应用到配置对象。
void applyCliOverrides(const CliOverrides& cli, VmProtectConfig& config);
// 校验最终配置是否满足运行契约。
bool validateConfig(const VmProtectConfig& config, const CliOverrides& cli);
// 构建最终函数列表（支持 analyzeAll）。
std::vector<std::string> buildFunctionNameList(const VmProtectConfig& config,
                                               elfkit::ElfImage& elf);

// 结束命名空间。
}  // namespace vmp
