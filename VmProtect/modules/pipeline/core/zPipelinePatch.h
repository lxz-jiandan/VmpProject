// 防止头文件重复包含。
#pragma once

// 引入字符串类型。
#include <string>

// 进入 pipeline 命名空间。
namespace vmp {

// 前向声明主流程配置结构。
struct VmProtectConfig;

// 执行 vmengine 路线流程：
// - mode=embed: embed；
// - mode=protect: embed + patchbay origin。
bool runVmengineProtectFlow(const VmProtectConfig& config);

// 结束命名空间。
}  // namespace vmp


