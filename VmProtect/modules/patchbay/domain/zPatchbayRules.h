#ifndef VMPROTECT_PATCHBAY_RULES_H
#define VMPROTECT_PATCHBAY_RULES_H

// 引入基础整型定义。
#include <cstdint>
// 引入字符串类型。
#include <string>
// 引入字符串数组容器。
#include <vector>

// 校验 vmengine 现有导出是否满足命名规则。
// 规则：
// - C 导出必须以 vm_ 开头。
// - C++ 导出必须位于 vm 命名空间。
// 入参：
// - inputExports: input so 中全部导出名。
// - error: 可选错误描述输出。
// 返回：
// - true: 全部命名合法。
// - false: 至少一个导出命名不合法。
bool validateVmengineExportNamingRules(const std::vector<std::string>& inputExports,
                                       std::string* error);

#endif // VMPROTECT_PATCHBAY_RULES_H
