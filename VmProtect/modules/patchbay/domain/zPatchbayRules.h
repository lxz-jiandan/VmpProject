#ifndef VMPROTECT_PATCHBAY_RULES_H
#define VMPROTECT_PATCHBAY_RULES_H

// 引入基础整型定义。
#include <cstdint>
// 引入字符串类型。
#include <string>
// 引入字符串数组容器。
#include <vector>

// 判断导出符号是否属于 fun_* 或 Java_* 范围。
// 入参：
// - name: 待判断符号名。
// 返回：
// - true: 符合 only_fun_java 过滤策略。
// - false: 不符合过滤策略。
bool isFunOrJavaSymbol(const std::string& name);

// 判断实现符号是否启用 takeover 槽位模式。
// 入参：
// - implName: 实现符号名。
// 返回：
// - true: 以 vm_takeover_slot_ 前缀开头。
// - false: 非槽位模式符号名。
bool isTakeoverSlotModeImpl(const char* implName);

// 按槽位编号生成标准槽位符号名。
// 入参：
// - slotId: 槽位索引。
// 出参：
// - 返回形如 vm_takeover_slot_0000 的符号名。
std::string buildTakeoverSlotSymbolName(uint32_t slotId);

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

