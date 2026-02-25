#ifndef VMPROTECT_PATCHBAY_ENTRY_H
#define VMPROTECT_PATCHBAY_ENTRY_H

// 判断给定子命令是否应由内嵌 patchbay CLI 处理。
// 入参：
// - cmd: 子命令字符串（如 export_alias_from_patchbay）。
// 返回：
// - true: 该命令属于 patchbay 域。
// - false: 非 patchbay 子命令。
bool vmprotectIsPatchbayCommand(const char* cmd);

// patchbay 内嵌入口（供主程序和进程内调用）。
// 入参：
// - argc: 参数数量。
// - argv: 参数数组。
// 返回：
// - 0: 执行成功。
// - 非 0: 参数错误或执行失败。
int vmprotectPatchbayEntry(int argc, char* argv[]);

#endif // VMPROTECT_PATCHBAY_ENTRY_H

