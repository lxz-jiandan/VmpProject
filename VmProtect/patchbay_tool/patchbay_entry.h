#ifndef VMPROTECT_PATCHBAY_ENTRY_H
#define VMPROTECT_PATCHBAY_ENTRY_H

// 判断给定子命令是否应由内嵌 patchbay CLI 处理。
// 典型命令：
// - export_alias_from_patchbay
bool vmprotect_is_patchbay_command(const char* cmd);

// 内嵌 patchbay 子命令入口。
// 返回值约定：
// - 0: 成功；
// - 非 0: 参数错误或执行失败。
int vmprotect_patchbay_entry(int argc, char* argv[]);

#endif // VMPROTECT_PATCHBAY_ENTRY_H
