/*
 * [VMP_FLOW_NOTE] 文件级流程注释。
 * - 文件：patchbayModel/zPatchElfTypes.h
 * - 主要职责：Patch ELF 类型集合：定义补丁流程共享的数据结构与标记类型。
 * - 输入：ELF 原始字节、补丁模型状态以及段/节/符号元数据。
 * - 输出：稳定的接口声明、类型约束和调用契约。
 * - 关键约束：
 *   1) 严格保持 ELF 布局与索引一致性，避免地址/偏移漂移。
 *   2) 失败路径必须可定位（返回值/错误信息/日志三者保持一致）。
 *   3) 本文件改动优先保证与上游调用契约兼容，不隐式改变既有语义。
 */
#ifndef VMP_ELFKIT_PATCHBAY_MODEL_ELF_H
#define VMP_ELFKIT_PATCHBAY_MODEL_ELF_H

// 共享 ELF ABI 常量与结构定义。
// patchbayModel 与 elfkit 其它子模块统一依赖这份头，避免类型分叉。
#include "zElfAbi.h"

#endif  // VMP_ELFKIT_PATCHBAY_MODEL_ELF_H
