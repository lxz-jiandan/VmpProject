/*
 * [VMP_FLOW_NOTE] 文件级流程注释。
 * - 文件：core/zElfTypes.h
 * - 主要职责：ELF 基础类型定义：统一项目内部 ELF 相关类型别名与结构体约束。
 * - 输入：ELF 二进制数据、地址/偏移信息与上下文配置。
 * - 输出：稳定的接口声明、类型约束和调用契约。
 * - 关键约束：
 *   1) 严格保持 ELF 布局与索引一致性，避免地址/偏移漂移。
 *   2) 失败路径必须可定位（返回值/错误信息/日志三者保持一致）。
 *   3) 本文件改动优先保证与上游调用契约兼容，不隐式改变既有语义。
 */
#ifndef VMP_ELFKIT_CORE_ELF_H
#define VMP_ELFKIT_CORE_ELF_H

// 引入 ELF ABI 常量与结构定义（Elf64_Ehdr/Elf64_Shdr 等）。
// 该头用于在 elfkit 子模块间共享统一 ELF 类型。
#include "zElfAbi.h"

#endif  // VMP_ELFKIT_CORE_ELF_H

