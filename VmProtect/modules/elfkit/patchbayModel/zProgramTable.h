/*
 * [VMP_FLOW_NOTE] 文件级流程注释。
 * - 文件：patchbayModel/zProgramTable.h
 * - 主要职责：Program Header 表模型：管理段项集合及其查找、增删、重排逻辑。
 * - 输入：ELF 原始字节、补丁模型状态以及段/节/符号元数据。
 * - 输出：稳定的接口声明、类型约束和调用契约。
 * - 关键约束：
 *   1) 严格保持 ELF 布局与索引一致性，避免地址/偏移漂移。
 *   2) 失败路径必须可定位（返回值/错误信息/日志三者保持一致）。
 *   3) 本文件改动优先保证与上游调用契约兼容，不隐式改变既有语义。
 */
#ifndef VMP_PATCHBAY_PROGRAM_TABLE_H
#define VMP_PATCHBAY_PROGRAM_TABLE_H

// Program Header 条目模型。
#include "zProgramEntry.h"

// 顺序容器。
#include <vector>

/**
 * @brief Program Header Table 的模型容器。
 *
 * 职责：
 * - 承载整个 phdr 列表；
 * - 提供 raw <-> model 的批量转换；
 * - 提供按段类型检索的便捷接口，减少上层重复循环代码。
 */
class zElfProgramHeaderTable {
public:
    // Program Header 条目序列；顺序与 ELF 文件中的 phdr 顺序一致。
    std::vector<zProgramTableElement> elements;

    /**
     * @brief 从原始 phdr 数组构建模型。
     * @param raw 原始 `Elf64_Phdr` 数组首地址。
     * @param count 条目数量。
     */
    void fromRaw(const Elf64_Phdr* raw, size_t count);

    /**
     * @brief 将模型序列化为原始 phdr 数组。
     * @return 可直接回写的 `Elf64_Phdr` 向量。
     */
    std::vector<Elf64_Phdr> toRaw() const;

    /**
     * @brief 查找首个指定类型段。
     * @param type 目标段类型（PT_*）。
     * @return 找到返回索引；找不到返回 -1。
     */
    int getFirstByType(Elf64_Word type) const;

    /**
     * @brief 查找所有指定类型段。
     * @param type 目标段类型（PT_*）。
     * @return 匹配的索引列表；可为空。
     */
    std::vector<int> getAllByType(Elf64_Word type) const;
};

#endif // VMP_PATCHBAY_PROGRAM_TABLE_H

