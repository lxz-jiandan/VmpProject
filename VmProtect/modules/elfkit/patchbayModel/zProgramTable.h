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

