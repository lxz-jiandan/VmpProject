#ifndef OVERT_ZELF_PROGRAM_HEADER_TABLE_H
#define OVERT_ZELF_PROGRAM_HEADER_TABLE_H

#include "zProgramTableElement.h"

#include <vector>

/**
 * @brief Program Header Table 的模型容器。
 *
 * 负责在原始 `Elf64_Phdr` 与内部 `zProgramTableElement` 表示之间转换，
 * 并提供按段类型检索的辅助能力。
 */
class zElfProgramHeaderTable {
public:
    std::vector<zProgramTableElement> elements;  ///< Program Header 条目序列。

    /**
     * @brief 从原始 phdr 数组构建模型。
     * @param raw 原始 Program Header 数组。
     * @param count 条目数量。
     */
    void fromRaw(const Elf64_Phdr* raw, size_t count);

    /**
     * @brief 将模型序列化为原始 phdr 数组。
     */
    std::vector<Elf64_Phdr> toRaw() const;

    /**
     * @brief 查找首个指定类型段。
     * @param type `PT_*` 段类型。
     * @return 找到返回索引，否则返回 -1。
     */
    int findFirstByType(Elf64_Word type) const;

    /**
     * @brief 查找全部指定类型段。
     * @param type `PT_*` 段类型。
     * @return 匹配索引列表。
     */
    std::vector<int> findAllByType(Elf64_Word type) const;
};

#endif // OVERT_ZELF_PROGRAM_HEADER_TABLE_H
