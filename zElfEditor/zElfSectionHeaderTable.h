#ifndef OVERT_ZELF_SECTION_HEADER_TABLE_H
#define OVERT_ZELF_SECTION_HEADER_TABLE_H

#include "zSectionTableElement.h"

#include <memory>
#include <string>
#include <vector>

/**
 * @brief Section Header Table 的模型容器。
 *
 * 按 section 类型创建不同派生类对象（字符串表、符号表、重定位表等），
 * 统一管理 section 元数据与 payload。
 */
class zElfSectionHeaderTable {
public:
    std::vector<std::unique_ptr<zSectionTableElement>> elements;  ///< Section 条目（多态对象）。

    /**
     * @brief 从原始 section header 与文件内容构建模型。
     * @param file_data 完整 ELF 文件字节。
     * @param file_size 文件大小。
     * @param section_headers 原始 section header 数组。
     * @param section_count section 数量。
     * @param shstrndx 节名字符串表索引。
     * @return true 表示解析成功。
     */
    bool fromRaw(const uint8_t* file_data,
                 size_t file_size,
                 const Elf64_Shdr* section_headers,
                 size_t section_count,
                 uint16_t shstrndx);

    /**
     * @brief 序列化为原始 section header 数组。
     */
    std::vector<Elf64_Shdr> toRaw() const;

    /**
     * @brief 按节名查找 section。
     * @param section_name 节名（如 `.text`）。
     * @return 找到返回索引，否则返回 -1。
     */
    int findByName(const std::string& section_name) const;

    /**
     * @brief 获取指定索引的可写 section 对象。
     */
    zSectionTableElement* get(size_t idx);

    /**
     * @brief 获取指定索引的只读 section 对象。
     */
    const zSectionTableElement* get(size_t idx) const;
};

#endif // OVERT_ZELF_SECTION_HEADER_TABLE_H
