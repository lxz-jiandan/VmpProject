/*
 * [VMP_FLOW_NOTE] 文件级流程注释。
 * - 文件：patchbayModel/zSectionTable.h
 * - 主要职责：Section Header 表模型：管理节项集合及索引/地址一致性维护。
 * - 输入：ELF 原始字节、补丁模型状态以及段/节/符号元数据。
 * - 输出：稳定的接口声明、类型约束和调用契约。
 * - 关键约束：
 *   1) 严格保持 ELF 布局与索引一致性，避免地址/偏移漂移。
 *   2) 失败路径必须可定位（返回值/错误信息/日志三者保持一致）。
 *   3) 本文件改动优先保证与上游调用契约兼容，不隐式改变既有语义。
 */
#ifndef VMP_PATCHBAY_SECTION_TABLE_H
#define VMP_PATCHBAY_SECTION_TABLE_H

// Section 条目基类及派生类声明。
#include "zSectionEntry.h"

// unique_ptr。
#include <memory>
// std::string。
#include <string>
// 顺序容器。
#include <vector>

/**
 * @brief Section Header Table 的模型容器。
 *
 * 核心能力：
 * - 将原始 `Elf64_Shdr[]` 解析为多态 section 对象；
 * - 统一管理 section 元数据与 payload；
 * - 提供序列化与按节名查询接口。
 */
class zElfSectionHeaderTable {
public:
    // 多态 section 集合；每个元素对应一个 section header 条目。
    std::vector<std::unique_ptr<zSectionTableElement>> elements;

    /**
     * @brief 从原始 section header 与文件字节构建模型。
     * @param fileData 完整 ELF 文件字节首地址。
     * @param fileSize 文件总字节数。
     * @param sectionHeaders 原始 section header 数组首地址。
     * @param sectionCount section 条目数量。
     * @param shstrndx 节名字符串表索引（e_shstrndx）。
     * @return true 表示解析成功；false 表示存在越界或格式异常。
     */
    bool fromRaw(const uint8_t* fileData,
                 size_t fileSize,
                 const Elf64_Shdr* sectionHeaders,
                 size_t sectionCount,
                 uint16_t shstrndx);

    /**
     * @brief 将模型序列化为原始 section header 数组。
     * @return 可写回文件的 `Elf64_Shdr` 向量。
     */
    std::vector<Elf64_Shdr> toRaw() const;

    /**
     * @brief 按节名查询 section 索引。
     * @param sectionName 目标节名（例如 `.text`、`.dynsym`）。
     * @return 找到返回索引；找不到返回 -1。
     */
    int getByName(const std::string& sectionName) const;

    /**
     * @brief 获取指定索引的可写 section 对象。
     * @param sectionIndex 目标索引。
     * @return 成功返回对象指针；越界返回 nullptr。
     */
    zSectionTableElement* get(size_t sectionIndex);

    /**
     * @brief 获取指定索引的只读 section 对象。
     * @param sectionIndex 目标索引。
     * @return 成功返回对象指针；越界返回 nullptr。
     */
    const zSectionTableElement* get(size_t sectionIndex) const;
};

#endif // VMP_PATCHBAY_SECTION_TABLE_H

