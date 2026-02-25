#ifndef VMP_PATCHBAY_SECTION_ENTRY_H
#define VMP_PATCHBAY_SECTION_ENTRY_H

#include "zPatchElfTypes.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

/**
 * @brief Section 条目的通用模型基类。
 *
 * 该类保存 `Elf64_Shdr` 的核心字段与 payload 数据，
 * 并作为字符串表/符号表/重定位表等派生类的统一父类。
 */
class zSectionTableElement {
public:
    Elf64_Word name = 0;            ///< 节名在 `.shstrtab` 中的偏移。
    Elf64_Word type = SHT_NULL;     ///< 节类型（`SHT_*`）。
    Elf64_Xword flags = 0;          ///< 节标志（`SHF_*`）。
    Elf64_Addr addr = 0;            ///< 虚拟地址 `sh_addr`。
    Elf64_Off offset = 0;           ///< 文件偏移 `sh_offset`。
    Elf64_Xword size = 0;           ///< 节大小 `sh_size`。
    Elf64_Word link = 0;            ///< 关联节索引 `sh_link`。
    Elf64_Word info = 0;            ///< 附加信息 `sh_info`。
    Elf64_Xword addralign = 1;      ///< 对齐约束 `sh_addralign`。
    Elf64_Xword entsize = 0;        ///< 表项大小 `sh_entsize`（若为表类型节）。
    std::string resolved_name;      ///< 解析后的节名字符串。
    std::vector<uint8_t> payload;   ///< 节原始数据内容。

    virtual ~zSectionTableElement() = default;

    /** @brief 从字节流解析 payload（基类为直接拷贝）。 */
    virtual void parseFromBytes(const uint8_t* data, size_t dataSize);

    /** @brief 序列化为字节流（基类直接返回 payload）。 */
    virtual std::vector<uint8_t> toByteArray() const;

    /** @brief 根据 payload/节类型同步 header 相关字段。 */
    virtual void syncHeader();

    /** @brief 转换为原始 `Elf64_Shdr` 结构。 */
    Elf64_Shdr toShdr() const;

    /** @brief 获取解析后的节名。 */
    const std::string& getSectionName() const;

    /** @brief 获取节类型。 */
    Elf64_Word getSectionType() const;

    /** @brief 获取节标志。 */
    Elf64_Xword getSectionFlags() const;

    /** @brief 从原始 `Elf64_Shdr` 反序列化字段。 */
    void fromShdr(const Elf64_Shdr& shdr);
};

// ============================================================================
// 派生类：字符串表节（所有派生类定义在同一文件以减少文件数量）
// ============================================================================

/**
 * @brief 字符串表节模型（`.strtab` / `.dynstr`）。
 */
class zStrTabSection : public zSectionTableElement {
public:
    /**
     * @brief 向字符串表末尾追加一个以 `\0` 结尾的字符串。
     * @param value 要追加的字符串（不含末尾空字符）。
     * @return 新字符串在表内的偏移。
     */
    uint32_t addString(const std::string& value);

    /**
     * @brief 按偏移读取字符串指针。
     * @param off 字符串偏移。
     * @return 成功返回 C 字符串指针，失败返回 `nullptr`。
     */
    const char* getStringAt(uint32_t off) const;
};

// ============================================================================
// 派生类：符号表节
// ============================================================================

/**
 * @brief 符号表节模型（`.symtab` / `.dynsym`）。
 */
class zSymbolSection : public zSectionTableElement {
public:
    std::vector<Elf64_Sym> symbols;  ///< 符号条目列表。

    /** @brief 从节 payload 解析符号表条目。 */
    void parseFromBytes(const uint8_t* data, size_t dataSize) override;

    /** @brief 将符号条目序列化为节 payload。 */
    std::vector<uint8_t> toByteArray() const override;

    /** @brief 同步节头元数据（size/entsize）。 */
    void syncHeader() override;

    /** @brief 获取符号条目数量。 */
    size_t getSymbolCount() const;
};

// ============================================================================
// 派生类：动态节
// ============================================================================

/**
 * @brief `.dynamic` 节的模型封装。
 */
class zDynamicSection : public zSectionTableElement {
public:
    std::vector<Elf64_Dyn> entries;  ///< 动态表条目（DT_*）列表。

    /** @brief 从原始字节解析动态表条目。 */
    void parseFromBytes(const uint8_t* data, size_t dataSize) override;

    /** @brief 将动态表条目序列化为字节数组。 */
    std::vector<uint8_t> toByteArray() const override;

    /** @brief 同步 header 元数据（size/entsize 等）。 */
    void syncHeader() override;

    /** @brief 获取当前动态表条目数量。 */
    size_t getEntryCount() const;
};

// ============================================================================
// 派生类：重定位表节
// ============================================================================

/**
 * @brief 重定位节模型（支持 RELA 与 REL 两种格式）。
 */
class zRelocationSection : public zSectionTableElement {
public:
    std::vector<Elf64_Rela> relocations;      ///< `SHT_RELA` 条目列表。
    std::vector<Elf64_Rel> rel_relocations;   ///< `SHT_REL` 条目列表。

    /** @brief 从节 payload 解析重定位条目。 */
    void parseFromBytes(const uint8_t* data, size_t dataSize) override;

    /** @brief 将当前重定位条目序列化为节 payload。 */
    std::vector<uint8_t> toByteArray() const override;

    /** @brief 同步 section header 元数据（size/entsize）。 */
    void syncHeader() override;

    /** @brief 获取当前重定位条目总数。 */
    size_t getRelocationCount() const;
};

#endif // VMP_PATCHBAY_SECTION_ENTRY_H

