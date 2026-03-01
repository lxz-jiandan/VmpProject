/*
 * [VMP_FLOW_NOTE] 文件级流程注释。
 * - 文件：patchbayModel/zSectionTable.cpp
 * - 主要职责：Section Header 表模型：管理节项集合及索引/地址一致性维护。
 * - 输入：ELF 原始字节、补丁模型状态以及段/节/符号元数据。
 * - 输出：经过校验的补丁模型或重建后的 ELF 输出数据。
 * - 关键约束：
 *   1) 严格保持 ELF 布局与索引一致性，避免地址/偏移漂移。
 *   2) 失败路径必须可定位（返回值/错误信息/日志三者保持一致）。
 *   3) 本文件改动优先保证与上游调用契约兼容，不隐式改变既有语义。
 */
#include "zSectionTable.h"

// 根据 section 类型与名称选择合适的模型派生类（所有类定义在同一文件以减少文件数量）。
static std::unique_ptr<zSectionTableElement> createSectionElementFromShdr(const Elf64_Shdr& raw,
                                                                           const std::string& sectionName) {
    // 字符串表（.strtab/.dynstr/.shstrtab）。
    if (raw.sh_type == SHT_STRTAB) {
        return std::make_unique<zStrTabSection>();
    }
    // 动态节（以类型或名称双重识别，兼容部分异常样本）。
    if (raw.sh_type == SHT_DYNAMIC || sectionName == ".dynamic") {
        return std::make_unique<zDynamicSection>();
    }
    // 符号节（静态/动态）。
    if (raw.sh_type == SHT_SYMTAB || raw.sh_type == SHT_DYNSYM ||
        sectionName == ".symtab" || sectionName == ".dynsym") {
        return std::make_unique<zSymbolSection>();
    }
    // 重定位节（RELA/REL）。
    if (raw.sh_type == SHT_RELA || raw.sh_type == SHT_REL || sectionName.rfind(".rela", 0) == 0) {
        return std::make_unique<zRelocationSection>();
    }
    // 其余节使用通用模型。
    return std::make_unique<zSectionTableElement>();
}

// 从原始 SHT 与文件字节构建多态 section 模型。
bool zElfSectionHeaderTable::fromRaw(const uint8_t* fileData,
                                     size_t fileSize,
                                     const Elf64_Shdr* sectionHeaders,
                                     size_t sectionCount,
                                     uint16_t shstrndx) {
    // 清空旧数据。
    elements.clear();
    // 没有 section header 视作空表，不是错误。
    if (!sectionHeaders || sectionCount == 0) {
        return true;
    }

    // .shstrtab 首地址。
    const char* shstr = nullptr;
    // .shstrtab 大小。
    size_t shstr_size = 0;

    // shstrndx 合法时尝试解析 section-name string table。
    if (shstrndx < sectionCount) {
        const Elf64_Shdr& sh = sectionHeaders[shstrndx];
        // .shstrtab 范围必须在文件内。
        if ((uint64_t)sh.sh_offset + sh.sh_size <= fileSize) {
            shstr = reinterpret_cast<const char*>(fileData + sh.sh_offset);
            shstr_size = sh.sh_size;
        }
    }

    // 预留容量。
    elements.reserve(sectionCount);
    // 逐条解析 section header。
    for (size_t sectionIndex = 0; sectionIndex < sectionCount; ++sectionIndex) {
        const Elf64_Shdr& raw = sectionHeaders[sectionIndex];

        // 解析节名文本。
        std::string resolved_name;
        if (shstr && raw.sh_name < shstr_size) {
            // 根据 sh_name 偏移从 .shstrtab 取节名。
            resolved_name = std::string(shstr + raw.sh_name);
        }

        // 按节类型构建最合适的派生类对象。
        std::unique_ptr<zSectionTableElement> item = createSectionElementFromShdr(raw, resolved_name);

        // 先装载头字段。
        item->fromShdr(raw);
        // 再写解析后的名称。
        item->resolved_name = std::move(resolved_name);

        // 非 NOBITS 且 size>0 的节需要从文件读取 payload。
        if (raw.sh_type != SHT_NOBITS && raw.sh_size > 0) {
            // 范围越界直接失败。
            if ((uint64_t)raw.sh_offset + raw.sh_size > fileSize) {
                return false;
            }
            // 由派生类执行具体 parse（符号/重定位等）。
            item->parseFromBytes(fileData + raw.sh_offset, (size_t)raw.sh_size);
        }

        // 统一同步一次头字段，确保 size/entsize 等派生信息一致。
        item->syncHeader();
        // 压入模型数组。
        elements.push_back(std::move(item));
    }
    return true;
}

// 将 section 模型序列化回原始 SHT。
std::vector<Elf64_Shdr> zElfSectionHeaderTable::toRaw() const {
    // 输出数组。
    std::vector<Elf64_Shdr> out;
    // 预留容量。
    out.reserve(elements.size());
    // 顺序序列化。
    for (const auto& element : elements) {
        // 每个派生对象都能回写为标准 Elf64_Shdr。
        out.push_back(element->toShdr());
    }
    return out;
}

// 按节名查找索引（找不到返回 -1）。
int zElfSectionHeaderTable::getByName(const std::string& sectionName) const {
    // 线性扫描名称。
    for (size_t sectionIndex = 0; sectionIndex < elements.size(); ++sectionIndex) {
        if (elements[sectionIndex]->resolved_name == sectionName) {
            return (int)sectionIndex;
        }
    }
    // 未命中返回 -1，调用方据此决定是否创建/跳过。
    return -1;
}

// 获取可写 section 对象。
zSectionTableElement* zElfSectionHeaderTable::get(size_t sectionIndex) {
    return sectionIndex < elements.size() ? elements[sectionIndex].get() : nullptr;
}

// 获取只读 section 对象。
const zSectionTableElement* zElfSectionHeaderTable::get(size_t sectionIndex) const {
    return sectionIndex < elements.size() ? elements[sectionIndex].get() : nullptr;
}

