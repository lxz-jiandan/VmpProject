#include "zElfSectionHeaderTable.h"

// 根据 section 类型与名称选择合适的模型派生类（所有类定义在同一文件以减少文件数量）。
static std::unique_ptr<zSectionTableElement> create_section_element_from_shdr(const Elf64_Shdr& raw,
                                                                               const std::string& section_name) {
    // 字符串表（.strtab/.dynstr/.shstrtab）。
    if (raw.sh_type == SHT_STRTAB) {
        return std::make_unique<zStrTabSection>();
    }
    // 动态节（以类型或名称双重识别，兼容部分异常样本）。
    if (raw.sh_type == SHT_DYNAMIC || section_name == ".dynamic") {
        return std::make_unique<zDynamicSection>();
    }
    // 符号节（静态/动态）。
    if (raw.sh_type == SHT_SYMTAB || raw.sh_type == SHT_DYNSYM ||
        section_name == ".symtab" || section_name == ".dynsym") {
        return std::make_unique<zSymbolSection>();
    }
    // 重定位节（RELA/REL）。
    if (raw.sh_type == SHT_RELA || raw.sh_type == SHT_REL || section_name.rfind(".rela", 0) == 0) {
        return std::make_unique<zRelocationSection>();
    }
    // 其余节使用通用模型。
    return std::make_unique<zSectionTableElement>();
}

// 从原始 SHT 与文件字节构建多态 section 模型。
bool zElfSectionHeaderTable::fromRaw(const uint8_t* file_data,
                                     size_t file_size,
                                     const Elf64_Shdr* section_headers,
                                     size_t section_count,
                                     uint16_t shstrndx) {
    elements.clear();
    if (!section_headers || section_count == 0) {
        // 没有 section header 视作空表，不是错误。
        return true;
    }

    const char* shstr = nullptr;
    size_t shstr_size = 0;
    if (shstrndx < section_count) {
        // 解析 section-name string table（.shstrtab）用于恢复节名。
        const Elf64_Shdr& sh = section_headers[shstrndx];
        if ((uint64_t)sh.sh_offset + sh.sh_size <= file_size) {
            shstr = reinterpret_cast<const char*>(file_data + sh.sh_offset);
            shstr_size = sh.sh_size;
        }
    }

    elements.reserve(section_count);
    for (size_t idx = 0; idx < section_count; ++idx) {
        const Elf64_Shdr& raw = section_headers[idx];
        std::string resolved_name;
        if (shstr && raw.sh_name < shstr_size) {
            // 根据 sh_name 偏移从 .shstrtab 取节名。
            resolved_name = std::string(shstr + raw.sh_name);
        }
        // 按节类型构建最合适的派生类对象。
        std::unique_ptr<zSectionTableElement> item = create_section_element_from_shdr(raw, resolved_name);

        // 先装载头字段，再写入解析后的名称。
        item->fromShdr(raw);
        item->resolved_name = std::move(resolved_name);

        if (raw.sh_type != SHT_NOBITS && raw.sh_size > 0) {
            // 非 NOBITS 节必须能在文件内取到 payload。
            if ((uint64_t)raw.sh_offset + raw.sh_size > file_size) {
                return false;
            }
            // 由派生类执行具体 parse（符号/重定位等）。
            item->parseFromBytes(file_data + raw.sh_offset, (size_t)raw.sh_size);
        }
        // 统一同步一次头字段，确保 size/entsize 等派生信息一致。
        item->syncHeader();
        elements.push_back(std::move(item));
    }
    return true;
}

// 将 section 模型序列化回原始 SHT。
std::vector<Elf64_Shdr> zElfSectionHeaderTable::toRaw() const {
    std::vector<Elf64_Shdr> out;
    out.reserve(elements.size());
    for (const auto& element : elements) {
        // 每个派生对象都能回写为标准 Elf64_Shdr。
        out.push_back(element->toShdr());
    }
    return out;
}

// 按节名查找索引（找不到返回 -1）。
int zElfSectionHeaderTable::findByName(const std::string& section_name) const {
    for (size_t idx = 0; idx < elements.size(); ++idx) {
        if (elements[idx]->resolved_name == section_name) {
            return (int)idx;
        }
    }
    // 未命中返回 -1，调用方据此决定是否创建/跳过。
    return -1;
}

// 获取可写 section 对象。
zSectionTableElement* zElfSectionHeaderTable::get(size_t idx) {
    return idx < elements.size() ? elements[idx].get() : nullptr;
}

// 获取只读 section 对象。
const zSectionTableElement* zElfSectionHeaderTable::get(size_t idx) const {
    return idx < elements.size() ? elements[idx].get() : nullptr;
}

