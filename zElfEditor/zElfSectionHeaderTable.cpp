#include "zElfSectionHeaderTable.h"

// 根据 section 类型与名称选择合适的模型派生类（所有类定义在同一文件以减少文件数量）。
static std::unique_ptr<zSectionTableElement> create_section_element_from_shdr(const Elf64_Shdr& raw,
                                                                               const std::string& section_name) {
    if (raw.sh_type == SHT_STRTAB) {
        return std::make_unique<zStrTabSection>();
    }
    if (raw.sh_type == SHT_DYNAMIC || section_name == ".dynamic") {
        return std::make_unique<zDynamicSection>();
    }
    if (raw.sh_type == SHT_SYMTAB || raw.sh_type == SHT_DYNSYM ||
        section_name == ".symtab" || section_name == ".dynsym") {
        return std::make_unique<zSymbolSection>();
    }
    if (raw.sh_type == SHT_RELA || raw.sh_type == SHT_REL || section_name.rfind(".rela", 0) == 0) {
        return std::make_unique<zRelocationSection>();
    }
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
        return true;
    }

    const char* shstr = nullptr;
    size_t shstr_size = 0;
    if (shstrndx < section_count) {
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
            resolved_name = std::string(shstr + raw.sh_name);
        }
        std::unique_ptr<zSectionTableElement> item = create_section_element_from_shdr(raw, resolved_name);

        item->fromShdr(raw);
        item->resolved_name = std::move(resolved_name);

        if (raw.sh_type != SHT_NOBITS && raw.sh_size > 0) {
            if ((uint64_t)raw.sh_offset + raw.sh_size > file_size) {
                return false;
            }
            item->parseFromBytes(file_data + raw.sh_offset, (size_t)raw.sh_size);
        }
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

