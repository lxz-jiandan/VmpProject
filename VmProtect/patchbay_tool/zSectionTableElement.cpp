#include "zSectionTableElement.h"
#include <cstring>

// ============================================================================
// 基类实现
// ============================================================================

// 基类默认解析逻辑：将原始字节直接保存为 payload。
void zSectionTableElement::parseFromBytes(const uint8_t* data, size_t data_size) {
    payload.clear();
    if (data && data_size > 0) {
        payload.assign(data, data + data_size);
    }
}

// 基类默认序列化逻辑：直接返回 payload。
std::vector<uint8_t> zSectionTableElement::toByteArray() const {
    return payload;
}

// 同步 header 中与 payload 相关的字段（NOBITS 不占文件内容）。
void zSectionTableElement::syncHeader() {
    if (type != SHT_NOBITS) {
        size = payload.size();
    }
}

// 返回解析后的 section 名称。
const std::string& zSectionTableElement::sectionName() const {
    return resolved_name;
}

// 返回 section 类型。
Elf64_Word zSectionTableElement::sectionType() const {
    return type;
}

// 返回 section 标志位。
Elf64_Xword zSectionTableElement::sectionFlags() const {
    return flags;
}

// 序列化为原始 Elf64_Shdr 结构。
Elf64_Shdr zSectionTableElement::toShdr() const {
    Elf64_Shdr sh{};
    sh.sh_name = name;
    sh.sh_type = type;
    sh.sh_flags = flags;
    sh.sh_addr = addr;
    sh.sh_offset = offset;
    sh.sh_size = size;
    sh.sh_link = link;
    sh.sh_info = info;
    sh.sh_addralign = addralign;
    sh.sh_entsize = entsize;
    return sh;
}

// 从原始 Elf64_Shdr 反序列化字段并做最小规范化处理。
void zSectionTableElement::fromShdr(const Elf64_Shdr& shdr) {
    name = shdr.sh_name;
    type = shdr.sh_type;
    flags = shdr.sh_flags;
    addr = shdr.sh_addr;
    offset = shdr.sh_offset;
    size = shdr.sh_size;
    link = shdr.sh_link;
    info = shdr.sh_info;
    addralign = shdr.sh_addralign == 0 ? 1 : shdr.sh_addralign;
    entsize = shdr.sh_entsize;
}

// ============================================================================
// 派生类实现：zStrTabSection
// ============================================================================

// 向字符串表追加一个以 '\0' 结尾的字符串，返回其起始偏移。
uint32_t zStrTabSection::addString(const std::string& value) {
    if (payload.empty()) {
        payload.push_back('\0');
    }
    const uint32_t off = (uint32_t)payload.size();
    payload.insert(payload.end(), value.begin(), value.end());
    payload.push_back('\0');
    syncHeader();
    return off;
}

// 按偏移获取字符串指针；越界返回 nullptr。
const char* zStrTabSection::getStringAt(uint32_t off) const {
    if (off >= payload.size()) {
        return nullptr;
    }
    return reinterpret_cast<const char*>(payload.data() + off);
}

// ============================================================================
// 派生类实现：zSymbolSection
// ============================================================================

// 解析符号表：读取 payload 并按 Elf64_Sym 切分。
void zSymbolSection::parseFromBytes(const uint8_t* data, size_t data_size) {
    zSectionTableElement::parseFromBytes(data, data_size);
    symbols.clear();
    if (payload.empty()) {
        return;
    }
    const size_t entry_size = entsize == 0 ? sizeof(Elf64_Sym) : (size_t)entsize;
    if (entry_size != sizeof(Elf64_Sym) || (payload.size() % entry_size) != 0) {
        return;
    }
    const size_t count = payload.size() / sizeof(Elf64_Sym);
    symbols.resize(count);
    std::memcpy(symbols.data(), payload.data(), payload.size());
}

// 将符号数组序列化回字节；若未维护 symbols，则回退使用 payload。
std::vector<uint8_t> zSymbolSection::toByteArray() const {
    if (symbols.empty()) {
        return zSectionTableElement::toByteArray();
    }
    std::vector<uint8_t> bytes(symbols.size() * sizeof(Elf64_Sym));
    std::memcpy(bytes.data(), symbols.data(), bytes.size());
    return bytes;
}

// 同步节头：更新 payload、entsize 与 size。
void zSymbolSection::syncHeader() {
    payload = toByteArray();
    entsize = sizeof(Elf64_Sym);
    zSectionTableElement::syncHeader();
}

// 返回符号数量。
size_t zSymbolSection::symbolCount() const {
    return symbols.size();
}

// ============================================================================
// 派生类实现：zDynamicSection
// ============================================================================

// 解析 `.dynamic` 节：先复用基类读取 payload，再按 Elf64_Dyn 切分条目。
void zDynamicSection::parseFromBytes(const uint8_t* data, size_t data_size) {
    zSectionTableElement::parseFromBytes(data, data_size);
    entries.clear();
    if (payload.empty()) {
        return;
    }
    const size_t entry_size = entsize == 0 ? sizeof(Elf64_Dyn) : (size_t)entsize;
    if (entry_size != sizeof(Elf64_Dyn) || (payload.size() % entry_size) != 0) {
        return;
    }
    const size_t count = payload.size() / sizeof(Elf64_Dyn);
    entries.resize(count);
    std::memcpy(entries.data(), payload.data(), payload.size());
}

// 将动态条目序列化回字节；若当前未维护 entries，则回退使用基类 payload。
std::vector<uint8_t> zDynamicSection::toByteArray() const {
    if (entries.empty()) {
        return zSectionTableElement::toByteArray();
    }
    std::vector<uint8_t> bytes(entries.size() * sizeof(Elf64_Dyn));
    std::memcpy(bytes.data(), entries.data(), bytes.size());
    return bytes;
}

// 同步 section header：确保 payload/entsize 与动态条目一致。
void zDynamicSection::syncHeader() {
    payload = toByteArray();
    entsize = sizeof(Elf64_Dyn);
    zSectionTableElement::syncHeader();
}

// 返回当前动态表条目数。
size_t zDynamicSection::entryCount() const {
    return entries.size();
}

// ============================================================================
// 派生类实现：zRelocationSection
// ============================================================================

// 解析重定位节：根据 section 类型区分 RELA 与 REL。
void zRelocationSection::parseFromBytes(const uint8_t* data, size_t data_size) {
    zSectionTableElement::parseFromBytes(data, data_size);
    relocations.clear();
    rel_relocations.clear();
    if (payload.empty()) {
        return;
    }
    if (type == SHT_REL) {
        const size_t entry_size = entsize == 0 ? sizeof(Elf64_Rel) : (size_t)entsize;
        if (entry_size != sizeof(Elf64_Rel) || (payload.size() % entry_size) != 0) {
            return;
        }
        const size_t count = payload.size() / sizeof(Elf64_Rel);
        rel_relocations.resize(count);
        std::memcpy(rel_relocations.data(), payload.data(), payload.size());
        return;
    }

    const size_t entry_size = entsize == 0 ? sizeof(Elf64_Rela) : (size_t)entsize;
    if (entry_size != sizeof(Elf64_Rela) || (payload.size() % entry_size) != 0) {
        return;
    }
    const size_t count = payload.size() / sizeof(Elf64_Rela);
    relocations.resize(count);
    std::memcpy(relocations.data(), payload.data(), payload.size());
}

// 序列化重定位条目：按当前类型输出 REL 或 RELA 字节流。
std::vector<uint8_t> zRelocationSection::toByteArray() const {
    if (type == SHT_REL) {
        if (rel_relocations.empty()) {
            return zSectionTableElement::toByteArray();
        }
        std::vector<uint8_t> bytes(rel_relocations.size() * sizeof(Elf64_Rel));
        std::memcpy(bytes.data(), rel_relocations.data(), bytes.size());
        return bytes;
    }
    if (relocations.empty()) {
        return zSectionTableElement::toByteArray();
    }
    std::vector<uint8_t> bytes(relocations.size() * sizeof(Elf64_Rela));
    std::memcpy(bytes.data(), relocations.data(), bytes.size());
    return bytes;
}

// 同步 header：更新 payload、entsize 与 size。
void zRelocationSection::syncHeader() {
    payload = toByteArray();
    entsize = type == SHT_REL ? sizeof(Elf64_Rel) : sizeof(Elf64_Rela);
    zSectionTableElement::syncHeader();
}

// 返回当前重定位条目总数。
size_t zRelocationSection::relocationCount() const {
    if (type == SHT_REL) {
        return rel_relocations.size();
    }
    return relocations.size();
}
