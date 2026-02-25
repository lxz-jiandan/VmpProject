#include "zSectionEntry.h"
// memcpy/memchr。
#include <cstring>

// ============================================================================
// 基类实现
// ============================================================================

// 基类默认解析逻辑：将原始字节直接保存为 payload。
void zSectionTableElement::parseFromBytes(const uint8_t* data, size_t data_size) {
    // 清空旧 payload。
    payload.clear();
    // 有输入时才复制。
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
    // 非 NOBITS 节才按 payload 更新 sh_size。
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
    // 零初始化 shdr。
    Elf64_Shdr sh{};
    // 节名在 shstrtab 中的偏移。
    sh.sh_name = name;
    // 节类型。
    sh.sh_type = type;
    // 节标志位。
    sh.sh_flags = flags;
    // 节虚拟地址。
    sh.sh_addr = addr;
    // 节文件偏移。
    sh.sh_offset = offset;
    // 节大小。
    sh.sh_size = size;
    // 关联节索引（如符号节的字符串表）。
    sh.sh_link = link;
    // 额外信息字段。
    sh.sh_info = info;
    // 节对齐。
    sh.sh_addralign = addralign;
    // 表项大小（如符号节项大小）。
    sh.sh_entsize = entsize;
    return sh;
}

// 从原始 Elf64_Shdr 反序列化字段并做最小规范化处理。
void zSectionTableElement::fromShdr(const Elf64_Shdr& shdr) {
    // 复制名称偏移。
    name = shdr.sh_name;
    // 复制类型。
    type = shdr.sh_type;
    // 复制标志位。
    flags = shdr.sh_flags;
    // 复制虚拟地址。
    addr = shdr.sh_addr;
    // 复制文件偏移。
    offset = shdr.sh_offset;
    // 复制大小。
    size = shdr.sh_size;
    // 复制 link。
    link = shdr.sh_link;
    // 复制 info。
    info = shdr.sh_info;
    // 对齐为 0 时按 ELF 约定规范化为 1。
    addralign = shdr.sh_addralign == 0 ? 1 : shdr.sh_addralign;
    // 复制条目大小。
    entsize = shdr.sh_entsize;
}

// ============================================================================
// 派生类实现：zStrTabSection
// ============================================================================

// 向字符串表追加一个以 '\0' 结尾的字符串，返回其起始偏移。
uint32_t zStrTabSection::addString(const std::string& value) {
    // 字符串表第一个字节必须是 '\0'，表示空串。
    if (payload.empty()) {
        payload.push_back('\0');
    }
    // 新字符串起始偏移。
    const uint32_t off = (uint32_t)payload.size();
    // 追加字符串内容。
    payload.insert(payload.end(), value.begin(), value.end());
    // 追加终止符。
    payload.push_back('\0');
    // 同步 sh_size。
    syncHeader();
    return off;
}

// 按偏移获取字符串指针；越界返回 nullptr。
const char* zStrTabSection::getStringAt(uint32_t off) const {
    // 越界保护。
    if (off >= payload.size()) {
        return nullptr;
    }
    // 返回 C 字符串首指针。
    return reinterpret_cast<const char*>(payload.data() + off);
}

// ============================================================================
// 派生类实现：zSymbolSection
// ============================================================================

// 解析符号表：读取 payload 并按 Elf64_Sym 切分。
void zSymbolSection::parseFromBytes(const uint8_t* data, size_t data_size) {
    // 先走基类，填充 payload。
    zSectionTableElement::parseFromBytes(data, data_size);
    // 清空旧 symbols。
    symbols.clear();
    // 空 payload 直接返回。
    if (payload.empty()) {
        return;
    }
    // 条目大小：优先用 sh_entsize，缺省回退 sizeof(Elf64_Sym)。
    const size_t entry_size = entsize == 0 ? sizeof(Elf64_Sym) : (size_t)entsize;
    // 条目大小不匹配或 payload 不能整除时认为格式异常。
    if (entry_size != sizeof(Elf64_Sym) || (payload.size() % entry_size) != 0) {
        return;
    }
    // 计算符号项个数。
    const size_t count = payload.size() / sizeof(Elf64_Sym);
    // 分配 symbols。
    symbols.resize(count);
    // 从 payload 拷贝到结构体数组。
    std::memcpy(symbols.data(), payload.data(), payload.size());
}

// 将符号数组序列化回字节；若未维护 symbols，则回退使用 payload。
std::vector<uint8_t> zSymbolSection::toByteArray() const {
    // 若 symbols 为空则沿用基类 payload。
    if (symbols.empty()) {
        return zSectionTableElement::toByteArray();
    }
    // 按符号项个数分配字节数组。
    std::vector<uint8_t> bytes(symbols.size() * sizeof(Elf64_Sym));
    // 结构体数组拷贝为连续字节。
    std::memcpy(bytes.data(), symbols.data(), bytes.size());
    return bytes;
}

// 同步节头：更新 payload、entsize 与 size。
void zSymbolSection::syncHeader() {
    // 先按 symbols 生成 payload。
    payload = toByteArray();
    // 记录符号项大小。
    entsize = sizeof(Elf64_Sym);
    // 调用基类同步 size。
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
    // 先填充 payload。
    zSectionTableElement::parseFromBytes(data, data_size);
    // 清空旧动态项。
    entries.clear();
    // 空 payload 直接返回。
    if (payload.empty()) {
        return;
    }
    // 条目大小：优先用 sh_entsize，缺省回退 sizeof(Elf64_Dyn)。
    const size_t entry_size = entsize == 0 ? sizeof(Elf64_Dyn) : (size_t)entsize;
    // 条目大小异常或 payload 非整项对齐时停止解析。
    if (entry_size != sizeof(Elf64_Dyn) || (payload.size() % entry_size) != 0) {
        return;
    }
    // 动态项个数。
    const size_t count = payload.size() / sizeof(Elf64_Dyn);
    // 分配 entries。
    entries.resize(count);
    // 拷贝动态项。
    std::memcpy(entries.data(), payload.data(), payload.size());
}

// 将动态条目序列化回字节；若当前未维护 entries，则回退使用基类 payload。
std::vector<uint8_t> zDynamicSection::toByteArray() const {
    // 无 entries 时返回现有 payload。
    if (entries.empty()) {
        return zSectionTableElement::toByteArray();
    }
    // 分配目标字节数组。
    std::vector<uint8_t> bytes(entries.size() * sizeof(Elf64_Dyn));
    // 序列化动态项。
    std::memcpy(bytes.data(), entries.data(), bytes.size());
    return bytes;
}

// 同步 section header：确保 payload/entsize 与动态条目一致。
void zDynamicSection::syncHeader() {
    // 回写 payload。
    payload = toByteArray();
    // 记录动态项大小。
    entsize = sizeof(Elf64_Dyn);
    // 调用基类同步 size。
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
    // 先填充 payload。
    zSectionTableElement::parseFromBytes(data, data_size);
    // 清空 RELA 容器。
    relocations.clear();
    // 清空 REL 容器。
    rel_relocations.clear();
    // 空 payload 直接返回。
    if (payload.empty()) {
        return;
    }

    // REL 节路径。
    if (type == SHT_REL) {
        // 条目大小：优先 sh_entsize，缺省 sizeof(Elf64_Rel)。
        const size_t entry_size = entsize == 0 ? sizeof(Elf64_Rel) : (size_t)entsize;
        // 条目大小异常或非整项对齐时返回。
        if (entry_size != sizeof(Elf64_Rel) || (payload.size() % entry_size) != 0) {
            return;
        }
        // 计算 REL 条目数。
        const size_t count = payload.size() / sizeof(Elf64_Rel);
        // 分配 REL 数组。
        rel_relocations.resize(count);
        // 复制 REL 条目。
        std::memcpy(rel_relocations.data(), payload.data(), payload.size());
        return;
    }

    // RELA 节路径。
    const size_t entry_size = entsize == 0 ? sizeof(Elf64_Rela) : (size_t)entsize;
    // 条目大小异常或非整项对齐时返回。
    if (entry_size != sizeof(Elf64_Rela) || (payload.size() % entry_size) != 0) {
        return;
    }
    // 计算 RELA 条目数。
    const size_t count = payload.size() / sizeof(Elf64_Rela);
    // 分配 RELA 数组。
    relocations.resize(count);
    // 复制 RELA 条目。
    std::memcpy(relocations.data(), payload.data(), payload.size());
}

// 序列化重定位条目：按当前类型输出 REL 或 RELA 字节流。
std::vector<uint8_t> zRelocationSection::toByteArray() const {
    // REL 输出路径。
    if (type == SHT_REL) {
        // 无 REL 结构数据时回退基类 payload。
        if (rel_relocations.empty()) {
            return zSectionTableElement::toByteArray();
        }
        // 分配 REL 字节缓冲。
        std::vector<uint8_t> bytes(rel_relocations.size() * sizeof(Elf64_Rel));
        // 序列化 REL。
        std::memcpy(bytes.data(), rel_relocations.data(), bytes.size());
        return bytes;
    }
    // RELA 输出路径：无结构数据时回退基类 payload。
    if (relocations.empty()) {
        return zSectionTableElement::toByteArray();
    }
    // 分配 RELA 字节缓冲。
    std::vector<uint8_t> bytes(relocations.size() * sizeof(Elf64_Rela));
    // 序列化 RELA。
    std::memcpy(bytes.data(), relocations.data(), bytes.size());
    return bytes;
}

// 同步 header：更新 payload、entsize 与 size。
void zRelocationSection::syncHeader() {
    // 回写 payload。
    payload = toByteArray();
    // 根据节类型设置 entsize。
    entsize = type == SHT_REL ? sizeof(Elf64_Rel) : sizeof(Elf64_Rela);
    // 调用基类同步 size。
    zSectionTableElement::syncHeader();
}

// 返回当前重定位条目总数。
size_t zRelocationSection::relocationCount() const {
    // REL 节返回 REL 数量。
    if (type == SHT_REL) {
        return rel_relocations.size();
    }
    // 其他返回 RELA 数量。
    return relocations.size();
}
