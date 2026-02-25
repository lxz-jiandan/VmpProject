#include "zElfTakeoverDynsym.h"

// strtoul。
#include <cstdlib>
// memcmp / strncmp。
#include <cstring>
// ELF 结构定义。
#include <elf.h>
// std::string。
#include <string>
// 哈希映射。
#include <unordered_map>
// 顺序容器。
#include <vector>

// 文件字节读取工具。
#include "zFileBytes.h"
// 日志。
#include "zLog.h"

namespace {

// 解析 takeover 槽位符号名：vm_takeover_slot_XXXX -> slot_id。
bool parseTakeoverSlotId(const char* symbol_name, uint32_t* out_slot_id) {
    // 输出参数必须有效。
    if (out_slot_id == nullptr || symbol_name == nullptr) {
        return false;
    }
    // 槽位符号固定前缀。
    static constexpr const char* kPrefix = "vm_takeover_slot_";
    // 前缀长度（不含 '\0'）。
    static constexpr size_t kPrefixLen = 17;
    // 前缀不匹配则不是槽位名。
    if (std::strncmp(symbol_name, kPrefix, kPrefixLen) != 0) {
        return false;
    }
    // 取前缀后的数字串。
    const char* digits = symbol_name + kPrefixLen;
    // 数字串不能为空。
    if (digits[0] == '\0') {
        return false;
    }
    // 必须全部是十进制数字。
    for (const char* p = digits; *p != '\0'; ++p) {
        if (*p < '0' || *p > '9') {
            return false;
        }
    }
    // 转成无符号长整型。
    const unsigned long slot = std::strtoul(digits, nullptr, 10);
    // 超出 uint32_t 范围则拒绝。
    if (slot > 0xFFFFFFFFUL) {
        return false;
    }
    // 回写解析结果。
    *out_slot_id = static_cast<uint32_t>(slot);
    return true;
}

} // namespace

// 从 patched vmengine so 的 dynsym/dynstr 恢复 takeover 表。
bool zElfRecoverTakeoverEntriesFromPatchedSo(
    const std::string& so_path,
    std::vector<zTakeoverSymbolEntry>& out_entries
) {
    // 每次调用先清空输出容器。
    out_entries.clear();
    // 整个 so 文件字节缓冲。
    std::vector<uint8_t> file_bytes;
    // 读取 so 文件到内存。
    if (!zFileBytes::readFileBytes(so_path, file_bytes)) {
        LOGE("[route_symbol_takeover] load vmengine file failed: %s", so_path.c_str());
        return false;
    }
    // 至少要容纳 ELF64 头。
    if (file_bytes.size() < sizeof(Elf64_Ehdr)) {
        LOGE("[route_symbol_takeover] vmengine file too small: %s", so_path.c_str());
        return false;
    }

    // 解释为 ELF64 头。
    const auto* ehdr = reinterpret_cast<const Elf64_Ehdr*>(file_bytes.data());
    // 校验魔数、位宽、小端。
    if (std::memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
        LOGE("[route_symbol_takeover] invalid elf header: %s", so_path.c_str());
        return false;
    }
    // 校验节表基本字段。
    if (ehdr->e_shoff == 0 || ehdr->e_shentsize != sizeof(Elf64_Shdr) || ehdr->e_shnum == 0) {
        LOGE("[route_symbol_takeover] invalid section table: %s", so_path.c_str());
        return false;
    }
    // 校验节表不越界。
    if (ehdr->e_shoff > file_bytes.size() ||
        static_cast<size_t>(ehdr->e_shoff) + static_cast<size_t>(ehdr->e_shnum) * sizeof(Elf64_Shdr) > file_bytes.size()) {
        LOGE("[route_symbol_takeover] section table out of range: %s", so_path.c_str());
        return false;
    }

    // 定位 section header 数组。
    const auto* shdrs = reinterpret_cast<const Elf64_Shdr*>(file_bytes.data() + ehdr->e_shoff);
    // dynsym 节。
    const Elf64_Shdr* dynsym_sh = nullptr;
    // dynstr 节。
    const Elf64_Shdr* dynstr_sh = nullptr;
    // 扫描 section 表定位 SHT_DYNSYM。
    for (uint16_t i = 0; i < ehdr->e_shnum; ++i) {
        if (shdrs[i].sh_type == SHT_DYNSYM) {
            dynsym_sh = &shdrs[i];
            // sh_link 指向关联字符串表。
            if (shdrs[i].sh_link < ehdr->e_shnum) {
                dynstr_sh = &shdrs[shdrs[i].sh_link];
            }
            break;
        }
    }
    // dynsym/dynstr 必须都存在且 dynstr 类型正确。
    if (dynsym_sh == nullptr || dynstr_sh == nullptr || dynstr_sh->sh_type != SHT_STRTAB) {
        LOGE("[route_symbol_takeover] dynsym/dynstr missing: %s", so_path.c_str());
        return false;
    }
    // dynsym 条目布局必须匹配 Elf64_Sym。
    if (dynsym_sh->sh_entsize != sizeof(Elf64_Sym) || dynsym_sh->sh_size < sizeof(Elf64_Sym)) {
        LOGE("[route_symbol_takeover] invalid dynsym layout: %s", so_path.c_str());
        return false;
    }
    // 校验 dynsym/dynstr 区间都在文件内。
    if (dynsym_sh->sh_offset > file_bytes.size() ||
        dynsym_sh->sh_size > file_bytes.size() - dynsym_sh->sh_offset ||
        dynstr_sh->sh_offset > file_bytes.size() ||
        dynstr_sh->sh_size > file_bytes.size() - dynstr_sh->sh_offset) {
        LOGE("[route_symbol_takeover] dynsym/dynstr out of range: %s", so_path.c_str());
        return false;
    }

    // dynsym 起始地址。
    const auto* dynsyms = reinterpret_cast<const Elf64_Sym*>(file_bytes.data() + dynsym_sh->sh_offset);
    // dynsym 条目数。
    const size_t dynsym_count = static_cast<size_t>(dynsym_sh->sh_size / sizeof(Elf64_Sym));
    // dynstr 起始地址。
    const char* dynstr = reinterpret_cast<const char*>(file_bytes.data() + dynstr_sh->sh_offset);
    // dynstr 字节长度。
    const size_t dynstr_size = static_cast<size_t>(dynstr_sh->sh_size);

    // 第一阶段映射：st_value -> slot_id（从 vm_takeover_slot_xxxx 符号提取）。
    std::unordered_map<uint64_t, uint32_t> slot_id_by_value;
    // 第二阶段映射：slot_id -> key（这里 key 使用普通符号 st_size 承载）。
    std::unordered_map<uint32_t, uint64_t> key_by_slot_id;

    // 第一遍：收集 slot 符号。
    for (size_t i = 1; i < dynsym_count; ++i) {
        // 跳过 dynsym[0]（保留空符号）。
        const Elf64_Sym& sym = dynsyms[i];
        // 名称偏移越界则跳过。
        if (sym.st_name >= dynstr_size) {
            continue;
        }
        // 取得符号名。
        const char* name = dynstr + sym.st_name;
        // 空名跳过。
        if (name[0] == '\0') {
            continue;
        }
        // 尝试解析 slot_id。
        uint32_t slot_id = 0;
        if (!parseTakeoverSlotId(name, &slot_id)) {
            continue;
        }
        // 用 st_value 建立 slot 映射。
        slot_id_by_value[static_cast<uint64_t>(sym.st_value)] = slot_id;
    }

    // 未找到任何 slot，直接失败。
    if (slot_id_by_value.empty()) {
        LOGE("[route_symbol_takeover] no takeover slots found in dynsym: %s", so_path.c_str());
        return false;
    }

    // 第二遍：从普通符号中恢复 slot_id -> key。
    for (size_t i = 1; i < dynsym_count; ++i) {
        const Elf64_Sym& sym = dynsyms[i];
        // 名称越界或未定义符号跳过。
        if (sym.st_name >= dynstr_size || sym.st_shndx == SHN_UNDEF) {
            continue;
        }
        // 读取符号名。
        const char* name = dynstr + sym.st_name;
        // 空名跳过。
        if (name[0] == '\0') {
            continue;
        }
        // slot 符号本身不参与 key 提取。
        uint32_t self_slot_id = 0;
        if (parseTakeoverSlotId(name, &self_slot_id)) {
            continue;
        }
        // 用 st_value 找对应 slot_id。
        const auto slot_it = slot_id_by_value.find(static_cast<uint64_t>(sym.st_value));
        if (slot_it == slot_id_by_value.end()) {
            continue;
        }
        const uint32_t slot_id = slot_it->second;
        // 当前实现把 key 编码在 st_size 字段。
        const uint64_t key = static_cast<uint64_t>(sym.st_size);
        // key 为 0 无效。
        if (key == 0) {
            continue;
        }
        // 同一 slot 出现不同 key 视为冲突。
        auto existed = key_by_slot_id.find(slot_id);
        if (existed != key_by_slot_id.end() && existed->second != key) {
            LOGE("[route_symbol_takeover] conflicting key for slot=%u: old=0x%llx new=0x%llx",
                 slot_id,
                 static_cast<unsigned long long>(existed->second),
                 static_cast<unsigned long long>(key));
            return false;
        }
        // 写入或覆盖同值。
        key_by_slot_id[slot_id] = key;
    }

    // 没拿到任何 key 也算失败。
    if (key_by_slot_id.empty()) {
        LOGE("[route_symbol_takeover] no takeover key entries found in dynsym: %s", so_path.c_str());
        return false;
    }

    // 输出条目数组。
    out_entries.reserve(key_by_slot_id.size());
    for (const auto& item : key_by_slot_id) {
        out_entries.push_back(zTakeoverSymbolEntry{item.first, item.second});
    }
    LOGI("[route_symbol_takeover] recovered slot entries from dynsym: slot_count=%llu",
         static_cast<unsigned long long>(out_entries.size()));
    return true;
}
