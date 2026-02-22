/**
 * @file zElfAddressRewriter.cpp
 * @brief 地址平移后的引用修复实现。
 *
 * 当注入或重构导致虚拟地址整体移动时，ELF 内部大量“写死地址”
 * 需要同步更新。该文件负责处理两大类结构：
 * - 常规结构：`.dynamic`、`.rela*`/`.rel*` 等
 * - 打包结构：`DT_RELR`、Android APS2（`DT_ANDROID_REL/RELA`）
 *
 * 设计要点：
 * - 尽量优先按 PT_LOAD 映射访问 file_image_；
 * - 无法映射时回退到 section payload；
 * - 保持“可回写”并在必要时标记重构脏状态。
 */

#include "zElf.h"
#include "zElfUtils.h"
#include "zLog.h"

#include <algorithm>
#include <cstring>
#include <cstdint>
#include <limits>
#include <unordered_map>
#include <vector>

namespace {

// 回退读取：在 ALLOC 节 payload 中按地址读取 64 位值。
bool read_u64_from_alloc_sections_legacy_fallback(const zElf& elf, Elf64_Addr addr, uint64_t* out_value) {
    if (!out_value) {
        return false;
    }
    for (const auto& section_ptr : elf.sectionHeaderModel().elements) {
        const auto* sec = section_ptr.get();
        if (!sec || (sec->flags & SHF_ALLOC) == 0 || sec->payload.empty()) {
            continue;
        }
        if (!contains_addr_range_u64(sec->addr, sec->size, addr, sizeof(uint64_t))) {
            continue;
        }
        const uint64_t off = (uint64_t)addr - sec->addr;
        if (off + sizeof(uint64_t) > sec->payload.size()) {
            return false;
        }
        std::memcpy(out_value, sec->payload.data() + off, sizeof(uint64_t));
        return true;
    }
    return false;
}

// 回退写入：在 ALLOC 节 payload 中按地址写入 64 位值。
bool write_u64_to_alloc_sections_legacy_fallback(zElf* elf, Elf64_Addr addr, uint64_t value) {
    if (!elf) {
        return false;
    }
    for (auto& section_ptr : elf->sectionHeaderModel().elements) {
        auto* sec = section_ptr.get();
        if (!sec || (sec->flags & SHF_ALLOC) == 0 || sec->payload.empty()) {
            continue;
        }
        if (!contains_addr_range_u64(sec->addr, sec->size, addr, sizeof(uint64_t))) {
            continue;
        }
        const uint64_t off = (uint64_t)addr - sec->addr;
        if (off + sizeof(uint64_t) > sec->payload.size()) {
            return false;
        }
        std::memcpy(sec->payload.data() + off, &value, sizeof(uint64_t));
        sec->syncHeader();
        return true;
    }
    return false;
}

// 将虚拟地址区间映射到文件偏移（要求完整落入某个 PT_LOAD 的 filesz 范围）。
static bool map_vaddr_range_to_file(const zElf& elf,
                            Elf64_Addr vaddr,
                            uint64_t size,
                            Elf64_Off* out_off) {
    if (!out_off) {
        return false;
    }
    if (size == 0) {
        return false;
    }

    const uint64_t begin = (uint64_t)vaddr;
    uint64_t end = 0;
    if (!add_u64_checked(begin, size, &end)) {
        return false;
    }

    for (const auto& ph : elf.programHeaderModel().elements) {
        if (ph.type != PT_LOAD || ph.filesz == 0 || ph.memsz == 0) {
            continue;
        }

        const uint64_t seg_va_begin = (uint64_t)ph.vaddr;
        uint64_t seg_va_end = 0;
        if (!add_u64_checked(seg_va_begin, (uint64_t)ph.memsz, &seg_va_end)) {
            continue;
        }
        if (begin < seg_va_begin || end > seg_va_end) {
            continue;
        }

        const uint64_t rel_begin = begin - seg_va_begin;
        const uint64_t rel_end = rel_begin + size;
        if (rel_end > (uint64_t)ph.filesz) {
            continue;
        }

        uint64_t off = 0;
        if (!add_u64_checked((uint64_t)ph.offset, rel_begin, &off)) {
            continue;
        }
        if (off > std::numeric_limits<Elf64_Off>::max()) {
            continue;
        }
        *out_off = (Elf64_Off)off;
        return true;
    }
    return false;
}

// 判断指定 RELA 类型是否需要对 addend 做地址重定位。
bool should_relocate_rela_addend(uint32_t rel_type, uint32_t rel_sym) {
    constexpr uint32_t R_AARCH64_RELATIVE_TYPE = 1027U;
    constexpr uint32_t R_AARCH64_GLOB_DAT_TYPE = 1025U;
    constexpr uint32_t R_AARCH64_JUMP_SLOT_TYPE = 1026U;
    constexpr uint32_t R_AARCH64_IRELATIVE_TYPE = 1032U;
    constexpr uint32_t R_AARCH64_ABS64_TYPE = 257U;
    constexpr uint32_t R_AARCH64_TLSDESC_TYPE = 1031U;

    if (rel_type == R_AARCH64_RELATIVE_TYPE && rel_sym == 0) {
        return true;
    }
    if (rel_type == R_AARCH64_IRELATIVE_TYPE) {
        return true;
    }
    if (rel_type == R_AARCH64_ABS64_TYPE ||
        rel_type == R_AARCH64_GLOB_DAT_TYPE ||
        rel_type == R_AARCH64_JUMP_SLOT_TYPE ||
        rel_type == R_AARCH64_TLSDESC_TYPE) {
        return true;
    }
    return false;
}

// 解码 DT_RELR 压缩流，输出每个重定位槽地址。
bool decode_relr_addresses(const uint8_t* data,
                          size_t size,
                          std::vector<uint64_t>* out_addresses,
                          std::string* error) {
    if (!data || !out_addresses) {
        if (error) {
            *error = "Invalid RELR decode input";
        }
        return false;
    }
    out_addresses->clear();
    if (size == 0) {
        return true;
    }
    if ((size % sizeof(Elf64_Addr)) != 0) {
        if (error) {
            *error = "DT_RELR table size is not aligned to Elf64_Addr";
        }
        return false;
    }

    const size_t count = size / sizeof(Elf64_Addr);
    uint64_t where = 0;
    bool where_initialized = false;

    for (size_t idx = 0; idx < count; ++idx) {
        uint64_t entry = 0;
        std::memcpy(&entry, data + idx * sizeof(Elf64_Addr), sizeof(uint64_t));

        if ((entry & 1ULL) == 0) {
            out_addresses->push_back(entry);
            where = entry + sizeof(Elf64_Addr);
            where_initialized = true;
            continue;
        }

        if (!where_initialized) {
            if (error) {
                *error = "Invalid DT_RELR stream: bitmap appears before base address";
            }
            return false;
        }

        uint64_t bitmap = entry >> 1;
        for (uint32_t bit = 0; bit < 63; ++bit) {
            if ((bitmap & (1ULL << bit)) == 0) {
                continue;
            }
            const uint64_t delta = (uint64_t)bit * sizeof(Elf64_Addr);
            if (std::numeric_limits<uint64_t>::max() - where < delta) {
                if (error) {
                    *error = "DT_RELR decoded address overflow";
                }
                return false;
            }
            const uint64_t reloc_addr = where + delta;
            out_addresses->push_back(reloc_addr);
        }

        const uint64_t advance = (uint64_t)(63) * sizeof(Elf64_Addr);
        if (std::numeric_limits<uint64_t>::max() - where < advance) {
            if (error) {
                *error = "DT_RELR decode cursor overflow";
            }
            return false;
        }
        where += advance;
    }

    return true;
}

// 将重定位槽地址重新编码为 DT_RELR 压缩流。
bool encode_relr_addresses(const std::vector<uint64_t>& addresses,
                          std::vector<uint8_t>* out_bytes,
                          std::string* error) {
    if (!out_bytes) {
        if (error) {
            *error = "Invalid RELR encode output buffer";
        }
        return false;
    }

    out_bytes->clear();
    if (addresses.empty()) {
        return true;
    }

    std::vector<uint64_t> sorted = addresses;
    std::sort(sorted.begin(), sorted.end());
    sorted.erase(std::unique(sorted.begin(), sorted.end()), sorted.end());

    for (uint64_t addr : sorted) {
        if ((addr % sizeof(Elf64_Addr)) != 0) {
            if (error) {
                *error = "DT_RELR address is not aligned to Elf64_Addr";
            }
            return false;
        }
    }

    std::vector<uint64_t> entries;
    entries.reserve(sorted.size());

    size_t idx = 0;
    while (idx < sorted.size()) {
        const uint64_t base = sorted[idx++];
        entries.push_back(base);

        if (std::numeric_limits<uint64_t>::max() - base < sizeof(Elf64_Addr)) {
            if (error) {
                *error = "DT_RELR encode cursor overflow";
            }
            return false;
        }
        const uint64_t where = base + sizeof(Elf64_Addr);

        uint64_t bitmap = 0;
        while (idx < sorted.size()) {
            const uint64_t addr = sorted[idx];
            if (addr < where) {
                ++idx;
                continue;
            }
            const uint64_t delta = addr - where;
            if ((delta % sizeof(Elf64_Addr)) != 0) {
                break;
            }
            const uint64_t bit = delta / sizeof(Elf64_Addr);
            if (bit >= 63) {
                break;
            }
            bitmap |= (1ULL << bit);
            ++idx;
        }

        if (bitmap != 0) {
            entries.push_back((bitmap << 1) | 1ULL);
        }
    }

    out_bytes->resize(entries.size() * sizeof(uint64_t));
    std::memcpy(out_bytes->data(), entries.data(), out_bytes->size());
    return true;
}

bool read_uleb128_at(const uint8_t* data,
                    size_t size,
                    size_t* cursor,
                    uint64_t* out_value) {
    if (!data || !cursor || !out_value) {
        return false;
    }
    uint64_t value = 0;
    uint32_t shift = 0;
    for (uint32_t i = 0; i < 10; ++i) {
        if (*cursor >= size) {
            return false;
        }
        const uint8_t byte = data[*cursor];
        ++(*cursor);
        value |= ((uint64_t)(byte & 0x7f)) << shift;
        if ((byte & 0x80) == 0) {
            *out_value = value;
            return true;
        }
        shift += 7;
    }
    return false;
}

void write_uleb128(uint64_t value, std::vector<uint8_t>* out) {
    if (!out) {
        return;
    }
    do {
        uint8_t byte = (uint8_t)(value & 0x7f);
        value >>= 7;
        if (value != 0) {
            byte |= 0x80;
        }
        out->push_back(byte);
    } while (value != 0);
}

bool read_sleb128_at(const uint8_t* data,
                    size_t size,
                    size_t* cursor,
                    int64_t* out_value) {
    if (!data || !cursor || !out_value) {
        return false;
    }
    int64_t value = 0;
    uint32_t shift = 0;
    uint8_t byte = 0;
    for (uint32_t i = 0; i < 10; ++i) {
        if (*cursor >= size) {
            return false;
        }
        byte = data[*cursor];
        ++(*cursor);
        value |= ((int64_t)(byte & 0x7f)) << shift;
        shift += 7;
        if ((byte & 0x80) == 0) {
            break;
        }
    }
    if ((byte & 0x80) != 0) {
        return false;
    }
    if ((shift < 64) && (byte & 0x40)) {
        value |= (~0LL) << shift;
    }
    *out_value = value;
    return true;
}

void write_sleb128(int64_t value, std::vector<uint8_t>* out) {
    if (!out) {
        return;
    }
    bool more = true;
    while (more) {
        uint8_t byte = (uint8_t)(value & 0x7f);
        const bool sign = (byte & 0x40) != 0;
        value >>= 7;
        if ((value == 0 && !sign) || (value == -1 && sign)) {
            more = false;
        } else {
            byte |= 0x80;
        }
        out->push_back(byte);
    }
}

struct AndroidPackedRelocationEntry {
    uint64_t offset = 0;
    uint64_t info = 0;
    bool has_addend = false;
    int64_t addend = 0;
};

// 解码 Android APS2 打包重定位流。
bool decode_android_aps2_relocations(const uint8_t* data,
                                     size_t size,
                                     std::vector<AndroidPackedRelocationEntry>* out_entries,
                                     std::string* error) {
    if (!data || !out_entries) {
        if (error) {
            *error = "Invalid APS2 decode input";
        }
        return false;
    }
    out_entries->clear();
    if (size < 4 || std::memcmp(data, "APS2", 4) != 0) {
        if (error) {
            *error = "Android packed relocation header is not APS2";
        }
        return false;
    }

    size_t cursor = 4;
    uint64_t reloc_count = 0;
    uint64_t initial_offset = 0;
    if (!read_uleb128_at(data, size, &cursor, &reloc_count) ||
        !read_uleb128_at(data, size, &cursor, &initial_offset)) {
        if (error) {
            *error = "Failed to read APS2 relocation header";
        }
        return false;
    }

    uint64_t current_offset = initial_offset;
    out_entries->reserve((size_t)reloc_count);

    while (out_entries->size() < reloc_count) {
        uint64_t group_size = 0;
        uint64_t group_flags = 0;
        if (!read_uleb128_at(data, size, &cursor, &group_size) ||
            !read_uleb128_at(data, size, &cursor, &group_flags)) {
            if (error) {
                *error = "Failed to read APS2 group header";
            }
            return false;
        }
        if (group_size == 0) {
            if (error) {
                *error = "APS2 group_size is zero";
            }
            return false;
        }

        const bool grouped_by_info = (group_flags & 1ULL) != 0;
        const bool grouped_by_offset_delta = (group_flags & 2ULL) != 0;
        const bool grouped_by_addend = (group_flags & 4ULL) != 0;
        const bool has_addend = (group_flags & 8ULL) != 0;

        uint64_t grouped_delta = 0;
        if (grouped_by_offset_delta && !read_uleb128_at(data, size, &cursor, &grouped_delta)) {
            if (error) {
                *error = "Failed to read APS2 grouped offset delta";
            }
            return false;
        }

        uint64_t grouped_info = 0;
        if (grouped_by_info && !read_uleb128_at(data, size, &cursor, &grouped_info)) {
            if (error) {
                *error = "Failed to read APS2 grouped relocation info";
            }
            return false;
        }

        int64_t grouped_addend = 0;
        if (has_addend && grouped_by_addend && !read_sleb128_at(data, size, &cursor, &grouped_addend)) {
            if (error) {
                *error = "Failed to read APS2 grouped addend";
            }
            return false;
        }

        for (uint64_t i = 0; i < group_size && out_entries->size() < reloc_count; ++i) {
            uint64_t delta = grouped_delta;
            if (!grouped_by_offset_delta && !read_uleb128_at(data, size, &cursor, &delta)) {
                if (error) {
                    *error = "Failed to read APS2 relocation delta";
                }
                return false;
            }
            if (std::numeric_limits<uint64_t>::max() - current_offset < delta) {
                if (error) {
                    *error = "APS2 relocation offset overflow";
                }
                return false;
            }
            current_offset += delta;

            uint64_t info = grouped_info;
            if (!grouped_by_info && !read_uleb128_at(data, size, &cursor, &info)) {
                if (error) {
                    *error = "Failed to read APS2 relocation info";
                }
                return false;
            }

            int64_t addend = grouped_addend;
            if (has_addend && !grouped_by_addend && !read_sleb128_at(data, size, &cursor, &addend)) {
                if (error) {
                    *error = "Failed to read APS2 relocation addend";
                }
                return false;
            }

            AndroidPackedRelocationEntry entry;
            entry.offset = current_offset;
            entry.info = info;
            entry.has_addend = has_addend;
            entry.addend = addend;
            out_entries->push_back(entry);
        }
    }

    return out_entries->size() == reloc_count;
}

// 将 APS2 重定位条目重新编码为字节流。
bool encode_android_aps2_relocations(const std::vector<AndroidPackedRelocationEntry>& entries,
                                     size_t max_size,
                                     std::vector<uint8_t>* out_bytes,
                                     std::string* error) {
    if (!out_bytes) {
        if (error) {
            *error = "Invalid APS2 encode output";
        }
        return false;
    }
    out_bytes->clear();
    if (entries.empty()) {
        if (error) {
            *error = "No APS2 relocations to encode";
        }
        return false;
    }

    for (size_t i = 1; i < entries.size(); ++i) {
        if (entries[i].offset < entries[i - 1].offset) {
            if (error) {
                *error = "APS2 offsets are not non-decreasing after relocation";
            }
            return false;
        }
    }

    out_bytes->insert(out_bytes->end(), {'A', 'P', 'S', '2'});
    write_uleb128(entries.size(), out_bytes);
    write_uleb128(0, out_bytes);

    uint64_t prev_offset = 0;
    for (const auto& entry : entries) {
        if (entry.offset < prev_offset) {
            if (error) {
                *error = "APS2 offset underflow while encoding";
            }
            return false;
        }
        const uint64_t delta = entry.offset - prev_offset;

        const uint64_t group_flags = entry.has_addend ? 8ULL : 0ULL;
        write_uleb128(1, out_bytes);
        write_uleb128(group_flags, out_bytes);
        write_uleb128(delta, out_bytes);
        write_uleb128(entry.info, out_bytes);
        if (entry.has_addend) {
            write_sleb128(entry.addend, out_bytes);
        }

        prev_offset = entry.offset;
    }

    if (max_size > 0 && out_bytes->size() > max_size) {
        if (error) {
            *error = "Re-encoded APS2 data exceeds original size";
        }
        return false;
    }
    return true;
}

} // namespace

// 先走 PT_LOAD 映射读，再回退 ALLOC 节读取。
bool zElfAddressRewriter::readU64MappedSegmentFirst(const zElf* elf, Elf64_Addr addr, uint64_t* out_value) {
    if (!elf || !out_value) {
        return false;
    }
    Elf64_Off slot_off = 0;
    if (map_vaddr_range_to_file(*elf, addr, sizeof(uint64_t), &slot_off) &&
        (uint64_t)slot_off + sizeof(uint64_t) <= elf->file_image_.size()) {
        std::memcpy(out_value, elf->file_image_.data() + slot_off, sizeof(uint64_t));
        return true;
    }
    return read_u64_from_alloc_sections_legacy_fallback(*elf, addr, out_value);
}

// 先走 PT_LOAD 映射写，再回退 ALLOC 节写入。
bool zElfAddressRewriter::writeU64MappedSegmentFirst(zElf* elf, Elf64_Addr addr, uint64_t value) {
    if (!elf) {
        return false;
    }
    bool wrote = false;
    Elf64_Off slot_off = 0;
    if (map_vaddr_range_to_file(*elf, addr, sizeof(uint64_t), &slot_off) &&
        (uint64_t)slot_off + sizeof(uint64_t) <= elf->file_image_.size()) {
        std::memcpy(elf->file_image_.data() + slot_off, &value, sizeof(uint64_t));
        wrote = true;
    }
    if (write_u64_to_alloc_sections_legacy_fallback(elf, addr, value)) {
        wrote = true;
    }
    return wrote;
}

// 将动态条目写入 PT_DYNAMIC 段。
bool zElfAddressRewriter::writeDynamicEntriesToPhdr(zElf* elf,
                                                     const std::vector<Elf64_Dyn>& entries,
                                                     Elf64_Off off,
                                                     Elf64_Xword size,
                                                     std::string* error) {
    if (!elf) {
        if (error) {
            *error = "Invalid ELF instance";
        }
        return false;
    }
    const size_t file_size = elf->fileImageSize();
    const size_t bytes = entries.size() * sizeof(Elf64_Dyn);
    if ((uint64_t)off + (uint64_t)size > file_size) {
        if (error) {
            *error = "PT_DYNAMIC range exceeds file size";
        }
        return false;
    }
    if (bytes > size) {
        if (error) {
            *error = "PT_DYNAMIC entries exceed original table size";
        }
        return false;
    }
    if (bytes > 0) {
        std::memcpy(elf->file_image_.data() + off, entries.data(), bytes);
    }
    return true;
}

// 常规地址重写：处理 `.dynamic`、`.rel[a]` 等可显式遍历的数据结构。
bool zElfAddressRewriter::rewriteAfterAddressShift(
        zElf* elf,
        const std::function<Elf64_Addr(Elf64_Addr)>& relocate_old_vaddr,
        std::string* error) {
    if (!elf) {
        if (error) {
            *error = "Invalid null zElf pointer";
        }
        return false;
    }

    bool dynamic_updated = false;
    for (auto& section_ptr : elf->sh_table_model_.elements) {
        auto* dynamic_section = dynamic_cast<zDynamicSection*>(section_ptr.get());
        if (!dynamic_section) {
            continue;
        }
        bool changed = false;
        for (auto& entry : dynamic_section->entries) {
            if (!is_dynamic_pointer_tag(entry.d_tag)) {
                continue;
            }
            const Elf64_Addr relocated = relocate_old_vaddr(entry.d_un.d_ptr);
            if (relocated != entry.d_un.d_ptr) {
                entry.d_un.d_ptr = relocated;
                changed = true;
            }
        }
        if (changed) {
            dynamic_section->syncHeader();
        }
        dynamic_updated = true;
    }

    if (!dynamic_updated) {
        std::vector<Elf64_Dyn> phdr_entries;
        Elf64_Off dynamic_off = 0;
        Elf64_Xword dynamic_size = 0;
        bool has_pt_dynamic = false;
        std::string pt_dynamic_error;
        const bool got_pt_dynamic = read_dynamic_entries_from_phdr(*elf,
                                                                   &phdr_entries,
                                                                   &dynamic_off,
                                                                   &dynamic_size,
                                                                   &has_pt_dynamic,
                                                                   &pt_dynamic_error);
        if (has_pt_dynamic && !got_pt_dynamic) {
            if (error) {
                *error = pt_dynamic_error.empty() ?
                         "Dynamic fallback rewrite failed: PT_DYNAMIC not mappable to file image" :
                         pt_dynamic_error;
            }
            return false;
        }
        if (got_pt_dynamic) {
            bool changed = false;
            for (size_t idx = 0; idx < phdr_entries.size(); ++idx) {
                Elf64_Dyn& entry = phdr_entries[idx];
                if (!is_dynamic_pointer_tag(entry.d_tag)) {
                    if (entry.d_tag == DT_NULL) {
                        break;
                    }
                    continue;
                }
                const Elf64_Addr relocated = relocate_old_vaddr(entry.d_un.d_ptr);
                if (relocated != entry.d_un.d_ptr) {
                    entry.d_un.d_ptr = relocated;
                    changed = true;
                }
                if (entry.d_tag == DT_NULL) {
                    break;
                }
            }
            if (changed) {
                if (!writeDynamicEntriesToPhdr(elf, phdr_entries, dynamic_off, dynamic_size, error)) {
                    return false;
                }
                elf->reconstruction_dirty_ = true;
            }
        }
    }

    for (auto& section_ptr : elf->sh_table_model_.elements) {
        auto* relocation_section = dynamic_cast<zRelocationSection*>(section_ptr.get());
        if (!relocation_section) {
            continue;
        }
        bool changed = false;
        if (relocation_section->type == SHT_REL) {
            for (auto& relocation : relocation_section->rel_relocations) {
                const Elf64_Addr relocated = relocate_old_vaddr(relocation.r_offset);
                if (relocated != relocation.r_offset) {
                    relocation.r_offset = relocated;
                    changed = true;
                }
            }
        } else {
            for (auto& relocation : relocation_section->relocations) {
                const uint32_t rel_type = (uint32_t)ELF64_R_TYPE(relocation.r_info);
                const uint32_t rel_sym = (uint32_t)ELF64_R_SYM(relocation.r_info);
                const Elf64_Addr relocated = relocate_old_vaddr(relocation.r_offset);
                if (relocated != relocation.r_offset) {
                    relocation.r_offset = relocated;
                    changed = true;
                }

                if (should_relocate_rela_addend(rel_type, rel_sym)) {
                    const uint64_t old_addend = static_cast<uint64_t>(relocation.r_addend);
                    const uint64_t relocated_addend = static_cast<uint64_t>(
                            relocate_old_vaddr((Elf64_Addr)old_addend));
                    if (relocated_addend != old_addend) {
                        relocation.r_addend = static_cast<Elf64_Sxword>(relocated_addend);
                        changed = true;
                    }
                }
            }
        }
        if (changed) {
            relocation_section->syncHeader();
        }
    }

    return true;
}

// 打包重定位重写：处理 DT_RELR 与 Android APS2（DT_ANDROID_REL/RELA）。
bool zElfAddressRewriter::rewritePackedRelocationsAfterShift(
        zElf* elf,
        const std::function<Elf64_Addr(Elf64_Addr)>& relocate_old_vaddr,
        std::string* error) {
    if (!elf) {
        if (error) {
            *error = "Invalid null zElf pointer";
        }
        return false;
    }

    auto fail = [error](const std::string& message) -> bool {
        if (error) {
            *error = message;
        }
        return false;
    };

    std::unordered_map<int64_t, uint64_t> dynamic_tags;
    std::string tag_error;
    if (!collect_dynamic_tags(*elf, &dynamic_tags, &tag_error)) {
        return fail("Failed to collect dynamic tags while patching packed relocations: " + tag_error);
    }

    const auto relr_it = dynamic_tags.find(DT_RELR_TAG);
    if (relr_it != dynamic_tags.end() && relr_it->second != 0) {
        const auto relrsz_it = dynamic_tags.find(DT_RELRSZ_TAG);
        const auto relrent_it = dynamic_tags.find(DT_RELRENT_TAG);
        if (relrsz_it == dynamic_tags.end() || relrsz_it->second == 0) {
            return fail("DT_RELR exists but DT_RELRSZ is missing/zero");
        }
        if (relrent_it != dynamic_tags.end() && relrent_it->second != sizeof(Elf64_Addr)) {
            return fail("DT_RELRENT mismatch");
        }

        const uint64_t relr_size = relrsz_it->second;
        Elf64_Off relr_off = 0;
        if (!map_vaddr_range_to_file(*elf, (Elf64_Addr)relr_it->second, relr_size, &relr_off) ||
            (uint64_t)relr_off + relr_size > elf->file_image_.size()) {
            return fail("DT_RELR range is not covered by PT_LOAD/file image");
        }

        const uint8_t* relr_bytes = elf->file_image_.data() + relr_off;
        std::vector<uint64_t> relr_addresses;
        std::string decode_error;
        if (!decode_relr_addresses(relr_bytes,
                                   (size_t)relr_size,
                                   &relr_addresses,
                                   &decode_error)) {
            return fail("Failed to decode DT_RELR entries: " + decode_error);
        }

        std::vector<uint64_t> relocated_addresses;
        relocated_addresses.reserve(relr_addresses.size());
        for (uint64_t old_addr : relr_addresses) {
            const Elf64_Addr new_addr = relocate_old_vaddr((Elf64_Addr)old_addr);
            relocated_addresses.push_back((uint64_t)new_addr);

            uint64_t slot_value = 0;
            if (!readU64MappedSegmentFirst(elf, new_addr, &slot_value)) {
                return fail("DT_RELR slot address is not mappable after relocation");
            }
            const uint64_t relocated_slot_value = (uint64_t)relocate_old_vaddr((Elf64_Addr)slot_value);
            if (!writeU64MappedSegmentFirst(elf, new_addr, relocated_slot_value)) {
                return fail("DT_RELR slot address cannot be updated");
            }
        }

        std::vector<uint8_t> relr_reencoded;
        std::string encode_error;
        if (!encode_relr_addresses(relocated_addresses, &relr_reencoded, &encode_error)) {
            return fail("Failed to encode relocated DT_RELR entries: " + encode_error);
        }
        if (relr_reencoded.size() > relr_size) {
            return fail("Relocated DT_RELR needs larger table");
        }

        std::memset(elf->file_image_.data() + relr_off, 0, (size_t)relr_size);
        if (!relr_reencoded.empty()) {
            std::memcpy(elf->file_image_.data() + relr_off,
                        relr_reencoded.data(),
                        relr_reencoded.size());
        }
        elf->reconstruction_dirty_ = true;
    }

    const auto android_rela_it = dynamic_tags.find(DT_ANDROID_RELA_TAG);
    if (android_rela_it != dynamic_tags.end() && android_rela_it->second != 0) {
        const auto android_relasz_it = dynamic_tags.find(DT_ANDROID_RELASZ_TAG);
        if (android_relasz_it == dynamic_tags.end() || android_relasz_it->second == 0) {
            return fail("DT_ANDROID_RELA exists but DT_ANDROID_RELASZ is missing/zero");
        }

        const uint64_t packed_size = android_relasz_it->second;
        Elf64_Off packed_off = 0;
        if (!map_vaddr_range_to_file(*elf, (Elf64_Addr)android_rela_it->second, packed_size, &packed_off) ||
            (uint64_t)packed_off + packed_size > elf->file_image_.size()) {
            return fail("DT_ANDROID_RELA range is not covered by PT_LOAD/file image");
        }

        const uint8_t* packed_bytes = elf->file_image_.data() + packed_off;
        std::vector<AndroidPackedRelocationEntry> packed_entries;
        std::string packed_error;
        if (!decode_android_aps2_relocations(packed_bytes,
                                             (size_t)packed_size,
                                             &packed_entries,
                                             &packed_error)) {
            return fail("Failed to decode DT_ANDROID_RELA APS2 stream: " + packed_error);
        }

        for (auto& entry : packed_entries) {
            const uint64_t old_offset = entry.offset;
            const uint64_t old_addend_bits = (uint64_t)entry.addend;
            entry.offset = (uint64_t)relocate_old_vaddr((Elf64_Addr)entry.offset);

            const uint32_t rel_type = (uint32_t)ELF64_R_TYPE(entry.info);
            const uint32_t rel_sym = (uint32_t)ELF64_R_SYM(entry.info);
            if (entry.has_addend && should_relocate_rela_addend(rel_type, rel_sym)) {
                entry.addend = (int64_t)(uint64_t)relocate_old_vaddr((Elf64_Addr)old_addend_bits);
            }
            if (entry.offset == 0 && old_offset != 0) {
                return fail("DT_ANDROID_RELA relocation offset moved to zero unexpectedly");
            }
        }

        std::vector<uint8_t> packed_reencoded;
        std::string encode_error;
        if (!encode_android_aps2_relocations(packed_entries,
                                             (size_t)packed_size,
                                             &packed_reencoded,
                                             &encode_error)) {
            return fail("Failed to encode relocated DT_ANDROID_RELA APS2 stream: " + encode_error);
        }

        std::memset(elf->file_image_.data() + packed_off, 0, (size_t)packed_size);
        if (!packed_reencoded.empty()) {
            std::memcpy(elf->file_image_.data() + packed_off,
                        packed_reencoded.data(),
                        packed_reencoded.size());
        }
        elf->reconstruction_dirty_ = true;
    }

    const auto android_rel_it = dynamic_tags.find(DT_ANDROID_REL_TAG);
    if (android_rel_it != dynamic_tags.end() && android_rel_it->second != 0) {
        const auto android_relsz_it = dynamic_tags.find(DT_ANDROID_RELSZ_TAG);
        if (android_relsz_it == dynamic_tags.end() || android_relsz_it->second == 0) {
            return fail("DT_ANDROID_REL exists but DT_ANDROID_RELSZ is missing/zero");
        }

        const uint64_t packed_size = android_relsz_it->second;
        Elf64_Off packed_off = 0;
        if (!map_vaddr_range_to_file(*elf, (Elf64_Addr)android_rel_it->second, packed_size, &packed_off) ||
            (uint64_t)packed_off + packed_size > elf->file_image_.size()) {
            return fail("DT_ANDROID_REL range is not covered by PT_LOAD/file image");
        }

        const uint8_t* packed_bytes = elf->file_image_.data() + packed_off;
        std::vector<AndroidPackedRelocationEntry> packed_entries;
        std::string packed_error;
        if (!decode_android_aps2_relocations(packed_bytes,
                                             (size_t)packed_size,
                                             &packed_entries,
                                             &packed_error)) {
            return fail("Failed to decode DT_ANDROID_REL APS2 stream: " + packed_error);
        }

        for (auto& entry : packed_entries) {
            entry.offset = (uint64_t)relocate_old_vaddr((Elf64_Addr)entry.offset);

            const uint32_t rel_type = (uint32_t)ELF64_R_TYPE(entry.info);
            const uint32_t rel_sym = (uint32_t)ELF64_R_SYM(entry.info);
            if (rel_type == 0) {
                continue;
            }

            if (rel_sym == 0) {
                uint64_t slot_value = 0;
                if (!readU64MappedSegmentFirst(elf, (Elf64_Addr)entry.offset, &slot_value)) {
                    return fail("DT_ANDROID_REL slot address is not mappable");
                }

                const uint64_t relocated_slot_value = (uint64_t)relocate_old_vaddr((Elf64_Addr)slot_value);
                if (!writeU64MappedSegmentFirst(elf, (Elf64_Addr)entry.offset, relocated_slot_value)) {
                    return fail("DT_ANDROID_REL slot cannot be updated");
                }
            }
        }

        std::vector<uint8_t> packed_reencoded;
        std::string encode_error;
        if (!encode_android_aps2_relocations(packed_entries,
                                             (size_t)packed_size,
                                             &packed_reencoded,
                                             &encode_error)) {
            return fail("Failed to encode relocated DT_ANDROID_REL APS2 stream: " + encode_error);
        }

        std::memset(elf->file_image_.data() + packed_off, 0, (size_t)packed_size);
        if (!packed_reencoded.empty()) {
            std::memcpy(elf->file_image_.data() + packed_off,
                        packed_reencoded.data(),
                        packed_reencoded.size());
        }
        elf->reconstruction_dirty_ = true;
    }

    return true;
}
