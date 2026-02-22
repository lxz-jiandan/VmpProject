/**
 * @file zElfUtils.cpp
 * @brief ELF 操作公共工具函数实现。
 *
 * 实现需要完整类型定义的共享工具函数，包括段属性推断、
 * 动态标签收集、LOAD 映射等。
 */

#include "zElfUtils.h"
#include "zElf.h"

#include <cstring>

// 根据 PT_LOAD 的 p_align 推断运行时页大小（默认 4KB）。
uint64_t infer_runtime_page_size_from_phdrs(
        const std::vector<zProgramTableElement>& phs) {
    uint64_t page_size = 0x1000ULL;
    for (const auto& ph : phs) {
        if (ph.type != PT_LOAD || ph.align == 0) {
            continue;
        }
        if ((ph.align & (ph.align - 1ULL)) != 0) {
            continue;
        }
        if (ph.align > page_size && ph.align <= 0x10000ULL) {
            page_size = ph.align;
        }
    }
    return page_size;
}

// 判断 LOAD 段的权限标志是否匹配 section 标志。
bool load_segment_matches_section_flags(
        const zProgramTableElement& ph,
        const zSectionTableElement& section) {
    if (ph.type != PT_LOAD) {
        return false;
    }
    if ((section.flags & SHF_EXECINSTR) != 0 && (ph.flags & PF_X) == 0) {
        return false;
    }
    if ((section.flags & SHF_WRITE) != 0 && (ph.flags & PF_W) == 0) {
        return false;
    }
    return true;
}

// 判断动态标签是否表示"地址指针字段"。
// 使用最完整的版本（包含 DT_TLSDESC_PLT/GOT）。
bool is_dynamic_pointer_tag(Elf64_Sxword tag) {
    switch (tag) {
        case DT_PLTGOT:
        case DT_HASH:
        case DT_STRTAB:
        case DT_SYMTAB:
        case DT_RELA:
        case DT_REL:
        case DT_INIT:
        case DT_FINI:
        case DT_INIT_ARRAY_TAG:
        case DT_FINI_ARRAY_TAG:
        case DT_PREINIT_ARRAY_TAG:
        case DT_DEBUG:
        case DT_JMPREL:
        case DT_VERSYM:
        case DT_VERNEED:
        case DT_VERDEF:
        case DT_GNU_HASH:
        case DT_RELR_TAG:
        case DT_ANDROID_REL_TAG:
        case DT_ANDROID_RELA_TAG:
        case 0x6ffffef6: // DT_TLSDESC_PLT
        case 0x6ffffef7: // DT_TLSDESC_GOT
            return true;
        default:
            return false;
    }
}

// 从 PT_DYNAMIC 段读取动态条目（6 参数完整版本）。
bool read_dynamic_entries_from_phdr(
        const zElf& elf,
        std::vector<Elf64_Dyn>* out_entries,
        Elf64_Off* out_off,
        Elf64_Xword* out_size,
        bool* out_has_pt_dynamic,
        std::string* error) {
    if (out_has_pt_dynamic) {
        *out_has_pt_dynamic = false;
    }
    if (out_entries) {
        out_entries->clear();
    }
    const uint8_t* file_data = elf.fileImageData();
    const size_t file_size = elf.fileImageSize();
    for (const auto& ph : elf.programHeaderModel().elements) {
        if (ph.type != PT_DYNAMIC || ph.filesz == 0) {
            continue;
        }
        if (out_has_pt_dynamic) {
            *out_has_pt_dynamic = true;
        }
        if (!file_data || file_size == 0) {
            if (error) {
                *error = "PT_DYNAMIC exists but file image is empty";
            }
            return false;
        }
        if ((uint64_t)ph.offset + (uint64_t)ph.filesz > file_size) {
            if (error) {
                *error = "PT_DYNAMIC range exceeds file size";
            }
            return false;
        }
        const size_t count = (size_t)(ph.filesz / sizeof(Elf64_Dyn));
        if (count == 0) {
            if (error) {
                *error = "PT_DYNAMIC size is too small";
            }
            return false;
        }
        if (out_entries) {
            out_entries->resize(count);
            std::memcpy(out_entries->data(), file_data + ph.offset,
                        count * sizeof(Elf64_Dyn));
        }
        if (out_off) {
            *out_off = ph.offset;
        }
        if (out_size) {
            *out_size = ph.filesz;
        }
        return true;
    }
    return false;
}

// 收集动态标签到 map（优先 SHT_DYNAMIC，必要时回退 PT_DYNAMIC）。
// 调用 read_dynamic_entries_from_phdr 而非内嵌 lambda。
bool collect_dynamic_tags(
        const zElf& elf,
        std::unordered_map<int64_t, uint64_t>* tags,
        std::string* error) {
    if (!tags) {
        return false;
    }
    tags->clear();

    auto collect_from_entries = [tags](const Elf64_Dyn* entries, size_t count) {
        if (!entries || count == 0) {
            return;
        }
        for (size_t idx = 0; idx < count; ++idx) {
            const Elf64_Dyn& entry = entries[idx];
            const int64_t tag = static_cast<int64_t>(entry.d_tag);
            if (tags->find(tag) == tags->end()) {
                (*tags)[tag] = static_cast<uint64_t>(entry.d_un.d_val);
            }
            if (entry.d_tag == DT_NULL) {
                break;
            }
        }
    };

    // 优先使用 SHT_DYNAMIC section 视图。
    const auto& sections = elf.sectionHeaderModel().elements;
    for (size_t idx = 0; idx < sections.size(); ++idx) {
        const auto* sec = sections[idx].get();
        if (!sec || sec->type != SHT_DYNAMIC) {
            continue;
        }

        const auto* dynamic_sec = dynamic_cast<const zDynamicSection*>(sec);
        if (!dynamic_sec) {
            if (error) {
                *error = "SHT_DYNAMIC section is not parsed as zDynamicSection at index "
                         + std::to_string(idx);
            }
            return false;
        }

        if (dynamic_sec->entries.empty() && sec->size > 0) {
            if (error) {
                *error = "Dynamic section parse failed at index " + std::to_string(idx);
            }
            return false;
        }

        collect_from_entries(dynamic_sec->entries.data(), dynamic_sec->entries.size());
        return true;
    }

    // 回退：通过 PT_DYNAMIC phdr 视图读取。
    std::vector<Elf64_Dyn> phdr_entries;
    bool has_pt_dynamic = false;
    std::string pt_dynamic_error;
    const bool got_pt_dynamic = read_dynamic_entries_from_phdr(
            elf, &phdr_entries, nullptr, nullptr, &has_pt_dynamic, &pt_dynamic_error);
    if (has_pt_dynamic && !got_pt_dynamic) {
        if (error) {
            *error = pt_dynamic_error.empty()
                     ? "PT_DYNAMIC exists but dynamic table is not mapped/parsed"
                     : pt_dynamic_error;
        }
        return false;
    }
    if (got_pt_dynamic) {
        collect_from_entries(phdr_entries.data(), phdr_entries.size());
    }
    return true;
}
