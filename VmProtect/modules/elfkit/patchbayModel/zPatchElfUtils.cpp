/**
 * @file elf_utils.cpp
 * @brief ELF 操作公共工具函数实现。
 *
 * 实现需要完整类型定义的共享工具函数，包括：
 * - 段属性匹配；
 * - 动态标签收集；
 * - PT_DYNAMIC 读取回退；
 * - 页大小推断。
 */

#include "zPatchElfUtils.h"
#include "zPatchElf.h"

// memcmp/memcpy/memchr。
#include <cstring>

// 根据 PT_LOAD 的 p_align 推断运行时页大小（默认 4KB）。
uint64_t inferRuntimePageSizeFromPhdrs(
        const std::vector<zProgramTableElement>& phs) {
    // 默认 4KB；若观测到更大合法对齐（如 16KB）再提升。
    uint64_t page_size = 0x1000ULL;
    // 遍历所有 Program Header。
    for (const auto& ph : phs) {
        // 仅 PT_LOAD 的 p_align 对运行时页大小有参考意义。
        if (ph.type != PT_LOAD || ph.align == 0) {
            continue;
        }
        // align 必须是 2 的幂，非幂值视为噪声数据忽略。
        if ((ph.align & (ph.align - 1ULL)) != 0) {
            continue;
        }
        // 只接受常见页大小上限（<=64KB），防止异常值污染推断结果。
        if (ph.align > page_size && ph.align <= 0x10000ULL) {
            page_size = ph.align;
        }
    }
    return page_size;
}

// 判断 LOAD 段的权限标志是否匹配 section 标志。
bool loadSegmentMatchesSectionFlags(
        const zProgramTableElement& ph,
        const zSectionTableElement& section) {
    // section 只能映射到 PT_LOAD 段。
    if (ph.type != PT_LOAD) {
        return false;
    }
    // 可执行节必须落到可执行段。
    if ((section.flags & SHF_EXECINSTR) != 0 && (ph.flags & PF_X) == 0) {
        return false;
    }
    // 可写节必须落到可写段。
    if ((section.flags & SHF_WRITE) != 0 && (ph.flags & PF_W) == 0) {
        return false;
    }
    // 读权限默认可被接受（多数 LOAD 至少具备 PF_R）。
    return true;
}

// 判断动态标签是否表示“地址指针字段”。
// 这类标签对应 d_ptr 语义，通常要求可映射到 PT_LOAD。
bool isDynamicPointerTag(Elf64_Sxword tag) {
    switch (tag) {
        // GOT/Hash/String/Symtab 基础地址。
        case DT_PLTGOT:
        case DT_HASH:
        case DT_STRTAB:
        case DT_SYMTAB:
        // 重定位相关地址。
        case DT_RELA:
        case DT_REL:
        // 初始化/结束函数指针。
        case DT_INIT:
        case DT_FINI:
        // 数组入口地址。
        case DT_INIT_ARRAY_TAG:
        case DT_FINI_ARRAY_TAG:
        case DT_PREINIT_ARRAY_TAG:
        // 运行时调试与 plt 跳转重定位表。
        case DT_DEBUG:
        case DT_JMPREL:
        // 版本与 GNU hash。
        case DT_VERSYM:
        case DT_VERNEED:
        case DT_VERDEF:
        case DT_GNU_HASH:
        // 新式 RELR 与 Android 动态重定位。
        case DT_RELR_TAG:
        case DT_ANDROID_REL_TAG:
        case DT_ANDROID_RELA_TAG:
        // TLS 描述符相关标签（glibc/clang 工具链常见）。
        case 0x6ffffef6: // DT_TLSDESC_PLT
        case 0x6ffffef7: // DT_TLSDESC_GOT
            return true;
        default:
            return false;
    }
}

// 从 PT_DYNAMIC 段读取动态条目（6 参数完整版本）。
bool readDynamicEntriesFromPhdr(
        const PatchElf& elf,
        std::vector<Elf64_Dyn>* out_entries,
        Elf64_Off* out_off,
        Elf64_Xword* out_size,
        bool* out_has_pt_dynamic,
        std::string* error) {
    // 默认声明“未发现 PT_DYNAMIC”。
    if (out_has_pt_dynamic) {
        *out_has_pt_dynamic = false;
    }
    // 输出 entries 先清空，避免返回旧值。
    if (out_entries) {
        out_entries->clear();
    }

    // 读取当前镜像视图。
    const uint8_t* file_data = elf.fileImageData();
    const size_t file_size = elf.fileImageSize();

    // 扫描 Program Header，寻找首个有效 PT_DYNAMIC。
    for (const auto& ph : elf.programHeaderModel().elements) {
        // 仅接受 filesz>0 的 PT_DYNAMIC。
        if (ph.type != PT_DYNAMIC || ph.filesz == 0) {
            continue;
        }
        // 标记“文件里声明了 PT_DYNAMIC”。
        if (out_has_pt_dynamic) {
            *out_has_pt_dynamic = true;
        }

        // 文件镜像为空时无法读取动态段。
        if (!file_data || file_size == 0) {
            if (error) {
                *error = "PT_DYNAMIC exists but file image is empty";
            }
            return false;
        }
        // 检查 PT_DYNAMIC 文件范围是否越界。
        if ((uint64_t)ph.offset + (uint64_t)ph.filesz > file_size) {
            if (error) {
                *error = "PT_DYNAMIC range exceeds file size";
            }
            return false;
        }

        // 按 Elf64_Dyn 大小计算条目数。
        const size_t count = (size_t)(ph.filesz / sizeof(Elf64_Dyn));
        // 动态段不足一个条目时视为异常。
        if (count == 0) {
            if (error) {
                *error = "PT_DYNAMIC size is too small";
            }
            return false;
        }

        // 需要导出 entries 时执行结构体数组复制。
        if (out_entries) {
            // 预分配目标数组。
            out_entries->resize(count);
            // 从 file_image_ 复制原始动态条目。
            std::memcpy(out_entries->data(), file_data + ph.offset,
                        count * sizeof(Elf64_Dyn));
        }
        // 输出 PT_DYNAMIC 偏移（可选）。
        if (out_off) {
            *out_off = ph.offset;
        }
        // 输出 PT_DYNAMIC 大小（可选）。
        if (out_size) {
            *out_size = ph.filesz;
        }
        // 读取成功即返回。
        return true;
    }

    // 没有 PT_DYNAMIC 视作“无可读动态表”，由上层决定是否报错。
    return false;
}

// 收集动态标签到 map（优先 SHT_DYNAMIC，必要时回退 PT_DYNAMIC）。
// 复用 readDynamicEntriesFromPhdr，避免重复实现读取逻辑。
bool collectDynamicTags(
        const PatchElf& elf,
        std::unordered_map<int64_t, uint64_t>* tags,
        std::string* error) {
    // 输出 map 指针不能为空。
    if (!tags) {
        return false;
    }
    // 先清空输出 map。
    tags->clear();

    // 统一的 entries -> map 收集逻辑：
    // 1) 同一 tag 仅保留首值；
    // 2) 遇到 DT_NULL 立即停止。
    auto collectEntries = [tags](const Elf64_Dyn* entries, size_t count) {
        // 空输入直接返回。
        if (!entries || count == 0) {
            return;
        }
        // 顺序遍历动态条目。
        for (size_t idx = 0; idx < count; ++idx) {
            const Elf64_Dyn& entry = entries[idx];
            const int64_t tag = static_cast<int64_t>(entry.d_tag);
            // 首次出现的 tag 才写入 map。
            if (tags->find(tag) == tags->end()) {
                (*tags)[tag] = static_cast<uint64_t>(entry.d_un.d_val);
            }
            // DT_NULL 是动态表终止符，命中后提前结束。
            if (entry.d_tag == DT_NULL) {
                break;
            }
        }
    };

    // 优先路径：使用 SHT_DYNAMIC 的模型解析结果。
    const auto& sections = elf.sectionHeaderModel().elements;
    for (size_t idx = 0; idx < sections.size(); ++idx) {
        const auto* sec = sections[idx].get();
        // 跳过空节与非 SHT_DYNAMIC 节。
        if (!sec || sec->type != SHT_DYNAMIC) {
            continue;
        }

        // 期望 SHT_DYNAMIC 已被解析为 zDynamicSection 派生类。
        const auto* dynamic_sec = dynamic_cast<const zDynamicSection*>(sec);
        if (!dynamic_sec) {
            if (error) {
                *error = "SHT_DYNAMIC section is not parsed as zDynamicSection at index "
                         + std::to_string(idx);
            }
            return false;
        }

        // 有 section.size 但 entries 为空，说明解析异常。
        if (dynamic_sec->entries.empty() && sec->size > 0) {
            if (error) {
                *error = "Dynamic section parse failed at index " + std::to_string(idx);
            }
            return false;
        }

        // 收集动态条目。
        collectEntries(dynamic_sec->entries.data(), dynamic_sec->entries.size());
        // 找到第一个 SHT_DYNAMIC 后即可返回。
        return true;
    }

    // 回退路径：按 PT_DYNAMIC 从原始字节流读取。
    std::vector<Elf64_Dyn> phdr_entries;
    bool has_pt_dynamic = false;
    std::string pt_dynamic_error;
    const bool got_pt_dynamic = readDynamicEntriesFromPhdr(
            elf, &phdr_entries, nullptr, nullptr, &has_pt_dynamic, &pt_dynamic_error);

    // 文件声明了 PT_DYNAMIC 但读取失败，属于结构错误。
    if (has_pt_dynamic && !got_pt_dynamic) {
        if (error) {
            *error = pt_dynamic_error.empty()
                     ? "PT_DYNAMIC exists but dynamic table is not mapped/parsed"
                     : pt_dynamic_error;
        }
        return false;
    }

    // 回退读取成功则按同一规则收集标签。
    if (got_pt_dynamic) {
        collectEntries(phdr_entries.data(), phdr_entries.size());
    }
    return true;
}
