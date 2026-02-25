#include "zPatchbayLayout.h"

// 校验 ELF 表布局是否满足 Android 端基本装载约束。
bool validateElfTablesForAndroid(const std::vector<uint8_t>& fileBytes, std::string* error) {
    // 至少需要容纳一个 ELF64 文件头。
    if (fileBytes.size() < sizeof(Elf64_Ehdr)) {
        if (error != nullptr) {
            *error = "output image too small for ELF header";
        }
        return false;
    }

    // 将文件起始字节解释为 ELF64 头视图。
    const auto* ehdr = reinterpret_cast<const Elf64_Ehdr*>(fileBytes.data());

    // 校验 Program Header 表范围以及 PT_LOAD 对齐同余关系。
    if (ehdr->e_phnum > 0) {
        // 计算 program header 表总字节数。
        const uint64_t phdrTableSize = static_cast<uint64_t>(ehdr->e_phnum) *
                                       static_cast<uint64_t>(ehdr->e_phentsize);
        // 条目尺寸或总字节数为 0 都属于非法头信息。
        if (ehdr->e_phentsize == 0 || phdrTableSize == 0) {
            if (error != nullptr) {
                *error = "invalid program header entry size/count";
            }
            return false;
        }
        // 校验 program header 表在文件范围内。
        if (ehdr->e_phoff > fileBytes.size() ||
            phdrTableSize > (fileBytes.size() - static_cast<size_t>(ehdr->e_phoff))) {
            if (error != nullptr) {
                *error = "program header table out of range";
            }
            return false;
        }
        // 获取 program header 表首地址。
        const auto* phdrs = reinterpret_cast<const Elf64_Phdr*>(fileBytes.data() + ehdr->e_phoff);
        // 逐项检查 PT_LOAD 段。
        for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
            const Elf64_Phdr& ph = phdrs[i];
            // 非 PT_LOAD 或无需对齐约束的段直接跳过。
            if (ph.p_type != PT_LOAD || ph.p_align <= 1) {
                continue;
            }
            // Android loader 依赖 p_offset 与 p_vaddr 对齐同余。
            if ((ph.p_offset % ph.p_align) != (ph.p_vaddr % ph.p_align)) {
                if (error != nullptr) {
                    *error = "PT_LOAD alignment congruence broken";
                }
                return false;
            }
        }
    }

    // 校验 Section Header 表范围与偏移对齐。
    if (ehdr->e_shnum > 0) {
        // 计算 section header 表总字节数。
        const uint64_t shdrTableSize = static_cast<uint64_t>(ehdr->e_shnum) *
                                       static_cast<uint64_t>(ehdr->e_shentsize);
        // 条目尺寸或总字节数为 0 都属于非法头信息。
        if (ehdr->e_shentsize == 0 || shdrTableSize == 0) {
            if (error != nullptr) {
                *error = "invalid section header entry size/count";
            }
            return false;
        }
        // Android 平台要求 section table 偏移非 0。
        if (ehdr->e_shoff == 0) {
            if (error != nullptr) {
                *error = "section header table offset is zero";
            }
            return false;
        }
        // 约定 section table 8 字节对齐。
        constexpr uint64_t kAndroidShdrAlign = sizeof(Elf64_Addr);
        if ((ehdr->e_shoff % kAndroidShdrAlign) != 0) {
            if (error != nullptr) {
                *error = "section header table offset is not 8-byte aligned";
            }
            return false;
        }
        // 校验 section header 表在文件范围内。
        if (ehdr->e_shoff > fileBytes.size() ||
            shdrTableSize > (fileBytes.size() - static_cast<size_t>(ehdr->e_shoff))) {
            if (error != nullptr) {
                *error = "section header table out of range";
            }
            return false;
        }
    }

    // 所有结构约束通过。
    return true;
}

