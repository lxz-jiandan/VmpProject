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
        for (uint16_t programHeaderIndex = 0; programHeaderIndex < ehdr->e_phnum; ++programHeaderIndex) {
            const Elf64_Phdr& ph = phdrs[programHeaderIndex];
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

        // 获取 section header 表首地址。
        const auto* shdrs = reinterpret_cast<const Elf64_Shdr*>(fileBytes.data() + ehdr->e_shoff);

        // 逐项校验“文件占位型 section”的文件范围与两两重叠。
        // - type=SHT_NOBITS 不占用文件字节，跳过重叠判断；
        // - size=0 视作空区间，跳过。
        for (uint16_t leftSectionIndex = 0; leftSectionIndex < ehdr->e_shnum; ++leftSectionIndex) {
            const Elf64_Shdr& left = shdrs[leftSectionIndex];
            if (left.sh_type == SHT_NOBITS || left.sh_size == 0) {
                continue;
            }

            if (left.sh_offset > fileBytes.size() ||
                left.sh_size > (fileBytes.size() - static_cast<size_t>(left.sh_offset))) {
                if (error != nullptr) {
                    *error = "section data out of range at index " + std::to_string(leftSectionIndex);
                }
                return false;
            }

            const uint64_t leftBegin = static_cast<uint64_t>(left.sh_offset);
            const uint64_t leftEnd = leftBegin + static_cast<uint64_t>(left.sh_size);

            for (uint16_t rightSectionIndex = static_cast<uint16_t>(leftSectionIndex + 1);
                 rightSectionIndex < ehdr->e_shnum;
                 ++rightSectionIndex) {
                const Elf64_Shdr& right = shdrs[rightSectionIndex];
                if (right.sh_type == SHT_NOBITS || right.sh_size == 0) {
                    continue;
                }
                if (right.sh_offset > fileBytes.size() ||
                    right.sh_size > (fileBytes.size() - static_cast<size_t>(right.sh_offset))) {
                    if (error != nullptr) {
                        *error = "section data out of range at index " + std::to_string(rightSectionIndex);
                    }
                    return false;
                }

                const uint64_t rightBegin = static_cast<uint64_t>(right.sh_offset);
                const uint64_t rightEnd = rightBegin + static_cast<uint64_t>(right.sh_size);
                const bool overlap = (leftBegin < rightEnd) && (rightBegin < leftEnd);
                if (overlap) {
                    if (error != nullptr) {
                        *error = "overlapping file-backed sections: " +
                                 std::to_string(leftSectionIndex) + " and " +
                                 std::to_string(rightSectionIndex);
                    }
                    return false;
                }
            }
        }
    }

    // 所有结构约束通过。
    return true;
}
