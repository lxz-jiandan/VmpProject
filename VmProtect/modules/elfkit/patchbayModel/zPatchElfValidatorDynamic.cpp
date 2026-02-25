// 动态表相关校验实现：检查 DT_* 标签配套关系、地址映射以及重解析一致性。
#include "zPatchElfValidator.h"
// 对外声明：zElfValidator 接口。

// PatchElf 模型入口。
#include "zPatchElf.h"
// 区间/标签工具函数。
#include "zPatchElfUtils.h"

// snprintf。
#include <cstdio>
// 错误信息拼接。
#include <string>
// 动态标签临时索引表。
#include <unordered_map>

namespace {

// 把动态标签值转成可读名称。
const char* dynamicTagName(Elf64_Sxword tag) {
    switch (tag) {
        // 基础动态链接标签。
        case DT_NULL:
            return "DT_NULL";
        case DT_NEEDED:
            return "DT_NEEDED";
        case DT_PLTRELSZ:
            return "DT_PLTRELSZ";
        case DT_PLTGOT:
            return "DT_PLTGOT";
        case DT_HASH:
            return "DT_HASH";
        case DT_STRTAB:
            return "DT_STRTAB";
        case DT_SYMTAB:
            return "DT_SYMTAB";
        case DT_RELA:
            return "DT_RELA";
        case DT_RELASZ:
            return "DT_RELASZ";
        case DT_RELAENT:
            return "DT_RELAENT";
        case DT_STRSZ:
            return "DT_STRSZ";
        case DT_SYMENT:
            return "DT_SYMENT";
        case DT_INIT:
            return "DT_INIT";
        case DT_FINI:
            return "DT_FINI";
        case DT_SONAME:
            return "DT_SONAME";
        case DT_REL:
            return "DT_REL";
        case DT_RELSZ:
            return "DT_RELSZ";
        case DT_RELENT:
            return "DT_RELENT";
        case DT_PLTREL:
            return "DT_PLTREL";
        case DT_DEBUG:
            return "DT_DEBUG";
        case DT_JMPREL:
            return "DT_JMPREL";
        case DT_INIT_ARRAY_TAG:
            return "DT_INIT_ARRAY";
        case DT_FINI_ARRAY_TAG:
            return "DT_FINI_ARRAY";
        case DT_PREINIT_ARRAY_TAG:
            return "DT_PREINIT_ARRAY";
        case DT_RELRSZ_TAG:
            return "DT_RELRSZ";
        case DT_VERSYM:
            return "DT_VERSYM";
        case DT_VERNEED:
            return "DT_VERNEED";
        case DT_VERDEF:
            return "DT_VERDEF";
        case DT_GNU_HASH:
            return "DT_GNU_HASH";
        case DT_RELR_TAG:
            return "DT_RELR";
        case DT_RELRENT_TAG:
            return "DT_RELRENT";
        case DT_ANDROID_REL_TAG:
            return "DT_ANDROID_REL";
        case DT_ANDROID_RELSZ_TAG:
            return "DT_ANDROID_RELSZ";
        case DT_ANDROID_RELA_TAG:
            return "DT_ANDROID_RELA";
        case DT_ANDROID_RELASZ_TAG:
            return "DT_ANDROID_RELASZ";
        default:
            // 未纳入白名单的标签统一记为未知。
            return "DT_UNKNOWN";
    }
}

// 输出形如 DT_RELA(7) 的标签文本。
std::string dynamicTagLabel(Elf64_Sxword tag) {
    // long long 强转用于保证 to_string 在不同平台上行为稳定。
    return std::string(dynamicTagName(tag)) + "(" + std::to_string((long long)tag) + ")";
}

// 以十六进制格式化 64 位值。
std::string hexU64Label(uint64_t value) {
    // 固定缓冲 + snprintf，避免 iostream 开销。
    char buffer[32] = {0};
    std::snprintf(buffer, sizeof(buffer), "0x%llx", (unsigned long long)value);
    return std::string(buffer);
}

// 判断某个虚拟地址区间是否被任一 PT_LOAD 映射。
bool isLoadMapped(const PatchElf& elf, uint64_t vaddr, uint64_t size) {
    // 遍历全部 Program Header。
    for (const auto& ph : elf.getProgramHeaderModel().elements) {
        // 仅关注 LOAD 段。
        if (ph.type != PT_LOAD) {
            // 非 LOAD 段不参与运行时地址可达性判断。
            continue;
        }
        // 只要有一个 LOAD 覆盖该区间即返回 true。
        if (containsAddrRangeU64(ph.vaddr, ph.memsz, vaddr, size)) {
            return true;
        }
    }
    // 没有任何 LOAD 覆盖。
    return false;
}

} // namespace

// PLT/GOT/重定位校验：动态标签配套关系与数据结构合法性。
bool zElfValidator::validatePltGotRelocations(const PatchElf& elf, std::string* error) {
    // 收集动态标签到 map(tag -> value)。
    std::unordered_map<int64_t, uint64_t> dynamic_tags;
    if (!collectDynamicTags(elf, &dynamic_tags, error)) {
        return false;
    }

    // 非空时执行详细规则校验。
    if (!dynamic_tags.empty()) {
        // 先校验所有“指针类动态标签”是否落在 LOAD 映射内。
        for (const auto& item : dynamic_tags) {
            // 标签值。
            const Elf64_Sxword tag = (Elf64_Sxword)item.first;
            // 标签对应地址/数值。
            const Elf64_Addr value = (Elf64_Addr)item.second;
            // 值为 0 或非指针标签时跳过。
            if (value == 0 || !isDynamicPointerTag(tag)) {
                // 非指针类标签或空地址值不做地址映射校验。
                continue;
            }
            // 指针标签必须能被某个 LOAD 映射。
            if (!isLoadMapped(elf, value, 1)) {
                if (error) {
                    *error = "Dynamic pointer tag is not mapped by PT_LOAD: " +
                             dynamicTagLabel(tag) +
                             ", value=" + hexU64Label((uint64_t)value);
                }
                return false;
            }
        }

        // DT_PLTREL 如存在，必须等于 DT_RELA。
        const auto pltRelIt = dynamic_tags.find(DT_PLTREL);
        if (pltRelIt != dynamic_tags.end() && pltRelIt->second != DT_RELA) {
            if (error) {
                *error = "DT_PLTREL is not DT_RELA";
            }
            return false;
        }

        // DT_RELAENT 如存在，必须等于 Elf64_Rela 大小。
        const auto relaEntIt = dynamic_tags.find(DT_RELAENT);
        if (relaEntIt != dynamic_tags.end() && relaEntIt->second != sizeof(Elf64_Rela)) {
            if (error) {
                *error = "DT_RELAENT mismatch";
            }
            return false;
        }

        // DT_PLTRELSZ 必须按 Elf64_Rela 对齐。
        const auto pltRelSzIt = dynamic_tags.find(DT_PLTRELSZ);
        if (pltRelSzIt != dynamic_tags.end() && (pltRelSzIt->second % sizeof(Elf64_Rela)) != 0) {
            if (error) {
                *error = "DT_PLTRELSZ is not aligned to Elf64_Rela size";
            }
            return false;
        }

        // DT_RELASZ 必须按 Elf64_Rela 对齐。
        const auto relaSzIt = dynamic_tags.find(DT_RELASZ);
        if (relaSzIt != dynamic_tags.end() && (relaSzIt->second % sizeof(Elf64_Rela)) != 0) {
            if (error) {
                *error = "DT_RELASZ is not aligned to Elf64_Rela size";
            }
            return false;
        }

        // DT_PLTGOT 如存在，必须落在 LOAD 映射内。
        const auto pltGotIt = dynamic_tags.find(DT_PLTGOT);
        if (pltGotIt != dynamic_tags.end()) {
            // 至少检查 8 字节，确保 GOT 入口地址可访问。
            if (!isLoadMapped(elf, (Elf64_Addr)pltGotIt->second, sizeof(uint64_t))) {
                if (error) {
                    *error = "DT_PLTGOT is not mapped by PT_LOAD";
                }
                return false;
            }
        }
    }
    // 全部规则通过。
    return true;
}

// 重解析一致性：用当前字节流重新解析并与模型规模做一致性比对。
bool zElfValidator::validateReparseConsistency(const PatchElf& elf, std::string* error) {
    // 文件字节首地址。
    const uint8_t* file_data = elf.getFileImageData();
    // 文件字节总长度。
    const size_t file_size = elf.getFileImageSize();
    // 字节缺失或太小都无法作为 ELF64 解析。
    if (!file_data || file_size < sizeof(Elf64_Ehdr)) {
        if (error) {
            *error = "No loaded ELF bytes for reparse";
        }
        return false;
    }

    // 重新解析 ELF 头。
    zElfHeader reparsed_header;
    if (!reparsed_header.fromRaw(file_data, file_size) ||
        !reparsed_header.isElf64AArch64()) {
        if (error) {
            *error = "Reparse header failed or target is not ELF64/AArch64";
        }
        return false;
    }

    // 取重解析后的原始头。
    const Elf64_Ehdr& eh = reparsed_header.raw;
    // 计算 phdr 区间末端。
    const uint64_t ph_end = (uint64_t)eh.e_phoff + (uint64_t)eh.e_phentsize * eh.e_phnum;
    // 计算 shdr 区间末端。
    const uint64_t sh_end = (uint64_t)eh.e_shoff + (uint64_t)eh.e_shentsize * eh.e_shnum;
    // 表区间越界则失败。
    if (ph_end > file_size || (eh.e_shnum > 0 && sh_end > file_size)) {
        if (error) {
            *error = "Reparse table offsets out of file range";
        }
        return false;
    }

    // 重解析 Program Header 表。
    zElfProgramHeaderTable reparsed_ph;
    // fromRaw 仅重建表结构，不改变原文件数据。
    reparsed_ph.fromRaw(reinterpret_cast<const Elf64_Phdr*>(file_data + eh.e_phoff), eh.e_phnum);
    // 校验每个 phdr 的 memsz/filesz 关系。
    for (size_t programHeaderIndex = 0;
         programHeaderIndex < reparsed_ph.elements.size();
         ++programHeaderIndex) {
        if (!reparsed_ph.elements[programHeaderIndex].isMemFileRelationValid()) {
            if (error) {
                *error = "Reparse memsz/filesz mismatch at phdr index " +
                         std::to_string(programHeaderIndex);
            }
            return false;
        }
    }

    // 重解析 Section Header 表。
    zElfSectionHeaderTable reparsed_sh;
    if (eh.e_shnum > 0) {
        // 存在 section table 时，执行完整重解析。
        if (!reparsed_sh.fromRaw(file_data,
                                 file_size,
                                 reinterpret_cast<const Elf64_Shdr*>(file_data + eh.e_shoff),
                                 eh.e_shnum,
                                 eh.e_shstrndx)) {
            if (error) {
                *error = "Reparse section table failed";
            }
            return false;
        }
    }

    // 对比 Program Header 数量是否一致。
    if (reparsed_ph.elements.size() != elf.getProgramHeaderModel().elements.size()) {
        if (error) {
            *error = "Reparse phdr count mismatch";
        }
        return false;
    }
    // 对比 Section Header 数量是否一致。
    if (reparsed_sh.elements.size() != elf.getSectionHeaderModel().elements.size()) {
        if (error) {
            *error = "Reparse shdr count mismatch";
        }
        return false;
    }
    // 解析规模一致。
    return true;
}

