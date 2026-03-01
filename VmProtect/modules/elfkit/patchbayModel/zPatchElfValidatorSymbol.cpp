/*
 * [VMP_FLOW_NOTE] 文件级流程注释。
 * - 文件：patchbayModel/zPatchElfValidatorSymbol.cpp
 * - 主要职责：符号校验：验证符号表、字符串表与版本相关引用关系。
 * - 输入：ELF 原始字节、补丁模型状态以及段/节/符号元数据。
 * - 输出：经过校验的补丁模型或重建后的 ELF 输出数据。
 * - 关键约束：
 *   1) 严格保持 ELF 布局与索引一致性，避免地址/偏移漂移。
 *   2) 失败路径必须可定位（返回值/错误信息/日志三者保持一致）。
 *   3) 本文件改动优先保证与上游调用契约兼容，不隐式改变既有语义。
 */
// 符号解析校验实现：检查符号表、字符串表和符号地址映射关系。
#include "zPatchElfValidator.h"

// PatchElf 聚合模型。
#include "zPatchElf.h"
// 地址区间/特殊索引工具。
#include "zPatchElfUtils.h"

// memchr。
#include <cstring>
// 错误文本拼接。
#include <string>
// 字符串表字节容器。
#include <vector>

namespace {

// 判断给定虚拟地址区间是否被任一 PT_LOAD 覆盖。
bool isLoadMapped(const PatchElf& elf, uint64_t vaddr, uint64_t size) {
    // 遍历所有 Program Header。
    for (const auto& ph : elf.getProgramHeaderModel().elements) {
        // 非 LOAD 段跳过。
        if (ph.type != PT_LOAD) {
            continue;
        }
        // 命中任一覆盖即成功。
        if (containsAddrRangeU64(ph.vaddr, ph.memsz, vaddr, size)) {
            return true;
        }
    }
    // 无覆盖返回 false。
    return false;
}

// 检查字符串表从 off 开始是否存在 '\0' 终止符。
bool hasStringEnd(const std::vector<uint8_t>& strtab, size_t off) {
    // 起始偏移越界时不合法。
    if (off >= strtab.size()) {
        return false;
    }
    // 起始扫描指针。
    const uint8_t* begin = strtab.data() + off;
    // 可扫描长度。
    const size_t len = strtab.size() - off;
    // 在 [off, end) 范围内找 '\0'。
    return std::memchr(begin, '\0', len) != nullptr;
}

} // namespace

// 符号解析校验：符号表、字符串表、节索引与地址可达性。
bool zElfValidator::validateSymbolResolution(const PatchElf& elf, std::string* error) {
    // 读取 section 列表。
    const auto& sections = elf.getSectionHeaderModel().elements;

    // 遍历每一个节。
    for (size_t sec_idx = 0; sec_idx < sections.size(); ++sec_idx) {
        // 当前节指针。
        const auto* section = sections[sec_idx].get();
        // 空节对象跳过。
        if (!section) {
            continue;
        }
        // 仅处理 SYMTAB/DYNSYM。
        if (section->type != SHT_SYMTAB && section->type != SHT_DYNSYM) {
            continue;
        }

        // 符号节应能动态转换为 zSymbolSection。
        const auto* symbol_section = dynamic_cast<const zSymbolSection*>(section);
        if (!symbol_section) {
            if (error) {
                *error = "Symbol section type mismatch at section index " + std::to_string(sec_idx);
            }
            return false;
        }
        // 节有尺寸但未解析出符号项，说明解析失败。
        if (symbol_section->symbols.empty() && section->size > 0) {
            if (error) {
                *error = "Symbol section parse failed at section index " + std::to_string(sec_idx);
            }
            return false;
        }

        // sh_link 指向关联字符串表节索引。
        const uint32_t strtab_idx = section->link;
        // 索引越界直接失败。
        if (strtab_idx >= sections.size()) {
            if (error) {
                *error = "Symbol section sh_link out of range at section index " + std::to_string(sec_idx);
            }
            return false;
        }

        // 取出字符串表节。
        const auto* strtab_section = sections[strtab_idx].get();
        // 关联节必须存在且类型为 STRTAB。
        if (!strtab_section || strtab_section->type != SHT_STRTAB) {
            if (error) {
                *error = "Symbol section sh_link is not a STRTAB at section index " + std::to_string(sec_idx);
            }
            return false;
        }

        // 字符串表字节数据。
        const auto& strtab = strtab_section->payload;
        // 空字符串表不可用于符号名解析。
        if (strtab.empty()) {
            if (error) {
                *error = "Symbol string table is empty for section index " + std::to_string(sec_idx);
            }
            return false;
        }

        // 遍历当前符号节的每个符号项。
        for (size_t sym_idx = 0; sym_idx < symbol_section->symbols.size(); ++sym_idx) {
            // 当前符号引用。
            const Elf64_Sym& sym = symbol_section->symbols[sym_idx];
            // 符号名偏移。
            const uint64_t st_name = sym.st_name;
            // 名字偏移越界。
            if (st_name >= strtab.size()) {
                if (error) {
                    *error = "Symbol name offset out of range at section " + std::to_string(sec_idx) +
                             ", symbol " + std::to_string(sym_idx);
                }
                return false;
            }
            // 名字必须以 '\0' 结尾。
            if (!hasStringEnd(strtab, (size_t)st_name)) {
                if (error) {
                    *error = "Symbol name is not null-terminated at section " + std::to_string(sec_idx) +
                             ", symbol " + std::to_string(sym_idx);
                }
                return false;
            }

            // 符号目标 section 索引。
            const uint16_t shndx = sym.st_shndx;
            // 特殊索引（如 ABS/UNDEF）走豁免逻辑。
            if (isSpecialShndx(shndx)) {
                continue;
            }
            // 普通索引必须在 section 数组范围内。
            if (shndx >= sections.size()) {
                if (error) {
                    *error = "Symbol section index out of range at section " + std::to_string(sec_idx) +
                             ", symbol " + std::to_string(sym_idx);
                }
                return false;
            }

            // 取符号目标节。
            const auto* target_section = sections[shndx].get();
            // 目标节缺失说明模型不完整。
            if (!target_section) {
                if (error) {
                    *error = "Symbol target section missing at section " + std::to_string(sec_idx) +
                             ", symbol " + std::to_string(sym_idx);
                }
                return false;
            }

            // 仅对 ALLOC 且 size>0 的目标节做地址可达性校验。
            if ((target_section->flags & SHF_ALLOC) != 0 && target_section->size > 0) {
                // 符号区间必须落在目标节 VA 区间内。
                if (!containsAddrRangeU64(target_section->addr,
                                             target_section->size,
                                             sym.st_value,
                                             sym.st_size)) {
                    if (error) {
                        *error = "Symbol value out of target section range at section " +
                                 std::to_string(sec_idx) + ", symbol " + std::to_string(sym_idx);
                    }
                    return false;
                }
                // 符号区间还必须被任意 LOAD 段实际映射。
                if (!isLoadMapped(elf, sym.st_value, sym.st_size)) {
                    if (error) {
                        *error = "Symbol value is not mapped by any PT_LOAD at section " +
                                 std::to_string(sec_idx) + ", symbol " + std::to_string(sym_idx);
                    }
                    return false;
                }
            }
        }
    }

    // 全部符号约束检查通过。
    return true;
}

