/**
 * @file zElfValidator.cpp
 * @brief ELF 结构一致性校验实现。
 *
 * 核心目标：在保存/注入/重构后，尽早发现 ELF 结构性错误，
 * 防止运行时才暴露问题（链接器拒载、段映射冲突、重定位异常等）。
 *
 * 主要校验维度：
 * - 基础头信息（ELF64/AArch64、表项大小、边界范围）
 * - Program Header 布局（对齐、覆盖、关键段约束）
 * - Section 与 Segment 的映射关系
 * - 符号表与字符串表一致性
 * - PLT/GOT 与动态重定位标签的匹配关系
 * - 重解析一致性（模型视图 vs 原始字节）
 */

#include "zElf.h"
#include "zElfUtils.h"
#include "zLog.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <limits>
#include <unordered_map>
#include <unordered_set>

// 向下按对齐粒度取整。
static uint64_t align_down_u64(uint64_t value, uint64_t align) {
    if (align == 0) {
        return value;
    }
    return value & ~(align - 1ULL);
}

// 将动态标签转为可读名称，便于日志与错误信息输出。
static const char* dynamic_tag_name(Elf64_Sxword tag) {
    switch (tag) {
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
            return "DT_UNKNOWN";
    }
}

static std::string dynamic_tag_label(Elf64_Sxword tag) {
    // 统一输出格式：TAG_NAME(TAG_VALUE)，便于日志搜索和脚本匹配。
    return std::string(dynamic_tag_name(tag)) + "(" + std::to_string((long long)tag) + ")";
}

static std::string hex_u64_label(uint64_t value) {
    // 统一十六进制展示，避免不同日志点格式不一致。
    char buffer[32] = {0};
    std::snprintf(buffer, sizeof(buffer), "0x%llx", (unsigned long long)value);
    return std::string(buffer);
}

static bool is_acceptable_load_overlap(const zProgramTableElement& a,
                                       const zProgramTableElement& b,
                                       uint64_t page_size) {
    // 仅对 PT_LOAD 检查重叠；其他段不在此规则约束范围。
    if (a.type != PT_LOAD || b.type != PT_LOAD) {
        return true;
    }

    // 计算文件映射重叠区间。
    const uint64_t overlap_file_begin = std::max<uint64_t>(a.offset, b.offset);
    const uint64_t overlap_file_end = std::min<uint64_t>(a.offset + a.filesz, b.offset + b.filesz);
    const uint64_t overlap_file_size = overlap_file_end > overlap_file_begin ? overlap_file_end - overlap_file_begin : 0;

    // 计算虚拟地址重叠区间。
    const uint64_t overlap_va_begin = std::max<uint64_t>(a.vaddr, b.vaddr);
    const uint64_t overlap_va_end = std::min<uint64_t>(a.vaddr + a.memsz, b.vaddr + b.memsz);
    const uint64_t overlap_va_size = overlap_va_end > overlap_va_begin ? overlap_va_end - overlap_va_begin : 0;

    // 两个维度都不重叠则直接可接受。
    if (overlap_file_size == 0 && overlap_va_size == 0) {
        return true;
    }

    // 要允许重叠，必须保持相同的 vaddr-offset 映射差值。
    const int64_t delta_a = (int64_t)a.vaddr - (int64_t)a.offset;
    const int64_t delta_b = (int64_t)b.vaddr - (int64_t)b.offset;
    if (delta_a != delta_b) {
        return false;
    }

    // 重叠规模限定在单页内，避免出现大范围别名映射。
    const uint64_t checked_page = page_size == 0 ? 0x1000ULL : page_size;
    if (overlap_file_size > checked_page || overlap_va_size > checked_page) {
        return false;
    }

    // 文件重叠必须落在同一页。
    if (overlap_file_size > 0) {
        const uint64_t first_page = align_down_u64(overlap_file_begin, checked_page);
        const uint64_t last_page = align_down_u64(overlap_file_end - 1, checked_page);
        if (first_page != last_page) {
            return false;
        }
    }

    // 虚拟地址重叠也必须落在同一页。
    if (overlap_va_size > 0) {
        const uint64_t first_page = align_down_u64(overlap_va_begin, checked_page);
        const uint64_t last_page = align_down_u64(overlap_va_end - 1, checked_page);
        if (first_page != last_page) {
            return false;
        }
    }

    return true;
}

// 给错误信息附加阶段前缀，便于快速定位失败阶段。
static void prefix_validation_error(std::string* error, const char* stage) {
    if (!error || !stage) {
        return;
    }
    if (error->empty()) {
        *error = std::string(stage) + " validation failed";
        return;
    }
    *error = std::string(stage) + ": " + *error;
}

static bool is_load_vaddr_mapped(const zElf& elf, uint64_t vaddr, uint64_t size) {
    // 只要任意 PT_LOAD 覆盖该区间，就认为地址可映射。
    for (const auto& ph : elf.programHeaderModel().elements) {
        if (ph.type != PT_LOAD) {
            continue;
        }
        if (contains_addr_range_u64(ph.vaddr, ph.memsz, vaddr, size)) {
            return true;
        }
    }
    return false;
}

static bool has_string_terminator(const std::vector<uint8_t>& strtab, size_t off) {
    // 字符串偏移必须先落在表内。
    if (off >= strtab.size()) {
        return false;
    }
    const uint8_t* begin = strtab.data() + off;
    const size_t len = strtab.size() - off;
    return std::memchr(begin, '\0', len) != nullptr;
}

static bool patch_aarch64_pc_relative_payload(
        std::vector<uint8_t>* payload,
        uint64_t pc_base,
        const std::function<uint64_t(uint64_t)>& old_pc_from_new_pc,
        const std::function<uint64_t(uint64_t)>& relocate_old_addr,
        size_t* patched_adrp_count,
        size_t* patched_adr_count,
        const char* context_name) {
    if (!payload) {
        return false;
    }

    auto is_adrp = [](uint32_t insn) -> bool {
        // ADRP: 以页为单位构造基址。
        return (insn & 0x9f000000U) == 0x90000000U;
    };

    auto is_adr = [](uint32_t insn) -> bool {
        // ADR: 直接生成 PC 相对地址（字节级）。
        return (insn & 0x9f000000U) == 0x10000000U;
    };

    auto decode_imm21 = [](uint32_t insn) -> int64_t {
        // 通用 imm21 解码，包含符号扩展。
        const uint32_t immlo = (insn >> 29) & 0x3U;
        const uint32_t immhi = (insn >> 5) & 0x7ffffU;
        int64_t imm21 = (int64_t)((immhi << 2) | immlo);
        if ((imm21 & (1LL << 20)) != 0) {
            imm21 |= ~((1LL << 21) - 1);
        }
        return imm21;
    };

    auto decode_adrp_target_page = [&decode_imm21](uint32_t insn, uint64_t pc) -> uint64_t {
        // ADRP 目标页 = pc_page + imm21<<12。
        return (uint64_t)((int64_t)(pc & ~0xfffULL) + (decode_imm21(insn) << 12));
    };

    auto decode_adr_target = [&decode_imm21](uint32_t insn, uint64_t pc) -> uint64_t {
        // ADR 目标地址 = pc + imm21。
        return (uint64_t)((int64_t)pc + decode_imm21(insn));
    };

    auto encode_imm21_same_rd = [](uint32_t op_base, uint32_t old_insn, int64_t imm21, uint32_t* out) -> bool {
        // 复用原 rd，仅替换立即数字段。
        if (!out || imm21 < -(1LL << 20) || imm21 > ((1LL << 20) - 1)) {
            return false;
        }
        const uint32_t rd = old_insn & 0x1fU;
        const uint32_t imm = (uint32_t)(imm21 & 0x1fffffU);
        const uint32_t immlo = imm & 0x3U;
        const uint32_t immhi = imm >> 2;
        *out = op_base | rd | (immlo << 29) | (immhi << 5);
        return true;
    };

    auto encode_adrp_same_rd = [&encode_imm21_same_rd](uint32_t old_insn, uint64_t pc, uint64_t new_page, uint32_t* out) -> bool {
        // ADRP 目标必须页对齐且可由 imm21<<12 表示。
        if ((new_page & 0xfffULL) != 0) {
            return false;
        }
        const int64_t pc_page = (int64_t)(pc & ~0xfffULL);
        const int64_t delta = (int64_t)new_page - pc_page;
        if ((delta & 0xfffLL) != 0) {
            return false;
        }
        return encode_imm21_same_rd(0x90000000U, old_insn, delta >> 12, out);
    };

    auto encode_adr_same_rd = [&encode_imm21_same_rd](uint32_t old_insn, uint64_t pc, uint64_t new_target, uint32_t* out) -> bool {
        // ADR 直接按 byte delta 编码 imm21。
        const int64_t delta = (int64_t)new_target - (int64_t)pc;
        return encode_imm21_same_rd(0x10000000U, old_insn, delta, out);
    };

    auto is_ldr_x_uimm = [](uint32_t insn) -> bool {
        return (insn & 0xffc00000U) == 0xf9400000U;
    };

    auto is_ldr_w_uimm = [](uint32_t insn) -> bool {
        return (insn & 0xffc00000U) == 0xb9400000U;
    };

    auto is_str_x_uimm = [](uint32_t insn) -> bool {
        return (insn & 0xffc00000U) == 0xf9000000U;
    };

    auto is_str_w_uimm = [](uint32_t insn) -> bool {
        return (insn & 0xffc00000U) == 0xb9000000U;
    };

    auto decode_ls_uimm = [](uint32_t insn) -> uint64_t {
        // load/store uimm 根据 size 字段决定缩放粒度。
        const uint32_t size = (insn >> 30) & 0x3U;
        return (uint64_t)(((insn >> 10) & 0xfffU) << size);
    };

    auto encode_ls_uimm_same = [](uint32_t old_insn, uint64_t imm, uint32_t* out) -> bool {
        // 保持原指令宽度/寄存器，只重写位移立即数。
        const uint32_t size = (old_insn >> 30) & 0x3U;
        const uint64_t align = 1ULL << size;
        if (!out || size > 3 || (imm & (align - 1)) != 0) {
            return false;
        }
        const uint64_t imm12 = imm >> size;
        if (imm12 > 0xfffULL) {
            return false;
        }
        *out = (old_insn & ~(0xfffU << 10)) | (uint32_t)(imm12 << 10);
        return true;
    };

    auto is_add_x_imm = [](uint32_t insn) -> bool {
        return (insn & 0xff000000U) == 0x91000000U;
    };

    auto decode_add_imm = [](uint32_t insn) -> uint64_t {
        // ADD immediate 支持可选 LSL#12。
        const uint64_t imm12 = (insn >> 10) & 0xfffU;
        const uint64_t shift = ((insn >> 22) & 0x1U) ? 12ULL : 0ULL;
        return imm12 << shift;
    };

    auto encode_add_imm_same = [](uint32_t old_insn, uint64_t imm, uint32_t* out) -> bool {
        // 优先无移位编码；仅在低 12 位全 0 时启用 LSL#12。
        if (!out) {
            return false;
        }
        uint32_t base = old_insn & ~((0xfffU << 10) | (1U << 22));
        if (imm <= 0xfffULL) {
            *out = base | (uint32_t)(imm << 10);
            return true;
        }
        if ((imm & 0xfffULL) == 0) {
            const uint64_t imm12 = imm >> 12;
            if (imm12 <= 0xfffULL) {
                *out = base | (1U << 22) | (uint32_t)(imm12 << 10);
                return true;
            }
        }
        return false;
    };

    const size_t insn_count = payload->size() / 4;
    size_t local_adrp_count = 0;
    size_t local_adr_count = 0;
    for (size_t insn_idx = 0; insn_idx < insn_count; ++insn_idx) {
        uint32_t insn = 0;
        if (!read_u32_le_bytes(*payload, insn_idx * 4, &insn)) {
            continue;
        }

        const uint64_t pc_new = pc_base + (uint64_t)insn_idx * 4ULL;
        // old_pc_from_new_pc 用于“重排后字节流”回溯原始 PC。
        const uint64_t pc_old = old_pc_from_new_pc ? old_pc_from_new_pc(pc_new) : pc_new;

        if (is_adrp(insn)) {
            const uint32_t adrp_rd = insn & 0x1fU;
            const uint64_t old_page = decode_adrp_target_page(insn, pc_old);
            uint64_t new_page = old_page;
            bool need_patch_adrp = false;

            for (size_t lookahead = 1; lookahead <= 4 && insn_idx + lookahead < insn_count; ++lookahead) {
                // 在短窗口内搜索与当前 ADRP 绑定的后续 use-site（LDR/STR/ADD）。
                uint32_t use_insn = 0;
                if (!read_u32_le_bytes(*payload, (insn_idx + lookahead) * 4, &use_insn)) {
                    continue;
                }

                const uint32_t rn = (use_insn >> 5) & 0x1fU;
                if (rn != adrp_rd) {
                    continue;
                }

                if (is_ldr_x_uimm(use_insn) || is_str_x_uimm(use_insn) ||
                    is_ldr_w_uimm(use_insn) || is_str_w_uimm(use_insn)) {
                    // 先修补页内偏移，再回填组头 ADRP。
                    const uint64_t old_abs = old_page + decode_ls_uimm(use_insn);
                    const uint64_t new_abs = relocate_old_addr ? relocate_old_addr(old_abs) : old_abs;
                    if (new_abs != old_abs) {
                        uint32_t new_use = 0;
                        if (!encode_ls_uimm_same(use_insn, new_abs & 0xfffULL, &new_use) ||
                            !write_u32_le_bytes(payload, (insn_idx + lookahead) * 4, new_use)) {
                            LOGE("Failed to patch ADRP-linked LS at context=%s insn=%zu",
                                 context_name ? context_name : "(unknown)",
                                 insn_idx + lookahead);
                            return false;
                        }
                        const uint64_t candidate_page = new_abs & ~0xfffULL;
                        if (need_patch_adrp && new_page != candidate_page) {
                            LOGE("Conflicted ADRP page at context=%s insn=%zu",
                                 context_name ? context_name : "(unknown)",
                                 insn_idx);
                            return false;
                        }
                        new_page = candidate_page;
                        need_patch_adrp = true;
                    }
                    continue;
                }

                if (is_add_x_imm(use_insn)) {
                    // ADD 同样参与“页基址+页内偏移”重建。
                    const uint32_t rd = use_insn & 0x1fU;
                    if (rd != adrp_rd) {
                        continue;
                    }
                    const uint64_t old_abs = old_page + decode_add_imm(use_insn);
                    const uint64_t new_abs = relocate_old_addr ? relocate_old_addr(old_abs) : old_abs;
                    if (new_abs != old_abs) {
                        uint32_t new_use = 0;
                        if (!encode_add_imm_same(use_insn, new_abs & 0xfffULL, &new_use) ||
                            !write_u32_le_bytes(payload, (insn_idx + lookahead) * 4, new_use)) {
                            LOGE("Failed to patch ADRP-linked ADD at context=%s insn=%zu",
                                 context_name ? context_name : "(unknown)",
                                 insn_idx + lookahead);
                            return false;
                        }
                        const uint64_t candidate_page = new_abs & ~0xfffULL;
                        if (need_patch_adrp && new_page != candidate_page) {
                            LOGE("Conflicted ADRP page at context=%s insn=%zu",
                                 context_name ? context_name : "(unknown)",
                                 insn_idx);
                            return false;
                        }
                        new_page = candidate_page;
                        need_patch_adrp = true;
                    }
                }
            }

            if (!need_patch_adrp) {
                // 若没识别到 use-site，则退化为直接迁移 ADRP 指向页。
                const uint64_t relocated_page = relocate_old_addr ? relocate_old_addr(old_page) : old_page;
                if (relocated_page != old_page) {
                    new_page = relocated_page;
                    need_patch_adrp = true;
                }
            }

            if (need_patch_adrp) {
                // 最后统一回写 ADRP 本体。
                uint32_t new_insn = 0;
                if (!encode_adrp_same_rd(insn, pc_new, new_page, &new_insn) ||
                    !write_u32_le_bytes(payload, insn_idx * 4, new_insn)) {
                    LOGE("Failed to patch ADRP at context=%s insn=%zu",
                         context_name ? context_name : "(unknown)",
                         insn_idx);
                    return false;
                }
                ++local_adrp_count;
            }
            continue;
        }

        if (is_adr(insn)) {
            // ADR 只有一个目标地址，直接迁移即可。
            const uint64_t old_target = decode_adr_target(insn, pc_old);
            const uint64_t new_target = relocate_old_addr ? relocate_old_addr(old_target) : old_target;
            if (new_target != old_target) {
                uint32_t new_insn = 0;
                if (!encode_adr_same_rd(insn, pc_new, new_target, &new_insn) ||
                    !write_u32_le_bytes(payload, insn_idx * 4, new_insn)) {
                    LOGE("Failed to patch ADR at context=%s insn=%zu",
                         context_name ? context_name : "(unknown)",
                         insn_idx);
                    return false;
                }
                ++local_adr_count;
            }
        }
    }

    if (patched_adrp_count) {
        *patched_adrp_count += local_adrp_count;
    }
    if (patched_adr_count) {
        *patched_adr_count += local_adr_count;
    }
    return true;
}

static const zSectionTableElement* find_section_by_addr(const zElf& elf,
                                                        uint64_t addr,
                                                        uint64_t size,
                                                        Elf64_Word type_filter,
                                                        bool require_alloc) {
    const auto& sections = elf.sectionHeaderModel().elements;
    for (const auto& section_ptr : sections) {
        const auto* section = section_ptr.get();
        if (!section || section->type == SHT_NULL) {
            continue;
        }
        if (type_filter != SHT_NULL && section->type != type_filter) {
            continue;
        }
        if (require_alloc && (section->flags & SHF_ALLOC) == 0) {
            continue;
        }
        if (contains_addr_range_u64(section->addr, section->size, addr, size)) {
            return section;
        }
    }
    return nullptr;
}

// 基础格式校验：文件头、表项尺寸、基础边界关系。
bool zElfValidator::validateBasic(const zElf& elf, std::string* error) {
    const auto& header = elf.headerModel();
    // 当前工具链仅支持 64 位 AArch64，其他目标直接拒绝。
    if (!header.isElf64AArch64()) {
        if (error) {
            *error = "Only ELF64 + AArch64 is supported";
        }
        return false;
    }

    if (header.raw.e_ehsize != sizeof(Elf64_Ehdr) ||
        header.raw.e_phentsize != sizeof(Elf64_Phdr) ||
        header.raw.e_shentsize != sizeof(Elf64_Shdr)) {
        // 头部声明的结构尺寸与 ELF64 规范不一致，后续偏移解析会失真。
        if (error) {
            *error = "ELF header entry size mismatch";
        }
        return false;
    }

    const size_t file_size = elf.fileImageSize();
    if (file_size > 0) {
        // 校验 PHT/SHT 表头区间不会越界到文件尾之外。
        const uint64_t ph_end = (uint64_t)header.raw.e_phoff +
                                (uint64_t)header.raw.e_phentsize * header.raw.e_phnum;
        if (ph_end > file_size) {
            if (error) {
                *error = "Program header table out of file range";
            }
            return false;
        }

        const uint64_t sh_end = (uint64_t)header.raw.e_shoff +
                                (uint64_t)header.raw.e_shentsize * header.raw.e_shnum;
        if (header.raw.e_shnum > 0 && sh_end > file_size) {
            if (error) {
                *error = "Section header table out of file range";
            }
            return false;
        }
    }

    // 每个 phdr 都必须满足 memsz >= filesz（加载器基本约束）。
    for (size_t idx = 0; idx < elf.programHeaderModel().elements.size(); ++idx) {
        if (!elf.programHeaderModel().elements[idx].validateMemFileRelation()) {
            if (error) {
                *error = "memsz < filesz in phdr index " + std::to_string(idx);
            }
            return false;
        }
    }
    return true;
}

// 段布局校验：对齐、覆盖、PT_PHDR/PT_DYNAMIC/PT_INTERP 等关键约束。
bool zElfValidator::validateProgramSegmentLayout(const zElf& elf, std::string* error) {
    const auto& phs = elf.programHeaderModel().elements;
    if (phs.empty()) {
        if (error) {
            *error = "Program header table is empty";
        }
        return false;
    }

    const size_t file_size = elf.fileImageSize();
    const uint64_t runtime_page_size = infer_runtime_page_size_from_phdrs(phs);
    const uint64_t checked_page_size = runtime_page_size == 0 ? 0x1000ULL : runtime_page_size;
    const uint64_t expected_phdr_size = (uint64_t)elf.headerModel().raw.e_phnum * sizeof(Elf64_Phdr);

    int load_count = 0;
    bool has_gnu_relro = false;
    bool has_tls = false;
    zProgramTableElement gnu_relro;
    zProgramTableElement tls_segment;
    for (size_t idx = 0; idx < phs.size(); ++idx) {
        const auto& ph = phs[idx];
        if (ph.type == PT_LOAD) {
            // 统计 LOAD 数量，最后用于“至少存在一个映射段”约束。
            ++load_count;
        }
        if (ph.type == PT_GNU_RELRO) {
            has_gnu_relro = true;
            gnu_relro = ph;
        }
        if (ph.type == PT_TLS) {
            has_tls = true;
            tls_segment = ph;
        }

        if (ph.align > 1) {
            // p_align 只允许 2 的幂；并满足 offset/vaddr 同余。
            if (!is_power_of_two_u64(ph.align)) {
                // 非 2 的幂会破坏页级映射计算。
                if (error) {
                    *error = "p_align is not power-of-two at phdr index " + std::to_string(idx);
                }
                return false;
            }
            if ((ph.offset % ph.align) != (ph.vaddr % ph.align)) {
                // 不同余会导致加载器无法建立一致的文件->内存映射。
                if (error) {
                    *error = "p_offset % p_align != p_vaddr % p_align at phdr index " + std::to_string(idx);
                }
                return false;
            }
        }

        if (ph.filesz > 0) {
            // 文件区间必须在镜像范围内。
            uint64_t end = 0;
            if (!add_u64_checked(ph.offset, ph.filesz, &end) || end > file_size) {
                // 包括“加法溢出”和“越过文件尾”两类错误。
                if (error) {
                    *error = "Segment file range out of file at phdr index " + std::to_string(idx);
                }
                return false;
            }
        }

        if (ph.memsz > 0) {
            // 虚拟地址区间不能发生 64 位溢出。
            uint64_t vaddr_end = 0;
            if (!add_u64_checked(ph.vaddr, ph.memsz, &vaddr_end)) {
                // 溢出后所有范围判断都不可信，直接判失败。
                if (error) {
                    *error = "Segment virtual range overflow at phdr index " + std::to_string(idx);
                }
                return false;
            }
        }

        if (ph.type == PT_PHDR) {
            // PT_PHDR 必须被某个 PT_LOAD 覆盖，并且 vaddr 映射与该 LOAD 一致。
            if (ph.filesz < expected_phdr_size || ph.memsz < ph.filesz) {
                if (error) {
                    *error = "PT_PHDR size mismatch at phdr index " + std::to_string(idx);
                }
                return false;
            }
            const uint64_t phdr_begin = ph.offset;
            const uint64_t phdr_end = ph.offset + ph.filesz;
            bool covered_by_load = false;
            for (const auto& load : phs) {
                if (load.type != PT_LOAD || load.filesz == 0) {
                    continue;
                }
                const uint64_t load_begin = load.offset;
                const uint64_t load_end = load.offset + load.filesz;
                if (phdr_begin < load_begin || phdr_end > load_end) {
                    continue;
                }
                const uint64_t expected_vaddr = (uint64_t)load.vaddr + (phdr_begin - load_begin);
                if ((uint64_t)ph.vaddr != expected_vaddr || (uint64_t)ph.paddr != expected_vaddr) {
                    // PT_PHDR 的 vaddr/paddr 必须严格由承载 LOAD 推导得到。
                    if (error) {
                        *error = "PT_PHDR vaddr/paddr mismatch at phdr index " + std::to_string(idx);
                    }
                    return false;
                }
                covered_by_load = true;
                break;
            }
            if (!covered_by_load) {
                if (error) {
                    *error = "PT_PHDR is not covered by any PT_LOAD at phdr index " + std::to_string(idx);
                }
                return false;
            }
        }

        if (ph.type == PT_DYNAMIC && ph.filesz > 0) {
            // PT_DYNAMIC 也必须落在某个 PT_LOAD 覆盖范围内。
            const uint64_t dyn_begin = ph.offset;
            const uint64_t dyn_end = ph.offset + ph.filesz;
            bool mapped = false;
            for (const auto& load : phs) {
                if (load.type != PT_LOAD || load.filesz == 0) {
                    continue;
                }
                const uint64_t load_begin = load.offset;
                const uint64_t load_end = load.offset + load.filesz;
                if (dyn_begin < load_begin || dyn_end > load_end) {
                    continue;
                }
                const uint64_t expected_vaddr = (uint64_t)load.vaddr + (dyn_begin - load_begin);
                if ((uint64_t)ph.vaddr != expected_vaddr) {
                    // dynamic 表的虚拟地址应与文件偏移映射一致。
                    if (error) {
                        *error = "PT_DYNAMIC vaddr mismatch at phdr index " + std::to_string(idx);
                    }
                    return false;
                }
                mapped = true;
                break;
            }
            if (!mapped) {
                if (error) {
                    *error = "PT_DYNAMIC is not covered by any PT_LOAD at phdr index " + std::to_string(idx);
                }
                return false;
            }
        }
    }

    if (load_count == 0) {
        // 没有 LOAD 段的 ELF 无法被常规运行时加载。
        if (error) {
            *error = "No PT_LOAD segments found";
        }
        return false;
    }

    if (has_gnu_relro && gnu_relro.memsz > 0) {
        // RELRO 区必须先位于可写 LOAD，运行时再改成只读。
        const uint64_t relro_begin = (uint64_t)gnu_relro.vaddr;
        const uint64_t relro_end = relro_begin + (uint64_t)gnu_relro.memsz;

        bool relro_covered = false;
        for (const auto& load : phs) {
            if (load.type != PT_LOAD || (load.flags & PF_W) == 0) {
                // RELRO 生效前位于可写段，因此必须匹配 PF_W。
                continue;
            }
            const uint64_t load_begin = (uint64_t)load.vaddr;
            const uint64_t load_end = load_begin + (uint64_t)load.memsz;
            if (relro_begin >= load_begin && relro_end <= load_end) {
                relro_covered = true;
                break;
            }
        }

        if (!relro_covered) {
            if (error) {
                *error = "PT_GNU_RELRO is not fully covered by a writable PT_LOAD";
            }
            return false;
        }
    }

    if (has_tls) {
        // TLS 段要求文件区间与虚拟区间都被某个 LOAD 包含。
        bool tls_covered = false;
        for (const auto& load : phs) {
            if (load.type != PT_LOAD) {
                continue;
            }
            const uint64_t load_file_begin = load.offset;
            const uint64_t load_file_end = load.offset + load.filesz;
            const uint64_t load_va_begin = load.vaddr;
            const uint64_t load_va_end = load.vaddr + load.memsz;

            const uint64_t tls_file_begin = tls_segment.offset;
            const uint64_t tls_file_end = tls_segment.offset + tls_segment.filesz;
            const uint64_t tls_va_begin = tls_segment.vaddr;
            const uint64_t tls_va_end = tls_segment.vaddr + tls_segment.memsz;

            const bool file_covered = tls_segment.filesz == 0 ||
                                      (tls_file_begin >= load_file_begin && tls_file_end <= load_file_end);
            const bool va_covered = tls_segment.memsz == 0 ||
                                    (tls_va_begin >= load_va_begin && tls_va_end <= load_va_end);
            if (file_covered && va_covered) {
                // 只有 file/va 两个维度都覆盖，TLS 才可认为合法。
                tls_covered = true;
                break;
            }
        }

        if (!tls_covered) {
            if (error) {
                *error = "PT_TLS is not covered by any PT_LOAD";
            }
            return false;
        }
    }

    for (size_t i = 0; i < phs.size(); ++i) {
        const auto& a = phs[i];
        if (a.type != PT_LOAD) {
            continue;
        }
        for (size_t j = i + 1; j < phs.size(); ++j) {
            const auto& b = phs[j];
            if (b.type != PT_LOAD) {
                continue;
            }

            const bool file_overlap = ranges_overlap_u64(a.offset, a.filesz, b.offset, b.filesz);
            const bool va_overlap = ranges_overlap_u64(a.vaddr, a.memsz, b.vaddr, b.memsz);
            // 允许的 overlap 仅限“同页同映射”类特例，其余一律视为非法。
            if ((file_overlap || va_overlap) && !is_acceptable_load_overlap(a, b, runtime_page_size)) {
                // 这里拒绝的是“不可解释的段重叠”，常见于重排错误或对齐计算失误。
                if (error) {
                    *error = "PT_LOAD overlap is not acceptable between phdr " + std::to_string(i) +
                             " and " + std::to_string(j);
                }
                return false;
            }
        }
    }

    return true;
}

// 节与段映射校验：ALLOC 节必须能被 LOAD 段覆盖并满足边界关系。
bool zElfValidator::validateSectionSegmentMapping(const zElf& elf, std::string* error) {
    const auto& phs = elf.programHeaderModel().elements;
    const auto& secs = elf.sectionHeaderModel().elements;
    const size_t file_size = elf.fileImageSize();
    if (secs.empty()) {
        return true;
    }

    for (size_t idx = 0; idx < secs.size(); ++idx) {
        const auto& section = *secs[idx];
        if (section.type == SHT_NULL) {
            continue;
        }

        if (section.type != SHT_NOBITS && section.size > 0 &&
            ((uint64_t)section.offset + section.size > file_size)) {
            // 非 NOBITS 节必须可在文件中完整读取。
            if (error) {
                *error = "Section out of file range at index " + std::to_string(idx);
            }
            return false;
        }

        if ((section.flags & SHF_ALLOC) == 0) {
            continue;
        }

        // ALLOC 节必须找到一个 flags 匹配的 LOAD 来承载它。
        bool mapped_to_load = false;
        for (const auto& ph : phs) {
            if (!load_segment_matches_section_flags(ph, section)) {
                continue;
            }

            // 文件区间检查：NOBITS 不占文件空间，可跳过文件范围约束。
            const uint64_t seg_file_start = ph.offset;
            const uint64_t seg_file_end = ph.offset + ph.filesz;
            const uint64_t sec_file_start = section.offset;
            const uint64_t sec_file_end = section.offset + section.size;
            const bool in_file_range = section.type == SHT_NOBITS ||
                                       (sec_file_start >= seg_file_start && sec_file_end <= seg_file_end);

            const uint64_t seg_va_start = ph.vaddr;
            const uint64_t seg_va_end = ph.vaddr + ph.memsz;
            const uint64_t sec_va_start = section.addr;
            const uint64_t sec_va_end = section.addr + section.size;
            // 虚拟地址区间始终需要落在段 memsz 范围内。
            const bool in_va_range = sec_va_start >= seg_va_start && sec_va_end <= seg_va_end;

            if (in_file_range && in_va_range) {
                // 命中一个满足 flags + file + va 三条件的 LOAD 即视为有效映射。
                mapped_to_load = true;
                break;
            }
        }

        if (!mapped_to_load) {
            if (error) {
                *error = "ALLOC section not mapped to LOAD at index " + std::to_string(idx) +
                         " (" + section.resolved_name + ")";
            }
            return false;
        }
    }
    return true;
}

// 符号解析校验：符号表、字符串表、节索引与地址可达性。
bool zElfValidator::validateSymbolResolution(const zElf& elf, std::string* error) {
    const auto& sections = elf.sectionHeaderModel().elements;

    for (size_t sec_idx = 0; sec_idx < sections.size(); ++sec_idx) {
        const auto* section = sections[sec_idx].get();
        if (!section) {
            continue;
        }
        if (section->type != SHT_SYMTAB && section->type != SHT_DYNSYM) {
            continue;
        }

        const auto* symbol_section = dynamic_cast<const zSymbolSection*>(section);
        if (!symbol_section) {
            // section 类型与具体解析类不一致，说明模型构建异常。
            if (error) {
                *error = "Symbol section type mismatch at section index " + std::to_string(sec_idx);
            }
            return false;
        }
        if (symbol_section->symbols.empty() && section->size > 0) {
            // 原始节有数据但未解析出符号，通常表示格式破坏。
            if (error) {
                *error = "Symbol section parse failed at section index " + std::to_string(sec_idx);
            }
            return false;
        }

        const uint32_t strtab_idx = section->link;
        // 符号节的 sh_link 必须指向字符串表。
        if (strtab_idx >= sections.size()) {
            if (error) {
                *error = "Symbol section sh_link out of range at section index " + std::to_string(sec_idx);
            }
            return false;
        }

        const auto* strtab_section = sections[strtab_idx].get();
        if (!strtab_section || strtab_section->type != SHT_STRTAB) {
            if (error) {
                *error = "Symbol section sh_link is not a STRTAB at section index " + std::to_string(sec_idx);
            }
            return false;
        }
        const auto& strtab = strtab_section->payload;
        if (strtab.empty()) {
            // 无字符串表时无法解析 st_name。
            if (error) {
                *error = "Symbol string table is empty for section index " + std::to_string(sec_idx);
            }
            return false;
        }

        for (size_t sym_idx = 0; sym_idx < symbol_section->symbols.size(); ++sym_idx) {
            const Elf64_Sym& sym = symbol_section->symbols[sym_idx];
            const uint64_t st_name = sym.st_name;
            if (st_name >= strtab.size()) {
                // st_name 必须是字符串表内偏移。
                if (error) {
                    *error = "Symbol name offset out of range at section " + std::to_string(sec_idx) +
                             ", symbol " + std::to_string(sym_idx);
                }
                return false;
            }
            if (!has_string_terminator(strtab, (size_t)st_name)) {
                // 防止读取越界直到文件尾都找不到 '\0'。
                if (error) {
                    *error = "Symbol name is not null-terminated at section " + std::to_string(sec_idx) +
                             ", symbol " + std::to_string(sym_idx);
                }
                return false;
            }

            const uint16_t shndx = sym.st_shndx;
            if (is_special_shndx(shndx)) {
                // SHN_UNDEF/ABS/COMMON 等特殊索引按规范跳过普通节范围校验。
                continue;
            }
            if (shndx >= sections.size()) {
                if (error) {
                    *error = "Symbol section index out of range at section " + std::to_string(sec_idx) +
                             ", symbol " + std::to_string(sym_idx);
                }
                return false;
            }

            const auto* target_section = sections[shndx].get();
            if (!target_section) {
                // 节索引合法但目标对象缺失，属于模型损坏。
                if (error) {
                    *error = "Symbol target section missing at section " + std::to_string(sec_idx) +
                             ", symbol " + std::to_string(sym_idx);
                }
                return false;
            }

            if ((target_section->flags & SHF_ALLOC) != 0 && target_section->size > 0) {
                // 对映射到内存的目标节，符号值必须落在节范围且被 PT_LOAD 可达。
                if (!contains_addr_range_u64(target_section->addr,
                                             target_section->size,
                                             sym.st_value,
                                             sym.st_size)) {
                    // 可分配节符号值必须落在其所属节的地址范围内。
                    if (error) {
                        *error = "Symbol value out of target section range at section " +
                                 std::to_string(sec_idx) + ", symbol " + std::to_string(sym_idx);
                    }
                    return false;
                }
                if (!is_load_vaddr_mapped(elf, sym.st_value, sym.st_size)) {
                    // 即便在节范围内，也必须被 PT_LOAD 实际映射覆盖。
                    if (error) {
                        *error = "Symbol value is not mapped by any PT_LOAD at section " +
                                 std::to_string(sec_idx) + ", symbol " + std::to_string(sym_idx);
                    }
                    return false;
                }
            }
        }
    }

    return true;
}

// PLT/GOT/重定位校验：动态标签配套关系与数据结构合法性。
bool zElfValidator::validatePltGotRelocations(const zElf& elf, std::string* error) {
    std::unordered_map<int64_t, uint64_t> dynamic_tags;
    if (!collect_dynamic_tags(elf, &dynamic_tags, error)) {
        return false;
    }

    if (!dynamic_tags.empty()) {
        // 先逐个检查 dynamic pointer 标签是否可由 PT_LOAD 映射到内存。
        for (const auto& item : dynamic_tags) {
            const Elf64_Sxword tag = (Elf64_Sxword)item.first;
            const Elf64_Addr value = (Elf64_Addr)item.second;
            if (value == 0 || !is_dynamic_pointer_tag(tag)) {
                continue;
            }
            if (!is_load_vaddr_mapped(elf, value, 1)) {
                if (error) {
                    *error = "Dynamic pointer tag is not mapped by PT_LOAD: " +
                             dynamic_tag_label(tag) +
                             ", value=" + hex_u64_label((uint64_t)value);
                }
                return false;
            }
        }

        // AArch64 下本项目约定 PLT 重定位类型为 RELA。
        const auto pltrel_it = dynamic_tags.find(DT_PLTREL);
        if (pltrel_it != dynamic_tags.end() && pltrel_it->second != DT_RELA) {
            // 当前项目仅支持 AArch64 的 RELA 路线。
            if (error) {
                *error = "DT_PLTREL is not DT_RELA";
            }
            return false;
        }

        const auto relaent_it = dynamic_tags.find(DT_RELAENT);
        if (relaent_it != dynamic_tags.end() && relaent_it->second != sizeof(Elf64_Rela)) {
            // RELA 表项大小必须与 Elf64_Rela 一致。
            if (error) {
                *error = "DT_RELAENT mismatch";
            }
            return false;
        }

        const auto pltrelsz_it = dynamic_tags.find(DT_PLTRELSZ);
        if (pltrelsz_it != dynamic_tags.end() && (pltrelsz_it->second % sizeof(Elf64_Rela)) != 0) {
            // PLT 重定位总大小必须是表项大小整数倍。
            if (error) {
                *error = "DT_PLTRELSZ is not aligned to Elf64_Rela size";
            }
            return false;
        }

        const auto relasz_it = dynamic_tags.find(DT_RELASZ);
        if (relasz_it != dynamic_tags.end() && (relasz_it->second % sizeof(Elf64_Rela)) != 0) {
            // .rela.dyn 总大小同样要求表项对齐。
            if (error) {
                *error = "DT_RELASZ is not aligned to Elf64_Rela size";
            }
            return false;
        }

        const auto pltgot_it = dynamic_tags.find(DT_PLTGOT);
        if (pltgot_it != dynamic_tags.end()) {
            // 至少要能读取一个 8 字节槽位。
            if (!is_load_vaddr_mapped(elf, (Elf64_Addr)pltgot_it->second, sizeof(uint64_t))) {
                if (error) {
                    *error = "DT_PLTGOT is not mapped by PT_LOAD";
                }
                return false;
            }
        }
    }
    return true;
}

// 重解析一致性：用当前字节流重新解析并与模型规模做一致性比对。
bool zElfValidator::validateReparseConsistency(const zElf& elf, std::string* error) {
    const uint8_t* file_data = elf.fileImageData();
    const size_t file_size = elf.fileImageSize();
    if (!file_data || file_size < sizeof(Elf64_Ehdr)) {
        if (error) {
            *error = "No loaded ELF bytes for reparse";
        }
        return false;
    }

    zElfHeader reparsed_header;
    if (!reparsed_header.fromRaw(file_data, file_size) ||
        !reparsed_header.isElf64AArch64()) {
        // 写回后的字节流必须仍可被“全新解析流程”识别。
        if (error) {
            *error = "Reparse header failed or target is not ELF64/AArch64";
        }
        return false;
    }

    const Elf64_Ehdr& eh = reparsed_header.raw;
    // 二次解析时再次验证表区间边界，防止模型写回后产生坏偏移。
    const uint64_t ph_end = (uint64_t)eh.e_phoff + (uint64_t)eh.e_phentsize * eh.e_phnum;
    const uint64_t sh_end = (uint64_t)eh.e_shoff + (uint64_t)eh.e_shentsize * eh.e_shnum;
    if (ph_end > file_size || (eh.e_shnum > 0 && sh_end > file_size)) {
        if (error) {
            *error = "Reparse table offsets out of file range";
        }
        return false;
    }

    zElfProgramHeaderTable reparsed_ph;
    // 使用“从字节重新解析”的方式校验写回后的结构是否可自洽。
    reparsed_ph.fromRaw(reinterpret_cast<const Elf64_Phdr*>(file_data + eh.e_phoff), eh.e_phnum);
    // 重解析结果中的 memsz/filesz 关系仍需成立。
    for (size_t idx = 0; idx < reparsed_ph.elements.size(); ++idx) {
        if (!reparsed_ph.elements[idx].validateMemFileRelation()) {
            if (error) {
                *error = "Reparse memsz/filesz mismatch at phdr index " + std::to_string(idx);
            }
            return false;
        }
    }

    zElfSectionHeaderTable reparsed_sh;
    if (eh.e_shnum > 0) {
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

    // 最后用“数量一致性”做快照级 sanity check。
    if (reparsed_ph.elements.size() != elf.programHeaderModel().elements.size()) {
        if (error) {
            *error = "Reparse phdr count mismatch";
        }
        return false;
    }
    if (reparsed_sh.elements.size() != elf.sectionHeaderModel().elements.size()) {
        if (error) {
            *error = "Reparse shdr count mismatch";
        }
        return false;
    }
    return true;
}

// 全量校验入口：按固定阶段顺序执行并附加阶段前缀。
bool zElfValidator::validateAll(const zElf& elf, std::string* error) {
    // 阶段顺序固定：先基础结构，再段布局，再动态重定位关系，最后重解析一致性。
    if (!validateBasic(elf, error)) {
        prefix_validation_error(error, "[BASIC]");
        return false;
    }
    if (!validateProgramSegmentLayout(elf, error)) {
        prefix_validation_error(error, "[SEGMENT]");
        return false;
    }
    // 当前主链路聚焦动态重定位与可加载性；section/symbol 细粒度校验按需单独调用。
    if (!validatePltGotRelocations(elf, error)) {
        prefix_validation_error(error, "[PLT_GOT]");
        return false;
    }
    if (!validateReparseConsistency(elf, error)) {
        prefix_validation_error(error, "[REPARSE]");
        return false;
    }
    return true;
}
