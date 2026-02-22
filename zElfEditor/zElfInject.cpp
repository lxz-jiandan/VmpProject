#include "zElf.h"
#include "zElfUtils.h"
#include "zLog.h"

#include <algorithm>
#include <cstring>
#include <functional>
#include <limits>
#include <unordered_set>

#include "zElfPcRelativePatcher.h"

/**
 * @file zElfInject.cpp
 * @brief donor -> target 段注入与融合实现。
 *
 * 该模块完成"把 donor ELF 的可加载段合并进 target ELF"的完整流程，
 * 包含段配对、数据搬运、地址修补、符号融合、重构与校验。
 *
 * 关键挑战：
 * - 不同 LOAD 段的对齐/权限/大小约束要保持可加载性；
 * - AArch64 PC 相对指令（ADRP/ADR/LDR literal）在迁移后需修补；
 * - 动态重定位和打包重定位中的地址要统一重写；
 * - 结果必须通过 validateAll() 的多阶段一致性校验。
 */

namespace {

#if 0 // moved to zElfPcRelativePatcher
struct PatchStats {
    size_t adrp = 0;
    size_t adr = 0;
    size_t ldr_literal = 0;
    size_t ldr_simd = 0;
    size_t prfm = 0;
    size_t br = 0;
    size_t bl = 0;
    size_t cond_br = 0;
    size_t expanded = 0;
};

bool arm64_reg_to_gpr_index(unsigned reg, bool* is_w, unsigned* index) {
    if (!is_w || !index) {
        return false;
    }
    if (reg >= AARCH64_REG_X0 && reg <= AARCH64_REG_X28) {
        *is_w = false;
        *index = reg - AARCH64_REG_X0;
        return true;
    }
    if (reg == AARCH64_REG_X29) {
        *is_w = false;
        *index = 29;
        return true;
    }
    if (reg == AARCH64_REG_X30) {
        *is_w = false;
        *index = 30;
        return true;
    }
    if (reg == AARCH64_REG_XZR) {
        *is_w = false;
        *index = 31;
        return true;
    }
    if (reg >= AARCH64_REG_W0 && reg <= AARCH64_REG_W28) {
        *is_w = true;
        *index = reg - AARCH64_REG_W0;
        return true;
    }
    if (reg == AARCH64_REG_W29) {
        *is_w = true;
        *index = 29;
        return true;
    }
    if (reg == AARCH64_REG_W30) {
        *is_w = true;
        *index = 30;
        return true;
    }
    if (reg == AARCH64_REG_WZR) {
        *is_w = true;
        *index = 31;
        return true;
    }
    return false;
}

void emit_u32(std::vector<uint8_t>* out, uint32_t insn) {
    if (!out) {
        return;
    }
    out->push_back((uint8_t)(insn & 0xffU));
    out->push_back((uint8_t)((insn >> 8) & 0xffU));
    out->push_back((uint8_t)((insn >> 16) & 0xffU));
    out->push_back((uint8_t)((insn >> 24) & 0xffU));
}

void emit_movz_movk_sequence(std::vector<uint8_t>* out, unsigned rd, bool is_w, uint64_t value) {
    if (!out) {
        return;
    }
    const uint32_t movz_base = is_w ? 0x52800000U : 0xd2800000U;
    const uint32_t movk_base = is_w ? 0x72800000U : 0xf2800000U;
    const int shifts[] = {0, 16, 32, 48};
    const int count = is_w ? 2 : 4;
    for (int i = 0; i < count; ++i) {
        const int shift = shifts[i];
        const uint16_t imm16 = (uint16_t)((value >> shift) & 0xffffU);
        const uint32_t hw = (uint32_t)(shift / 16);
        const uint32_t base = (i == 0) ? movz_base : movk_base;
        const uint32_t insn = base | (hw << 21) | ((uint32_t)imm16 << 5) | (rd & 0x1fU);
        emit_u32(out, insn);
    }
}

bool emit_ldr_reg(std::vector<uint8_t>* out, bool is_w, unsigned rt, unsigned rn, bool is_ldrsw) {
    if (!out) {
        return false;
    }
    uint32_t base = 0;
    if (is_ldrsw) {
        base = 0xb9800000U;
    } else {
        base = is_w ? 0xb9400000U : 0xf9400000U;
    }
    const uint32_t insn = base | ((rn & 0x1fU) << 5) | (rt & 0x1fU);
    emit_u32(out, insn);
    return true;
}

bool emit_ldr_zero_reg(std::vector<uint8_t>* out, unsigned rt, unsigned rn, int size_bytes) {
    if (!out) {
        return false;
    }
    uint32_t base = 0;
    switch (size_bytes) {
        case 1:
            base = 0x39400000U;
            break;
        case 2:
            base = 0x79400000U;
            break;
        case 4:
            base = 0xb9400000U;
            break;
        case 8:
            base = 0xf9400000U;
            break;
        default:
            return false;
    }
    const uint32_t insn = base | ((rn & 0x1fU) << 5) | (rt & 0x1fU);
    emit_u32(out, insn);
    return true;
}

enum SimdClass {
    SIMD_INVALID = 0,
    SIMD_B,
    SIMD_H,
    SIMD_S,
    SIMD_D,
    SIMD_Q,
};

bool arm64_reg_to_simd_class(unsigned reg, unsigned* index, SimdClass* cls) {
    if (!index || !cls) {
        return false;
    }
    if (reg >= AARCH64_REG_B0 && reg <= AARCH64_REG_B31) {
        *index = reg - AARCH64_REG_B0;
        *cls = SIMD_B;
        return true;
    }
    if (reg >= AARCH64_REG_H0 && reg <= AARCH64_REG_H31) {
        *index = reg - AARCH64_REG_H0;
        *cls = SIMD_H;
        return true;
    }
    if (reg >= AARCH64_REG_S0 && reg <= AARCH64_REG_S31) {
        *index = reg - AARCH64_REG_S0;
        *cls = SIMD_S;
        return true;
    }
    if (reg >= AARCH64_REG_D0 && reg <= AARCH64_REG_D31) {
        *index = reg - AARCH64_REG_D0;
        *cls = SIMD_D;
        return true;
    }
    if (reg >= AARCH64_REG_Q0 && reg <= AARCH64_REG_Q31) {
        *index = reg - AARCH64_REG_Q0;
        *cls = SIMD_Q;
        return true;
    }
    return false;
}

bool emit_simd_ldr_reg(std::vector<uint8_t>* out, SimdClass cls, unsigned rt, unsigned rn) {
    if (!out) {
        return false;
    }
    uint32_t base = 0;
    switch (cls) {
        case SIMD_B:
            base = 0x3d400000U;
            break;
        case SIMD_H:
            base = 0x7d400000U;
            break;
        case SIMD_S:
            base = 0xbd400000U;
            break;
        case SIMD_D:
            base = 0xfd400000U;
            break;
        case SIMD_Q:
            base = 0x3dc00000U;
            break;
        default:
            return false;
    }
    const uint32_t insn = base | ((rn & 0x1fU) << 5) | (rt & 0x1fU);
    emit_u32(out, insn);
    return true;
}

bool emit_ldr_signed_reg(std::vector<uint8_t>* out, unsigned rt, unsigned rn, bool is_half, bool to_w) {
    if (!out) {
        return false;
    }
    uint32_t base = 0;
    if (is_half) {
        base = to_w ? 0x79c00000U : 0x79800000U;
    } else {
        base = to_w ? 0x39c00000U : 0x39800000U;
    }
    const uint32_t insn = base | ((rn & 0x1fU) << 5) | (rt & 0x1fU);
    emit_u32(out, insn);
    return true;
}

uint32_t encode_imm19(uint32_t raw, int32_t imm19) {
    return (raw & ~(0x7ffffU << 5)) | (((uint32_t)imm19 & 0x7ffffU) << 5);
}

uint32_t encode_imm14(uint32_t raw, int32_t imm14) {
    return (raw & ~(0x3fffU << 5)) | (((uint32_t)imm14 & 0x3fffU) << 5);
}

int invert_arm64_cc(int cc) {
    switch (cc) {
        case AArch64CC_EQ: return AArch64CC_NE;
        case AArch64CC_NE: return AArch64CC_EQ;
        case AArch64CC_HS: return AArch64CC_LO;
        case AArch64CC_LO: return AArch64CC_HS;
        case AArch64CC_MI: return AArch64CC_PL;
        case AArch64CC_PL: return AArch64CC_MI;
        case AArch64CC_VS: return AArch64CC_VC;
        case AArch64CC_VC: return AArch64CC_VS;
        case AArch64CC_HI: return AArch64CC_LS;
        case AArch64CC_LS: return AArch64CC_HI;
        case AArch64CC_GE: return AArch64CC_LT;
        case AArch64CC_LT: return AArch64CC_GE;
        case AArch64CC_GT: return AArch64CC_LE;
        case AArch64CC_LE: return AArch64CC_GT;
        default: return -1;
    }
}

uint32_t encode_b_cond(int32_t imm19, int cc) {
    return 0x54000000U | (((uint32_t)imm19 & 0x7ffffU) << 5) | ((uint32_t)cc & 0xfU);
}

// 修补 AArch64 PC 相对寻址指令（ADRP/ADR/LDR literal/BL/B），使用 capstone 并扩容为 PC 无关序列。
bool patch_aarch64_pc_relative_payload(
        const std::vector<uint8_t>& input,
        uint64_t old_pc_base,
        const std::function<uint64_t(uint64_t)>& relocate_old_addr,
        std::vector<uint8_t>* output,
        PatchStats* stats,
        const char* context_name) {
    if (!output) {
        return false;
    }

    output->clear();
    output->reserve(input.size());

    csh handle = 0;
    if (cs_open(CS_ARCH_AARCH64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        LOGE("Failed to init capstone for context=%s", context_name ? context_name : "(unknown)");
        return false;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    const uint8_t* code = input.data();
    size_t size = input.size();
    uint64_t address = old_pc_base;

    cs_insn insn;
    while (size >= 4) {
        const uint64_t insn_addr = address;
        if (!cs_disasm_iter(handle, &code, &size, &address, &insn)) {
            const size_t off = (size_t)(insn_addr - old_pc_base);
            uint32_t raw = 0;
            if (!read_u32_le_bytes(input, off, &raw)) {
                cs_close(&handle);
                return false;
            }
            emit_u32(output, raw);
            code += 4;
            size -= 4;
            address += 4;
            continue;
        }

        bool patched = false;
        const cs_aarch64& arm64 = insn.detail->aarch64;
        const uint32_t raw =
                (uint32_t)insn.bytes[0] |
                ((uint32_t)insn.bytes[1] << 8) |
                ((uint32_t)insn.bytes[2] << 16) |
                ((uint32_t)insn.bytes[3] << 24);

        auto emit_branch_sequence = [&](uint64_t old_target) -> bool {
            const uint64_t new_target = relocate_old_addr(old_target);
            const unsigned scratch = 16;
            emit_movz_movk_sequence(output, scratch, false, new_target);
            emit_u32(output, 0xd61f0000U | ((scratch & 0x1fU) << 5));
            return true;
        };

        if (insn.id == AARCH64_INS_B &&
            arm64.op_count >= 1 &&
            arm64.operands[0].type == AARCH64_OP_IMM &&
            arm64.cc != AArch64CC_AL && arm64.cc != AArch64CC_Invalid) {
            const int inv_cc = invert_arm64_cc(arm64.cc);
            if (inv_cc < 0) {
                cs_close(&handle);
                return false;
            }
            const int32_t skip_imm19 = 5;
            emit_u32(output, encode_b_cond(skip_imm19, inv_cc));
            if (!emit_branch_sequence((uint64_t)arm64.operands[0].imm)) {
                cs_close(&handle);
                return false;
            }
            if (stats) {
                ++stats->cond_br;
                ++stats->expanded;
            }
            patched = true;
        } else if ((insn.id == AARCH64_INS_CBZ || insn.id == AARCH64_INS_CBNZ) &&
                   arm64.op_count >= 2 &&
                   arm64.operands[1].type == AARCH64_OP_IMM) {
            const int32_t skip_imm19 = 5;
            const uint32_t inv_raw = raw ^ (1U << 24);
            emit_u32(output, encode_imm19(inv_raw, skip_imm19));
            if (!emit_branch_sequence((uint64_t)arm64.operands[1].imm)) {
                cs_close(&handle);
                return false;
            }
            if (stats) {
                ++stats->cond_br;
                ++stats->expanded;
            }
            patched = true;
        } else if ((insn.id == AARCH64_INS_TBZ || insn.id == AARCH64_INS_TBNZ) &&
                   arm64.op_count >= 3 &&
                   arm64.operands[2].type == AARCH64_OP_IMM) {
            const int32_t skip_imm14 = 5;
            const uint32_t inv_raw = raw ^ (1U << 24);
            emit_u32(output, encode_imm14(inv_raw, skip_imm14));
            if (!emit_branch_sequence((uint64_t)arm64.operands[2].imm)) {
                cs_close(&handle);
                return false;
            }
            if (stats) {
                ++stats->cond_br;
                ++stats->expanded;
            }
            patched = true;
        }

        if (patched) {
            continue;
        }

        if (insn.id == AARCH64_INS_ADRP && arm64.op_count >= 2 &&
            arm64.operands[0].type == AARCH64_OP_REG &&
            arm64.operands[1].type == AARCH64_OP_IMM) {
            bool is_w = false;
            unsigned rd = 0;
            if (!arm64_reg_to_gpr_index(arm64.operands[0].reg, &is_w, &rd)) {
                cs_close(&handle);
                return false;
            }
            const uint64_t old_target = (uint64_t)arm64.operands[1].imm;
            const uint64_t new_target_page = relocate_old_addr(old_target) & ~0xfffULL;
            emit_movz_movk_sequence(output, rd, is_w, new_target_page);
            if (stats) {
                ++stats->adrp;
                ++stats->expanded;
            }
            patched = true;
        } else if (insn.id == AARCH64_INS_ADR && arm64.op_count >= 2 &&
                   arm64.operands[0].type == AARCH64_OP_REG &&
                   arm64.operands[1].type == AARCH64_OP_IMM) {
            bool is_w = false;
            unsigned rd = 0;
            if (!arm64_reg_to_gpr_index(arm64.operands[0].reg, &is_w, &rd)) {
                cs_close(&handle);
                return false;
            }
            const uint64_t old_target = (uint64_t)arm64.operands[1].imm;
            const uint64_t new_target = relocate_old_addr(old_target);
            emit_movz_movk_sequence(output, rd, is_w, new_target);
            if (stats) {
                ++stats->adr;
                ++stats->expanded;
            }
            patched = true;
        } else if (arm64.op_count >= 2 &&
                   arm64.operands[0].type == AARCH64_OP_REG &&
                   arm64.operands[1].type == AARCH64_OP_IMM &&
                   (insn.id == AARCH64_INS_LDR || insn.id == AARCH64_INS_LDRSW ||
                    insn.id == AARCH64_INS_LDRB || insn.id == AARCH64_INS_LDRH ||
                    insn.id == AARCH64_INS_LDRSB || insn.id == AARCH64_INS_LDRSH)) {
            bool is_w = false;
            unsigned rt = 0;
            unsigned simd_rt = 0;
            SimdClass simd_class = SIMD_INVALID;
            const bool is_gpr = arm64_reg_to_gpr_index(arm64.operands[0].reg, &is_w, &rt);
            const bool is_simd = arm64_reg_to_simd_class(arm64.operands[0].reg, &simd_rt, &simd_class);
            if (!is_gpr && !is_simd) {
                cs_close(&handle);
                return false;
            }
            const uint64_t old_target = (uint64_t)arm64.operands[1].imm;
            const uint64_t new_target = relocate_old_addr(old_target);
            const unsigned scratch = 16;
            emit_movz_movk_sequence(output, scratch, false, new_target);
            if (is_gpr) {
                bool ok = false;
                if (insn.id == AARCH64_INS_LDRSW) {
                    ok = emit_ldr_reg(output, false, rt, scratch, true);
                } else if (insn.id == AARCH64_INS_LDRB) {
                    ok = emit_ldr_zero_reg(output, rt, scratch, 1);
                } else if (insn.id == AARCH64_INS_LDRH) {
                    ok = emit_ldr_zero_reg(output, rt, scratch, 2);
                } else if (insn.id == AARCH64_INS_LDRSB) {
                    ok = emit_ldr_signed_reg(output, rt, scratch, false, is_w);
                } else if (insn.id == AARCH64_INS_LDRSH) {
                    ok = emit_ldr_signed_reg(output, rt, scratch, true, is_w);
                } else {
                    ok = emit_ldr_zero_reg(output, rt, scratch, is_w ? 4 : 8);
                }
                if (!ok) {
                    cs_close(&handle);
                    return false;
                }
                if (stats) {
                    ++stats->ldr_literal;
                    ++stats->expanded;
                }
            } else {
                if (!emit_simd_ldr_reg(output, simd_class, simd_rt, scratch)) {
                    cs_close(&handle);
                    return false;
                }
                if (stats) {
                    ++stats->ldr_simd;
                    ++stats->expanded;
                }
            }
            patched = true;
        } else if (insn.id == AARCH64_INS_PRFM &&
                   arm64.op_count >= 2 &&
                   arm64.operands[1].type == AARCH64_OP_IMM) {
            emit_u32(output, 0xd503201fU);
            if (stats) {
                ++stats->prfm;
            }
            patched = true;
        } else if ((insn.id == AARCH64_INS_B || insn.id == AARCH64_INS_BL) &&
                   arm64.op_count >= 1 &&
                   arm64.operands[0].type == AARCH64_OP_IMM) {
            const uint64_t old_target = (uint64_t)arm64.operands[0].imm;
            const uint64_t new_target = relocate_old_addr(old_target);
            const unsigned scratch = 16;
            emit_movz_movk_sequence(output, scratch, false, new_target);
            const uint32_t br_insn = (insn.id == AARCH64_INS_BL) ? 0xd63f0000U : 0xd61f0000U;
            emit_u32(output, br_insn | ((scratch & 0x1fU) << 5));
            if (stats) {
                if (insn.id == AARCH64_INS_BL) {
                    ++stats->bl;
                } else {
                    ++stats->br;
                }
                ++stats->expanded;
            }
            patched = true;
        }

        if (!patched) {
            const uint32_t raw =
                    (uint32_t)insn.bytes[0] |
                    ((uint32_t)insn.bytes[1] << 8) |
                    ((uint32_t)insn.bytes[2] << 16) |
                    ((uint32_t)insn.bytes[3] << 24);
            emit_u32(output, raw);
        }
    }

    if (size > 0) {
        const size_t off = input.size() - size;
        output->insert(output->end(), input.begin() + (size_t)off, input.end());
    }

    cs_close(&handle);
    return true;
}
#endif


} // namespace

bool zElf::buildLoadExpansionPlanForInjection(
        const zElf& donor_elf,
        const std::vector<int>& target_load_indices,
        const std::unordered_map<int, std::vector<int>>& donor_for_target_load,
        LoadExpansionResult* out_result) {
    if (!out_result) {
        return false;
    }

    out_result->load_states.clear();
    out_result->load_state_pos.clear();
    out_result->donor_base_deltas_for_target.clear();
    out_result->old_sections.clear();

    out_result->load_states.reserve(target_load_indices.size());

    const uint64_t runtime_page_size = infer_runtime_page_size_from_phdrs(ph_table_model_.elements);

    // 先为每个 target LOAD 计算扩容后的 filesz/memsz，并记录 donor 片段插入位置。
    for (int target_idx : target_load_indices) {
        const auto& target_ph = ph_table_model_.elements[(size_t)target_idx];
        LoadMergeState state;
        state.idx = target_idx;
        state.old_offset = target_ph.offset;
        state.old_vaddr = target_ph.vaddr;
        state.old_paddr = target_ph.paddr;
        state.old_filesz = target_ph.filesz;
        state.old_memsz = target_ph.memsz;

        const uint64_t target_align = target_ph.align == 0 ? 1 : (uint64_t)target_ph.align;
        uint64_t tail_cursor = state.old_filesz;
        uint64_t max_mem = state.old_memsz;
        std::vector<uint64_t> donor_base_deltas;
        auto donor_it = donor_for_target_load.find(target_idx);
        if (donor_it != donor_for_target_load.end()) {
            donor_base_deltas.reserve(donor_it->second.size());
            for (int donor_idx : donor_it->second) {
                const auto& donor_ph = donor_elf.programHeaderModel().elements[(size_t)donor_idx];
                const uint64_t donor_align = donor_ph.align == 0 ? 1 : (uint64_t)donor_ph.align;
                const uint64_t insert_align = std::max<uint64_t>(target_align, donor_align);
                const uint64_t aligned_abs = align_up_u64((uint64_t)state.old_offset + tail_cursor, insert_align);
                const uint64_t base_delta = aligned_abs - (uint64_t)state.old_offset;
                donor_base_deltas.push_back(base_delta);
                tail_cursor = base_delta + donor_ph.filesz;
                max_mem = std::max<uint64_t>(max_mem, base_delta + donor_ph.memsz);
            }
        }

        state.new_filesz = (Elf64_Xword)tail_cursor;
        state.new_memsz = (Elf64_Xword)std::max<uint64_t>(max_mem, state.new_filesz);
        if (!donor_base_deltas.empty()) {
            out_result->donor_base_deltas_for_target[target_idx] = std::move(donor_base_deltas);
        }

        out_result->load_state_pos[target_idx] = out_result->load_states.size();
        out_result->load_states.push_back(state);
    }

    uint64_t cumulative_shift = 0;
    // 计算各 target LOAD 的全局偏移平移量，生成旧地址到新地址的分段映射基础。
    for (size_t idx = 0; idx < out_result->load_states.size(); ++idx) {
        auto& state = out_result->load_states[idx];
        state.shift = (Elf64_Off)cumulative_shift;

        if (idx + 1 >= out_result->load_states.size()) {
            continue;
        }

        const auto& next_state = out_result->load_states[idx + 1];
        const uint64_t new_file_end = (uint64_t)state.old_offset + cumulative_shift + state.new_filesz;
        const uint64_t next_file_begin = (uint64_t)next_state.old_offset + cumulative_shift;
        const uint64_t new_vaddr_end = (uint64_t)state.old_vaddr + cumulative_shift + state.new_memsz;
        const uint64_t next_vaddr_begin = (uint64_t)next_state.old_vaddr + cumulative_shift;

        const uint64_t need_file_shift = new_file_end > next_file_begin ? new_file_end - next_file_begin : 0;
        const uint64_t need_vaddr_shift = new_vaddr_end > next_vaddr_begin ? new_vaddr_end - next_vaddr_begin : 0;
        const uint64_t need_shift = std::max<uint64_t>(need_file_shift, need_vaddr_shift);
        cumulative_shift += align_up_u64(need_shift, runtime_page_size);
    }

    out_result->old_ph = ph_table_model_.elements;

    out_result->old_sections.reserve(sh_table_model_.elements.size());
    for (const auto& section_ptr : sh_table_model_.elements) {
        OldSectionState state;
        state.offset = section_ptr->offset;
        state.addr = section_ptr->addr;
        state.type = section_ptr->type;
        state.flags = section_ptr->flags;
        out_result->old_sections.push_back(state);
    }

    return true;
}

bool zElf::expandSectionsForInjection(const LoadExpansionResult& expansion) {
    if (expansion.load_states.empty() || expansion.old_sections.size() != sh_table_model_.elements.size()) {
        return false;
    }

    auto shift_for_old_vaddr = [&expansion](Elf64_Addr value) -> Elf64_Off {
        if (value == 0) {
            return 0;
        }
        for (const auto& state : expansion.load_states) {
            const uint64_t begin = state.old_vaddr;
            const uint64_t end = begin + state.old_memsz;
            if ((uint64_t)value >= begin && (uint64_t)value < end) {
                return state.shift;
            }
        }
        return 0;
    };

    auto shift_for_old_offset = [&expansion](Elf64_Off value) -> Elf64_Off {
        if (value == 0) {
            return 0;
        }
        for (const auto& state : expansion.load_states) {
            const uint64_t begin = state.old_offset;
            const uint64_t end = begin + state.old_filesz;
            if ((uint64_t)value >= begin && (uint64_t)value < end) {
                return state.shift;
            }
        }
        return 0;
    };

    for (size_t idx = 0; idx < sh_table_model_.elements.size(); ++idx) {
        auto& section = *sh_table_model_.elements[idx];
        const auto& old_section = expansion.old_sections[idx];
        if (section.type == SHT_NULL || (old_section.flags & SHF_ALLOC) == 0) {
            continue;
        }

        Elf64_Off shift = shift_for_old_vaddr(old_section.addr);
        if (shift == 0 && old_section.type != SHT_NOBITS) {
            shift = shift_for_old_offset(old_section.offset);
        }
        if (shift == 0) {
            continue;
        }

        section.addr = (Elf64_Addr)((uint64_t)old_section.addr + shift);
        section.offset = (Elf64_Off)((uint64_t)old_section.offset + shift);
    }

    return true;
}

bool zElf::expandLoadSegmentsForInjection(const LoadExpansionResult& expansion) {
    if (expansion.load_states.empty() || expansion.old_ph.size() != ph_table_model_.elements.size()) {
        return false;
    }

    auto shift_for_old_vaddr = [&expansion](Elf64_Addr value) -> Elf64_Off {
        if (value == 0) {
            return 0;
        }
        for (const auto& state : expansion.load_states) {
            const uint64_t begin = state.old_vaddr;
            const uint64_t end = begin + state.old_memsz;
            if ((uint64_t)value >= begin && (uint64_t)value < end) {
                return state.shift;
            }
        }
        return 0;
    };

    auto shift_for_old_offset = [&expansion](Elf64_Off value) -> Elf64_Off {
        if (value == 0) {
            return 0;
        }
        for (const auto& state : expansion.load_states) {
            const uint64_t begin = state.old_offset;
            const uint64_t end = begin + state.old_filesz;
            if ((uint64_t)value >= begin && (uint64_t)value < end) {
                return state.shift;
            }
        }
        return 0;
    };

    for (const auto& state : expansion.load_states) {
        auto& ph = ph_table_model_.elements[(size_t)state.idx];
        ph.offset = (Elf64_Off)((uint64_t)state.old_offset + state.shift);
        ph.vaddr = (Elf64_Addr)((uint64_t)state.old_vaddr + state.shift);
        ph.paddr = (Elf64_Addr)((uint64_t)state.old_paddr + state.shift);
        ph.filesz = state.new_filesz;
        ph.memsz = state.new_memsz;
    }

    for (size_t idx = 0; idx < ph_table_model_.elements.size(); ++idx) {
        auto& ph = ph_table_model_.elements[idx];
        if (ph.type == PT_LOAD || ph.type == PT_PHDR) {
            continue;
        }

        const auto& old_item = expansion.old_ph[idx];
        Elf64_Off shift = shift_for_old_vaddr(old_item.vaddr);
        if (shift == 0) {
            shift = shift_for_old_offset(old_item.offset);
        }
        if (shift == 0) {
            continue;
        }
        ph.offset = (Elf64_Off)((uint64_t)old_item.offset + shift);
        ph.vaddr = (Elf64_Addr)((uint64_t)old_item.vaddr + shift);
        ph.paddr = (Elf64_Addr)((uint64_t)old_item.paddr + shift);
    }

    const Elf64_Off entry_shift = shift_for_old_vaddr(header_model_.raw.e_entry);
    if (entry_shift != 0) {
        header_model_.raw.e_entry = (Elf64_Addr)((uint64_t)header_model_.raw.e_entry + entry_shift);
    }

    return true;
}

bool zElf::appendLoadDataAndMirrorSections(
        const zElf& donor_elf,
        const std::vector<std::pair<int, int>>& donor_target_pairs,
        const LoadExpansionResult& expansion,
        std::vector<SegmentRelocation>* segment_relocations,
        std::unordered_map<uint16_t, uint16_t>* donor_section_index_remap,
        int* mirrored_text_target_idx,
        size_t* mirrored_text_blob_idx,
        size_t* mirrored_text_blob_off,
        size_t* mirrored_text_size) {
    if (!segment_relocations || !donor_section_index_remap || !mirrored_text_target_idx ||
        !mirrored_text_blob_idx || !mirrored_text_blob_off || !mirrored_text_size) {
        return false;
    }

    segment_relocations->clear();
    donor_section_index_remap->clear();
    *mirrored_text_target_idx = -1;
    *mirrored_text_blob_idx = (size_t)-1;
    *mirrored_text_blob_off = 0;
    *mirrored_text_size = 0;

    // donor_placement_cursor 记录同一 target LOAD 下多段 donor 的放置顺序。
    std::unordered_map<int, size_t> donor_placement_cursor;
    // 将 donor LOAD 数据块注入到对应 target LOAD 末尾，同时记录重定位映射信息。
    for (const auto& pair : donor_target_pairs) {
        const int donor_idx = pair.first;
        const int target_idx = pair.second;
        const auto& donor_ph = donor_elf.programHeaderModel().elements[(size_t)donor_idx];
        const auto state_it = expansion.load_state_pos.find(target_idx);
        if (state_it == expansion.load_state_pos.end() || state_it->second >= expansion.load_states.size()) {
            LOGE("Missing load state for target PT_LOAD[%d]", target_idx);
            return false;
        }
        const auto& state = expansion.load_states[state_it->second];

        const auto placement_it = expansion.donor_base_deltas_for_target.find(target_idx);
        if (placement_it == expansion.donor_base_deltas_for_target.end()) {
            LOGE("Missing donor placement map for target PT_LOAD[%d]", target_idx);
            return false;
        }
        // base_delta 是 donor 在该 target LOAD 中的相对插入偏移（按顺序多段累加）。
        const size_t cursor = donor_placement_cursor[target_idx];
        if (cursor >= placement_it->second.size()) {
            LOGE("Donor placement cursor out of range for target PT_LOAD[%d]", target_idx);
            return false;
        }
        const uint64_t base_delta = placement_it->second[cursor];
        donor_placement_cursor[target_idx] = cursor + 1;

        const Elf64_Off new_off = (Elf64_Off)((uint64_t)state.old_offset + state.shift + base_delta);
        const Elf64_Addr new_va = (Elf64_Addr)((uint64_t)state.old_vaddr + state.shift + base_delta);

        // PendingBlob 保存本次注入的数据块与其新地址/偏移，后续统一修补。
        PendingBlob blob;
        blob.offset = new_off;
        blob.vaddr = new_va;
        blob.executable = (state.old_memsz > 0) && ((ph_table_model_.elements[(size_t)target_idx].flags & PF_X) != 0);
        blob.bytes.resize((size_t)donor_ph.filesz);
        std::memcpy(blob.bytes.data(),
                    donor_elf.file_image_.data() + donor_ph.offset,
                    (size_t)donor_ph.filesz);
        pending_blobs_.push_back(std::move(blob));

        // 记录 donor -> target 的地址映射区间，供符号/重定位/指令修补使用。
        SegmentRelocation relocation;
        relocation.donor_offset = donor_ph.offset;
        relocation.donor_filesz = donor_ph.filesz;
        relocation.new_offset = new_off;
        relocation.donor_vaddr = donor_ph.vaddr;
        relocation.donor_memsz = donor_ph.memsz;
        relocation.new_vaddr = new_va;
        segment_relocations->push_back(relocation);
        LOGI("donor PT_LOAD relocation: donor_vaddr=0x%llx donor_memsz=0x%llx -> new_vaddr=0x%llx",
             (unsigned long long)relocation.donor_vaddr,
             (unsigned long long)relocation.donor_memsz,
             (unsigned long long)relocation.new_vaddr);
    }

    LOGI("Merged donor PT_LOAD into matching target PT_LOAD, phnum=%zu",
         ph_table_model_.elements.size());

    // 当 donor/target 存在同名数据符号且布局一致时，建立地址别名范围用于重定位修补。
    struct SymbolAliasRange {
        Elf64_Addr donor_begin = 0;
        Elf64_Xword donor_size = 0;
        Elf64_Addr target_begin = 0;
    };
    std::vector<SymbolAliasRange> donor_symbol_alias_ranges;
    {
        const int alias_donor_symtab_idx = donor_elf.sectionHeaderModel().findByName(".symtab");
        const int alias_donor_strtab_idx = donor_elf.sectionHeaderModel().findByName(".strtab");
        const int alias_target_symtab_idx = sh_table_model_.findByName(".symtab");
        const int alias_target_strtab_idx = sh_table_model_.findByName(".strtab");

        if (alias_donor_symtab_idx >= 0 && alias_donor_strtab_idx >= 0 &&
            alias_target_symtab_idx >= 0 && alias_target_strtab_idx >= 0) {
            const auto* alias_donor_symtab = dynamic_cast<const zSymbolSection*>(donor_elf.sectionHeaderModel().get((size_t)alias_donor_symtab_idx));
            const auto* alias_donor_strtab = dynamic_cast<const zStrTabSection*>(donor_elf.sectionHeaderModel().get((size_t)alias_donor_strtab_idx));
            const auto* alias_target_symtab = dynamic_cast<const zSymbolSection*>(sh_table_model_.get((size_t)alias_target_symtab_idx));
            const auto* alias_target_strtab = dynamic_cast<const zStrTabSection*>(sh_table_model_.get((size_t)alias_target_strtab_idx));

            if (alias_donor_symtab && alias_donor_strtab && alias_target_symtab && alias_target_strtab) {
                auto find_target_symbol_by_name = [](const zSymbolSection* symtab,
                                                     const zStrTabSection* strtab,
                                                     const char* name) -> int {
                    if (!symtab || !strtab || !name) {
                        return -1;
                    }
                    for (size_t idx = 1; idx < symtab->symbols.size(); ++idx) {
                        const auto& sym = symtab->symbols[idx];
                        const char* sym_name = strtab->getStringAt(sym.st_name);
                        if (!sym_name) {
                            continue;
                        }
                        if (std::strcmp(sym_name, name) == 0) {
                            return (int)idx;
                        }
                    }
                    return -1;
                };

                // 仅挑选可安全等价的“数据符号”区间，避免函数/文件/节符号引入错误映射。
                for (size_t idx = 1; idx < alias_donor_symtab->symbols.size(); ++idx) {
                    const auto& donor_sym = alias_donor_symtab->symbols[idx];
                    if (donor_sym.st_name == 0 || donor_sym.st_value == 0 || is_special_shndx(donor_sym.st_shndx)) {
                        continue;
                    }

                    const unsigned donor_bind = ELF64_ST_BIND(donor_sym.st_info);
                    if (donor_bind == STB_LOCAL) {
                        continue;
                    }

                    const unsigned donor_type = ELF64_ST_TYPE(donor_sym.st_info);
                    if (donor_type == STT_FUNC || donor_type == STT_SECTION || donor_type == STT_FILE) {
                        continue;
                    }

                    const char* donor_name = alias_donor_strtab->getStringAt(donor_sym.st_name);
                    if (!donor_name || donor_name[0] == '\0') {
                        continue;
                    }

                    const int target_idx = find_target_symbol_by_name(alias_target_symtab, alias_target_strtab, donor_name);
                    if (target_idx < 0) {
                        continue;
                    }

                    const auto& target_sym = alias_target_symtab->symbols[(size_t)target_idx];
                    if (target_sym.st_value == 0 || is_special_shndx(target_sym.st_shndx)) {
                        continue;
                    }

                    if (donor_sym.st_size == 0 || target_sym.st_size == 0) {
                        continue;
                    }

                    if (donor_sym.st_size != target_sym.st_size) {
                        continue;
                    }

                    if (donor_sym.st_shndx >= donor_elf.sectionHeaderModel().elements.size() ||
                        target_sym.st_shndx >= sh_table_model_.elements.size()) {
                        continue;
                    }

                    const auto* donor_sym_sec = donor_elf.sectionHeaderModel().elements[(size_t)donor_sym.st_shndx].get();
                    const auto* target_sym_sec = sh_table_model_.elements[(size_t)target_sym.st_shndx].get();
                    if (!donor_sym_sec || !target_sym_sec) {
                        continue;
                    }

                    if (((donor_sym_sec->flags ^ target_sym_sec->flags) & (SHF_WRITE | SHF_ALLOC)) != 0) {
                        continue;
                    }

                    const bool donor_in_section = contains_addr_range_u64(donor_sym_sec->addr,
                                                                           donor_sym_sec->size,
                                                                           donor_sym.st_value,
                                                                           donor_sym.st_size);
                    const bool target_in_section = contains_addr_range_u64(target_sym_sec->addr,
                                                                            target_sym_sec->size,
                                                                            target_sym.st_value,
                                                                            target_sym.st_size);
                    if (!donor_in_section || !target_in_section) {
                        continue;
                    }

                    const unsigned target_bind = ELF64_ST_BIND(target_sym.st_info);
                    if (target_bind == STB_LOCAL) {
                        continue;
                    }

                    const unsigned target_type = ELF64_ST_TYPE(target_sym.st_info);
                    if (target_type == STT_FUNC || target_type == STT_SECTION || target_type == STT_FILE) {
                        continue;
                    }

                    SymbolAliasRange alias;
                    alias.donor_begin = donor_sym.st_value;
                    alias.donor_size = donor_sym.st_size == 0 ? 1 : donor_sym.st_size;
                    alias.target_begin = target_sym.st_value;
                    donor_symbol_alias_ranges.push_back(alias);
                }

                if (!donor_symbol_alias_ranges.empty()) {
                    LOGI("Built donor->target data symbol alias ranges: %zu", donor_symbol_alias_ranges.size());
                }
            }
        }
    }

    // 将 donor 虚拟地址映射到 target 中的新位置（优先符号别名，其次段迁移区间）。
    auto relocate_donor_vaddr = [&segment_relocations, &donor_symbol_alias_ranges](Elf64_Addr original) -> Elf64_Addr {
        for (const auto& alias : donor_symbol_alias_ranges) {
            const uint64_t begin = alias.donor_begin;
            const uint64_t end = begin + alias.donor_size;
            if ((uint64_t)original >= begin && (uint64_t)original < end) {
                return (Elf64_Addr)(alias.target_begin + ((uint64_t)original - begin));
            }
        }

        for (const auto& relocation : *segment_relocations) {
            if (relocation.donor_memsz == 0) {
                continue;
            }
            const uint64_t begin = relocation.donor_vaddr;
            const uint64_t end = begin + relocation.donor_memsz;
            if ((uint64_t)original >= begin && (uint64_t)original < end) {
                return (Elf64_Addr)(relocation.new_vaddr + ((uint64_t)original - begin));
            }
        }
        return original;
    };

    // 将 donor 文件偏移映射到 target 的新偏移，仅依赖段迁移区间。
    auto relocate_donor_offset = [&segment_relocations](Elf64_Off original) -> Elf64_Off {
        for (const auto& relocation : *segment_relocations) {
            if (relocation.donor_filesz == 0) {
                continue;
            }
            const uint64_t begin = relocation.donor_offset;
            const uint64_t end = begin + relocation.donor_filesz;
            if ((uint64_t)original >= begin && (uint64_t)original < end) {
                return (Elf64_Off)(relocation.new_offset + ((uint64_t)original - begin));
            }
        }
        return original;
    };

    // 根据 blob 新地址反推出该段的平移量（new_vaddr - donor_vaddr）。
    auto find_blob_segment_delta = [&segment_relocations](const PendingBlob& blob, int64_t* out_delta) -> bool {
        if (!out_delta) {
            return false;
        }
        for (const auto& relocation : *segment_relocations) {
            if (relocation.donor_memsz == 0) {
                continue;
            }
            const uint64_t begin = relocation.new_vaddr;
            const uint64_t end = begin + relocation.donor_memsz;
            if ((uint64_t)blob.vaddr >= begin && (uint64_t)blob.vaddr < end) {
                *out_delta = (int64_t)relocation.new_vaddr - (int64_t)relocation.donor_vaddr;
                return true;
            }
        }
        return false;
    };

    {
        PatchStats patched_stats{};
        for (auto& blob : pending_blobs_) {
            if (!blob.executable || blob.bytes.empty()) {
                continue;
            }

            int64_t seg_delta = 0;
            if (!find_blob_segment_delta(blob, &seg_delta)) {
                continue;
            }

            const uint64_t old_pc_base = (uint64_t)((int64_t)blob.vaddr - seg_delta);
            std::vector<uint8_t> patched_blob;

            // 对注入代码进行 ADRP/ADR/LDR literal/BL/B 修补，扩容为 PC 无关序列。
            if (!patch_aarch64_pc_relative_payload(
                    blob.bytes,
                    old_pc_base,
                    [&relocate_donor_vaddr](uint64_t old_addr) -> uint64_t {
                        return (uint64_t)relocate_donor_vaddr((Elf64_Addr)old_addr);
                    },
                    &patched_blob,
                    &patched_stats,
                    "injected-blob")) {
                return false;
            }

            blob.bytes.swap(patched_blob);
        }

        if (patched_stats.adrp > 0 || patched_stats.adr > 0 || patched_stats.ldr_literal > 0 ||
            patched_stats.ldr_simd > 0 || patched_stats.prfm > 0 || patched_stats.br > 0 ||
            patched_stats.bl > 0 || patched_stats.cond_br > 0) {
            LOGI("Patched injected blob PC-relative instructions: ADRP=%zu ADR=%zu LDR=%zu LDRSIMD=%zu PRFM=%zu B=%zu BL=%zu CBR=%zu EXPAND=%zu",
                 patched_stats.adrp,
                 patched_stats.adr,
                 patched_stats.ldr_literal,
                 patched_stats.ldr_simd,
                 patched_stats.prfm,
                 patched_stats.br,
                 patched_stats.bl,
                 patched_stats.cond_br,
                 patched_stats.expanded);
        }
    }

    {
        const int donor_text_idx = donor_elf.sectionHeaderModel().findByName(".text");
        const auto* donor_text = donor_text_idx >= 0 ? donor_elf.sectionHeaderModel().get((size_t)donor_text_idx) : nullptr;
        if (donor_text && donor_text->type != SHT_NOBITS && !donor_text->payload.empty() &&
            (donor_text->flags & SHF_ALLOC) != 0) {
            auto injected_text = std::make_unique<zSectionTableElement>();
            injected_text->type = donor_text->type;
            injected_text->flags = donor_text->flags;
            injected_text->addr = relocate_donor_vaddr(donor_text->addr);
            injected_text->offset = relocate_donor_offset(donor_text->offset);
            injected_text->addralign = donor_text->addralign == 0 ? 1 : donor_text->addralign;
            injected_text->entsize = donor_text->entsize;
            injected_text->resolved_name = ".text.vmp";

            if (header_model_.raw.e_shstrndx < sh_table_model_.elements.size()) {
                auto* shstrtab = dynamic_cast<zStrTabSection*>(sh_table_model_.get(header_model_.raw.e_shstrndx));
                if (shstrtab) {
                    injected_text->name = shstrtab->addString(injected_text->resolved_name);
                }
            }

            bool copied_from_blob = false;
            const uint64_t sec_off_begin = injected_text->offset;
            const uint64_t sec_off_end = sec_off_begin + donor_text->payload.size();
            for (size_t blob_idx = 0; blob_idx < pending_blobs_.size(); ++blob_idx) {
                const auto& blob = pending_blobs_[blob_idx];
                const uint64_t blob_begin = blob.offset;
                const uint64_t blob_end = blob_begin + blob.bytes.size();
                if (sec_off_begin >= blob_begin && sec_off_end <= blob_end) {
                    const size_t local_off = (size_t)(sec_off_begin - blob_begin);
                    injected_text->payload.assign(blob.bytes.begin() + (ptrdiff_t)local_off,
                                                  blob.bytes.begin() + (ptrdiff_t)local_off + (ptrdiff_t)donor_text->payload.size());
                    copied_from_blob = true;
                    *mirrored_text_blob_idx = blob_idx;
                    *mirrored_text_blob_off = local_off;
                    *mirrored_text_size = donor_text->payload.size();
                    break;
                }
            }
            if (!copied_from_blob) {
                injected_text->payload = donor_text->payload;
            }
            injected_text->syncHeader();

            const uint16_t mapped_index = (uint16_t)sh_table_model_.elements.size();
            sh_table_model_.elements.push_back(std::move(injected_text));
            (*donor_section_index_remap)[(uint16_t)donor_text_idx] = mapped_index;
            *mirrored_text_target_idx = (int)mapped_index;
            LOGI("Added donor .text mirror section for symbol mapping: donor=%u target=%u",
                 (uint16_t)donor_text_idx,
                 mapped_index);
        }
    }

    return true;
}


bool zElf::injectImpl(const char* donor_path, const char* output_path) {

    using PendingBlob = zElf::PendingBlob;

    // 注入主流程概览：
    // 1) 解析 donor/target 并建立 LOAD 段配对关系；
    // 2) 扩容 target LOAD 段，记录旧->新地址映射；
    // 3) 搬运 donor 代码/数据并修补 PC 相对指令；
    // 4) 合并关键 section（如符号/字符串/重定位相关）；
    // 5) 统一重构、地址重写、二次重构并做完整校验。

    if (!donor_path || !output_path) {
        LOGE("Invalid path arguments");
        return false;
    }

    zElf donor_elf(donor_path);
    if (!donor_elf.isLoaded() || donor_elf.programHeaderModel().elements.empty()) {
        LOGE("Failed to parse donor ELF: %s", donor_path);
        return false;
    }

    // 收集 donor 中可注入的 PT_LOAD 段（filesz>0 表示段内有实际数据）。
    std::vector<int> donor_load_indices;
    for (size_t idx = 0; idx < donor_elf.programHeaderModel().elements.size(); ++idx) {
        const auto& ph = donor_elf.programHeaderModel().elements[idx];
        if (ph.type != PT_LOAD || ph.filesz == 0) {
            continue;
        }
        const uint64_t pht_size =
                (uint64_t)donor_elf.headerModel().raw.e_phnum * (uint64_t)sizeof(Elf64_Phdr);
        if (ph.offset == donor_elf.headerModel().raw.e_phoff &&
            ph.filesz == pht_size) {
            continue;
        }
        donor_load_indices.push_back((int)idx);
    }
    if (donor_load_indices.empty()) {
        LOGE("No donor PT_LOAD segments found");
        return false;
    }

    std::sort(donor_load_indices.begin(), donor_load_indices.end(),
              [&donor_elf](int a, int b) {
                  return donor_elf.programHeaderModel().elements[(size_t)a].offset <
                         donor_elf.programHeaderModel().elements[(size_t)b].offset;
              });

    // 收集 target 中可承载注入的 PT_LOAD 段。
    std::vector<int> target_load_indices;
    for (size_t idx = 0; idx < ph_table_model_.elements.size(); ++idx) {
        if (ph_table_model_.elements[idx].type == PT_LOAD) {
            target_load_indices.push_back((int)idx);
        }
    }
    if (target_load_indices.empty()) {
        LOGE("No target PT_LOAD segment found");
        return false;
    }
    std::sort(target_load_indices.begin(), target_load_indices.end(),
              [this](int a, int b) {
                  return ph_table_model_.elements[(size_t)a].offset < ph_table_model_.elements[(size_t)b].offset;
              });

    // used_target_load_indices 用于避免多个 donor 竞争同一个 target LOAD。
    std::unordered_set<int> used_target_load_indices;
    // donor_for_target_load 记录每个 target LOAD 对应的 donor LOAD 列表。
    std::unordered_map<int, std::vector<int>> donor_for_target_load;
    std::vector<std::pair<int, int>> donor_target_pairs;
    donor_target_pairs.reserve(donor_load_indices.size());

    auto sanitize_flags = [](Elf64_Word flags) -> Elf64_Word {
        return flags & (PF_R | PF_W | PF_X);
    };

    auto score_load_match = [&sanitize_flags](const zProgramTableElement& donor,
                                              const zProgramTableElement& target) -> int64_t {
        const Elf64_Word donor_flags = sanitize_flags(donor.flags);
        const Elf64_Word target_flags = sanitize_flags(target.flags);
        if (donor_flags != target_flags) {
            return std::numeric_limits<int64_t>::min();
        }

        int64_t score = 0;

        const bool donor_exec = (donor_flags & PF_X) != 0;
        const bool target_exec = (target_flags & PF_X) != 0;
        if (donor_exec == target_exec) {
            score += 5000;
        }

        const bool donor_write = (donor_flags & PF_W) != 0;
        const bool target_write = (target_flags & PF_W) != 0;
        if (donor_write == target_write) {
            score += 3000;
        }

        const uint64_t donor_align = donor.align == 0 ? 1 : donor.align;
        const uint64_t target_align = target.align == 0 ? 1 : target.align;
        const uint64_t align_diff = donor_align > target_align ? donor_align - target_align : target_align - donor_align;
        score -= (int64_t)std::min<uint64_t>(align_diff, 0x100000ULL);

        const uint64_t donor_size = std::max<uint64_t>((uint64_t)donor.filesz, (uint64_t)donor.memsz);
        const uint64_t target_size = std::max<uint64_t>((uint64_t)target.filesz, (uint64_t)target.memsz);
        const uint64_t size_diff = donor_size > target_size ? donor_size - target_size : target_size - donor_size;
        score -= (int64_t)std::min<uint64_t>(size_diff, 0x100000ULL);

        return score;
    };

    for (int donor_idx : donor_load_indices) {
        // 为每个 donor LOAD 选择“最匹配”的 target LOAD（权限/大小/对齐综合评分）。
        const auto& donor_ph = donor_elf.programHeaderModel().elements[(size_t)donor_idx];
        if ((uint64_t)donor_ph.offset + donor_ph.filesz > donor_elf.file_image_.size()) {
            LOGE("Donor PT_LOAD[%d] out of donor file range", donor_idx);
            return false;
        }

        int target_idx = -1;
        int64_t best_score = std::numeric_limits<int64_t>::min();
        for (int candidate_idx : target_load_indices) {
            if (used_target_load_indices.find(candidate_idx) != used_target_load_indices.end()) {
                continue;
            }
            const auto& candidate = ph_table_model_.elements[(size_t)candidate_idx];
            const int64_t score = score_load_match(donor_ph, candidate);
            if (score > best_score) {
                best_score = score;
                target_idx = candidate_idx;
            }
        }
        if (target_idx < 0 || best_score == std::numeric_limits<int64_t>::min()) {
            LOGE("No compatible target PT_LOAD for donor PT_LOAD[%d] flags=0x%x",
                 donor_idx,
                 donor_ph.flags & (PF_R | PF_W | PF_X));
            return false;
        }
        used_target_load_indices.insert(target_idx);
        donor_for_target_load[target_idx].push_back(donor_idx);
        donor_target_pairs.emplace_back(donor_idx, target_idx);
    }

    std::vector<SegmentRelocation> segment_relocations;
    std::unordered_map<uint16_t, uint16_t> donor_section_index_remap;
    std::unordered_map<Elf64_Addr, Elf64_Addr> donor_to_target_plt_entry;
    int mirrored_text_target_idx = -1;
    size_t mirrored_text_blob_idx = (size_t)-1;
    size_t mirrored_text_blob_off = 0;
    size_t mirrored_text_size = 0;
    // expansion 保存扩容后的段状态与旧->新位移映射。
    LoadExpansionResult expansion;
    // 先计算扩容计划，再按顺序应用：先 Section，后 LOAD。
    if (!buildLoadExpansionPlanForInjection(donor_elf, target_load_indices, donor_for_target_load, &expansion)) {
        return false;
    }
    if (!expandSectionsForInjection(expansion)) {
        return false;
    }
    if (!expandLoadSegmentsForInjection(expansion)) {
        return false;
    }

    // 根据旧地址查询段级位移，方便统一迁移地址/偏移。
    auto shift_for_old_vaddr = [&expansion](Elf64_Addr value) -> Elf64_Off {
        if (value == 0) {
            return 0;
        }
        for (const auto& state : expansion.load_states) {
            const uint64_t begin = state.old_vaddr;
            const uint64_t end = begin + state.old_memsz;
            if ((uint64_t)value >= begin && (uint64_t)value < end) {
                return state.shift;
            }
        }
        return 0;
    };

    // 偏移迁移用于文件内 section（非 NOBITS）定位更精确。
    auto shift_for_old_offset = [&expansion](Elf64_Off value) -> Elf64_Off {
        if (value == 0) {
            return 0;
        }
        for (const auto& state : expansion.load_states) {
            const uint64_t begin = state.old_offset;
            const uint64_t end = begin + state.old_filesz;
            if ((uint64_t)value >= begin && (uint64_t)value < end) {
                return state.shift;
            }
        }
        return 0;
    };

    // 将旧虚拟地址重定位到新虚拟地址。
    auto relocate_old_vaddr = [&shift_for_old_vaddr](Elf64_Addr old_vaddr) -> Elf64_Addr {
        const Elf64_Off shift = shift_for_old_vaddr(old_vaddr);
        if (shift == 0) {
            return old_vaddr;
        }
        return (Elf64_Addr)((uint64_t)old_vaddr + shift);
    };

    const auto& old_sections = expansion.old_sections;

    {
        // 修补 target 原有可执行 section 中的 PC-relative 指令，扩容为 PC 无关序列。
        PatchStats patched_stats{};
        for (size_t idx = 0; idx < sh_table_model_.elements.size(); ++idx) {
            auto& section = *sh_table_model_.elements[idx];
            if ((section.flags & SHF_EXECINSTR) == 0) {
                continue;
            }
            if (section.payload.empty() && section.type != SHT_NOBITS && section.size > 0) {
                const uint64_t end = (uint64_t)section.offset + (uint64_t)section.size;
                if (section.offset > 0 && end <= file_image_.size()) {
                    section.payload.assign(file_image_.begin() + (size_t)section.offset,
                                           file_image_.begin() + (size_t)end);
                }
            }
            if (section.payload.empty()) {
                continue;
            }

            Elf64_Addr old_section_addr = section.addr;
            if (idx < old_sections.size()) {
                const auto& old_section = old_sections[idx];
                old_section_addr = old_section.addr;
            }

            const uint64_t old_pc_base = (uint64_t)old_section_addr;
            std::vector<uint8_t> patched_payload;

            if (!patch_aarch64_pc_relative_payload(
                    section.payload,
                    old_pc_base,
                    [&relocate_old_vaddr](uint64_t old_addr) -> uint64_t {
                        return (uint64_t)relocate_old_vaddr((Elf64_Addr)old_addr);
                    },
                    &patched_payload,
                    &patched_stats,
                    section.resolved_name.c_str())) {
                return false;
            }
            if (!patched_payload.empty()) {
                section.payload.swap(patched_payload);
            }
            section.syncHeader();
        }

        if (patched_stats.adrp > 0 || patched_stats.adr > 0 || patched_stats.ldr_literal > 0 ||
            patched_stats.ldr_simd > 0 || patched_stats.prfm > 0 || patched_stats.br > 0 ||
            patched_stats.bl > 0 || patched_stats.cond_br > 0) {
            LOGI("Patched executable PC-relative instructions: ADRP=%zu ADR=%zu LDR=%zu LDRSIMD=%zu PRFM=%zu B=%zu BL=%zu CBR=%zu EXPAND=%zu",
                 patched_stats.adrp,
                 patched_stats.adr,
                 patched_stats.ldr_literal,
                 patched_stats.ldr_simd,
                 patched_stats.prfm,
                 patched_stats.br,
                 patched_stats.bl,
                 patched_stats.cond_br,
                 patched_stats.expanded);
        }
    }

    {
        // 修补 target .plt 中的 AArch64 入口序列，保证段扩容后跳转仍指向正确 GOT/PLT。
        const int plt_idx = sh_table_model_.findByName(".plt");
        if (plt_idx >= 0) {
            auto* plt_section = sh_table_model_.get((size_t)plt_idx);
            if (plt_section && !plt_section->payload.empty()) {
                auto read_u32_le = [](const std::vector<uint8_t>& bytes, size_t off, uint32_t* out) -> bool {
                    if (!out || off + 4 > bytes.size()) {
                        return false;
                    }
                    *out = (uint32_t)bytes[off] |
                           ((uint32_t)bytes[off + 1] << 8) |
                           ((uint32_t)bytes[off + 2] << 16) |
                           ((uint32_t)bytes[off + 3] << 24);
                    return true;
                };

                auto write_u32_le = [](std::vector<uint8_t>* bytes, size_t off, uint32_t value) -> bool {
                    if (!bytes || off + 4 > bytes->size()) {
                        return false;
                    }
                    (*bytes)[off] = (uint8_t)(value & 0xff);
                    (*bytes)[off + 1] = (uint8_t)((value >> 8) & 0xff);
                    (*bytes)[off + 2] = (uint8_t)((value >> 16) & 0xff);
                    (*bytes)[off + 3] = (uint8_t)((value >> 24) & 0xff);
                    return true;
                };

                auto is_adrp_x16 = [](uint32_t insn) -> bool {
                    return (insn & 0x9f00001fU) == 0x90000010U;
                };

                auto decode_adrp_target_page = [](uint32_t insn, uint64_t pc) -> uint64_t {
                    const uint32_t immlo = (insn >> 29) & 0x3U;
                    const uint32_t immhi = (insn >> 5) & 0x7ffffU;
                    int64_t imm21 = (int64_t)((immhi << 2) | immlo);
                    if ((imm21 & (1LL << 20)) != 0) {
                        imm21 |= ~((1LL << 21) - 1);
                    }
                    const int64_t delta = imm21 << 12;
                    const uint64_t page = pc & ~0xfffULL;
                    return (uint64_t)((int64_t)page + delta);
                };

                auto encode_adrp_x16 = [](uint64_t pc, uint64_t target_page, uint32_t* out) -> bool {
                    if (!out || (target_page & 0xfffULL) != 0) {
                        return false;
                    }
                    const int64_t pc_page = (int64_t)(pc & ~0xfffULL);
                    const int64_t delta = (int64_t)target_page - pc_page;
                    if ((delta & 0xfffLL) != 0) {
                        return false;
                    }
                    const int64_t imm21 = delta >> 12;
                    if (imm21 < -(1LL << 20) || imm21 > ((1LL << 20) - 1)) {
                        return false;
                    }
                    const uint32_t imm = (uint32_t)(imm21 & 0x1fffffU);
                    const uint32_t immlo = imm & 0x3U;
                    const uint32_t immhi = imm >> 2;
                    *out = 0x90000010U | (immlo << 29) | (immhi << 5);
                    return true;
                };

                auto is_ldr_x17_from_x16 = [](uint32_t insn) -> bool {
                    return (insn & 0xffc003ffU) == 0xf9400211U;
                };

                auto decode_ldr_uimm = [](uint32_t insn) -> uint64_t {
                    return (uint64_t)(((insn >> 10) & 0xfffU) << 3);
                };

                auto encode_ldr_x17_from_x16 = [](uint64_t imm, uint32_t* out) -> bool {
                    if (!out || (imm & 0x7ULL) != 0) {
                        return false;
                    }
                    const uint64_t imm12 = imm >> 3;
                    if (imm12 > 0xfffULL) {
                        return false;
                    }
                    *out = 0xf9400211U | (uint32_t)(imm12 << 10);
                    return true;
                };

                auto is_add_x16_x16_imm = [](uint32_t insn) -> bool {
                    return (insn & 0xffc003ffU) == 0x91000210U;
                };

                auto decode_add_imm = [](uint32_t insn) -> uint64_t {
                    const uint64_t imm12 = (insn >> 10) & 0xfffU;
                    const uint64_t shift = ((insn >> 22) & 0x1U) ? 12ULL : 0ULL;
                    return imm12 << shift;
                };

                auto encode_add_x16_x16_imm = [](uint64_t imm, uint32_t* out) -> bool {
                    if (!out) {
                        return false;
                    }
                    if (imm <= 0xfffULL) {
                        *out = 0x91000210U | (uint32_t)(imm << 10);
                        return true;
                    }
                    if ((imm & 0xfffULL) == 0) {
                        const uint64_t imm12 = imm >> 12;
                        if (imm12 <= 0xfffULL) {
                            *out = 0x91400210U | (uint32_t)(imm12 << 10);
                            return true;
                        }
                    }
                    return false;
                };

                const size_t insn_count = plt_section->payload.size() / 4;
                size_t patched_groups = 0;

                for (size_t insn_idx = 0; insn_idx < insn_count; ++insn_idx) {
                    uint32_t adrp_insn = 0;
                    if (!read_u32_le(plt_section->payload, insn_idx * 4, &adrp_insn) ||
                        !is_adrp_x16(adrp_insn)) {
                        continue;
                    }

                    const uint64_t pc = (uint64_t)plt_section->addr + (uint64_t)insn_idx * 4ULL;
                    const uint64_t old_page = decode_adrp_target_page(adrp_insn, pc);
                    bool need_patch_adrp = false;
                    uint64_t new_page = old_page;

                    if (insn_idx + 1 < insn_count) {
                        uint32_t ldr_insn = 0;
                        if (read_u32_le(plt_section->payload, (insn_idx + 1) * 4, &ldr_insn) &&
                            is_ldr_x17_from_x16(ldr_insn)) {
                            const uint64_t old_abs = old_page + decode_ldr_uimm(ldr_insn);
                            const uint64_t new_abs = (uint64_t)relocate_old_vaddr((Elf64_Addr)old_abs);
                            if (new_abs != old_abs) {
                                uint32_t new_ldr = 0;
                                if (!encode_ldr_x17_from_x16(new_abs & 0xfffULL, &new_ldr) ||
                                    !write_u32_le(&plt_section->payload, (insn_idx + 1) * 4, new_ldr)) {
                                    LOGE("Failed to patch .plt LDR at insn=%zu", insn_idx + 1);
                                    return false;
                                }
                                new_page = new_abs & ~0xfffULL;
                                need_patch_adrp = true;
                            }
                        }
                    }

                    if (insn_idx + 2 < insn_count) {
                        uint32_t add_insn = 0;
                        if (read_u32_le(plt_section->payload, (insn_idx + 2) * 4, &add_insn) &&
                            is_add_x16_x16_imm(add_insn)) {
                            const uint64_t old_abs = old_page + decode_add_imm(add_insn);
                            const uint64_t new_abs = (uint64_t)relocate_old_vaddr((Elf64_Addr)old_abs);
                            if (new_abs != old_abs) {
                                uint32_t new_add = 0;
                                if (!encode_add_x16_x16_imm(new_abs & 0xfffULL, &new_add) ||
                                    !write_u32_le(&plt_section->payload, (insn_idx + 2) * 4, new_add)) {
                                    LOGE("Failed to patch .plt ADD at insn=%zu", insn_idx + 2);
                                    return false;
                                }
                                const uint64_t page_from_add = new_abs & ~0xfffULL;
                                if (need_patch_adrp && new_page != page_from_add) {
                                    LOGE("Conflicted ADRP page while patching .plt at insn=%zu", insn_idx);
                                    return false;
                                }
                                new_page = page_from_add;
                                need_patch_adrp = true;
                            }
                        }
                    }

                    if (need_patch_adrp) {
                        uint32_t new_adrp = 0;
                        if (!encode_adrp_x16(pc, new_page, &new_adrp) ||
                            !write_u32_le(&plt_section->payload, insn_idx * 4, new_adrp)) {
                            LOGE("Failed to patch .plt ADRP at insn=%zu", insn_idx);
                            return false;
                        }
                        ++patched_groups;
                    }
                }

                if (patched_groups > 0) {
                    plt_section->syncHeader();
                    LOGI("Patched .plt addressing groups: %zu", patched_groups);
                }
            }
        }
    }

    for (auto& section_ptr : sh_table_model_.elements) {
        auto* symbol_section = dynamic_cast<zSymbolSection*>(section_ptr.get());
        if (!symbol_section) {
            continue;
        }
        bool changed = false;
        for (auto& symbol : symbol_section->symbols) {
            if (symbol.st_value == 0 || is_special_shndx(symbol.st_shndx)) {
                continue;
            }
            Elf64_Addr relocated = relocate_old_vaddr(symbol.st_value);
            if (relocated != symbol.st_value) {
                symbol.st_value = relocated;
                changed = true;
            }
        }
        if (changed) {
            symbol_section->syncHeader();
        }
    }

    auto find_plt_section = [](const zElfSectionHeaderTable& sht) -> const zSectionTableElement* {
        int idx = sht.findByName(".plt");
        if (idx < 0) {
            idx = sht.findByName(".plt.sec");
        }
        return idx >= 0 ? sht.get((size_t)idx) : nullptr;
    };

    auto find_rela_plt_section = [](const zElfSectionHeaderTable& sht) -> const zRelocationSection* {
        int idx = sht.findByName(".rela.plt");
        if (idx < 0) {
            idx = sht.findByName(".rela.plt.sec");
        }
        if (idx < 0) {
            return nullptr;
        }
        return dynamic_cast<const zRelocationSection*>(sht.get((size_t)idx));
    };

    auto build_plt_symbol_entry_map = [](const zElfSectionHeaderTable& sht,
                                         const zSectionTableElement* plt_section,
                                         const zRelocationSection* rela_plt,
                                         std::unordered_map<std::string, std::vector<Elf64_Addr>>* out_map) -> bool {
        if (!plt_section || !rela_plt || !out_map || plt_section->size < 16) {
            return false;
        }

        out_map->clear();
        const auto& sections = sht.elements;
        if (rela_plt->link >= sections.size()) {
            return false;
        }

        const auto* dynsym = dynamic_cast<const zSymbolSection*>(sections[rela_plt->link].get());
        if (!dynsym || dynsym->type != SHT_DYNSYM) {
            return false;
        }
        if (dynsym->link >= sections.size()) {
            return false;
        }

        const auto* dynstr = dynamic_cast<const zStrTabSection*>(sections[dynsym->link].get());
        if (!dynstr) {
            return false;
        }

        constexpr Elf64_Xword kPltEntrySize = 16;
        Elf64_Xword plt_header_size = 0;
        const Elf64_Xword reloc_count = (Elf64_Xword)rela_plt->relocations.size();
        const Elf64_Xword reloc_entries_bytes = reloc_count * kPltEntrySize;
        if (plt_section->size >= reloc_entries_bytes) {
            plt_header_size = plt_section->size - reloc_entries_bytes;
        }
        if ((plt_header_size % kPltEntrySize) != 0) {
            plt_header_size = 16;
        }
        for (size_t rel_idx = 0; rel_idx < rela_plt->relocations.size(); ++rel_idx) {
            const auto& rela = rela_plt->relocations[rel_idx];
            const uint32_t sym_index = ELF64_R_SYM(rela.r_info);
            if (sym_index >= dynsym->symbols.size()) {
                continue;
            }

            const auto& sym = dynsym->symbols[sym_index];
            const char* sym_name = dynstr->getStringAt(sym.st_name);
            if (!sym_name || sym_name[0] == '\0') {
                continue;
            }

            const Elf64_Xword entry_off = plt_header_size + (Elf64_Xword)rel_idx * kPltEntrySize;
            if (entry_off + kPltEntrySize > plt_section->size) {
                break;
            }

            const Elf64_Addr entry_addr = plt_section->addr + entry_off;
            (*out_map)[sym_name].push_back(entry_addr);
        }
        return !out_map->empty();
    };

    // 基于 .plt + .rela.plt 生成 donor/target 的 PLT 槽位映射（按符号名对应）。
    const auto* donor_plt_section = find_plt_section(donor_elf.sectionHeaderModel());
    const auto* target_plt_section = find_plt_section(sh_table_model_);
    const auto* donor_rela_plt = find_rela_plt_section(donor_elf.sectionHeaderModel());
    const auto* target_rela_plt = find_rela_plt_section(sh_table_model_);

    bool plt_mapped_by_symbol = false;
    if (donor_plt_section && target_plt_section && donor_rela_plt && target_rela_plt) {
        std::unordered_map<std::string, std::vector<Elf64_Addr>> donor_symbol_entries;
        std::unordered_map<std::string, std::vector<Elf64_Addr>> target_symbol_entries;
        if (build_plt_symbol_entry_map(donor_elf.sectionHeaderModel(), donor_plt_section, donor_rela_plt, &donor_symbol_entries) &&
            build_plt_symbol_entry_map(sh_table_model_, target_plt_section, target_rela_plt, &target_symbol_entries)) {
            size_t mapped_count = 0;
            for (const auto& donor_item : donor_symbol_entries) {
                const auto target_it = target_symbol_entries.find(donor_item.first);
                if (target_it == target_symbol_entries.end()) {
                    continue;
                }

                const auto& donor_entries = donor_item.second;
                const auto& target_entries = target_it->second;
                const size_t pair_count = std::min(donor_entries.size(), target_entries.size());
                for (size_t idx = 0; idx < pair_count; ++idx) {
                    donor_to_target_plt_entry[donor_entries[idx]] = target_entries[idx];
                    ++mapped_count;
                }
            }
            if (mapped_count > 0) {
                plt_mapped_by_symbol = true;
                LOGI("Mapped donor->target .plt entries by .rela.plt symbol names: %zu", mapped_count);
            }
        }
    }

    if (!plt_mapped_by_symbol && donor_plt_section && target_plt_section && donor_rela_plt && target_rela_plt) {
        LOGW("Skip unsafe .plt fallback by offset; only symbol-based .plt mapping is allowed");
    }
    // 在段尾追加 donor 数据并镜像关键 section。
    if (!appendLoadDataAndMirrorSections(
            donor_elf,
            donor_target_pairs,
            expansion,
            &segment_relocations,
            &donor_section_index_remap,
            &mirrored_text_target_idx,
            &mirrored_text_blob_idx,
            &mirrored_text_blob_off,
            &mirrored_text_size)) {
        return false;
    }

    // 若已建立 donor->target 的 PLT 槽位映射，则修补新注入代码中的 tail-call 目标。
    if (!donor_to_target_plt_entry.empty()) {
        auto read_u32_le = [](const std::vector<uint8_t>& bytes, size_t off, uint32_t* out) -> bool {
            if (!out || off + 4 > bytes.size()) {
                return false;
            }
            *out = (uint32_t)bytes[off] |
                   ((uint32_t)bytes[off + 1] << 8) |
                   ((uint32_t)bytes[off + 2] << 16) |
                   ((uint32_t)bytes[off + 3] << 24);
            return true;
        };
        auto write_u32_le = [](std::vector<uint8_t>* bytes, size_t off, uint32_t value) -> bool {
            if (!bytes || off + 4 > bytes->size()) {
                return false;
            }
            (*bytes)[off] = (uint8_t)(value & 0xff);
            (*bytes)[off + 1] = (uint8_t)((value >> 8) & 0xff);
            (*bytes)[off + 2] = (uint8_t)((value >> 16) & 0xff);
            (*bytes)[off + 3] = (uint8_t)((value >> 24) & 0xff);
            return true;
        };
        auto is_b_imm26 = [](uint32_t insn) -> bool {
            return (insn & 0xfc000000U) == 0x14000000U;
        };
        auto decode_b_target = [](uint32_t insn, uint64_t pc) -> uint64_t {
            int64_t imm26 = (int32_t)(insn & 0x03ffffffU);
            if ((imm26 & (1LL << 25)) != 0) {
                imm26 |= ~((1LL << 26) - 1);
            }
            return (uint64_t)((int64_t)pc + (imm26 << 2));
        };
        auto encode_b_to_target = [](uint64_t pc, uint64_t target, uint32_t* out) -> bool {
            if (!out) {
                return false;
            }
            const int64_t delta = (int64_t)target - (int64_t)pc;
            if ((delta & 0x3LL) != 0) {
                return false;
            }
            const int64_t imm26 = delta >> 2;
            if (imm26 < -(1LL << 25) || imm26 > ((1LL << 25) - 1)) {
                return false;
            }
            *out = 0x14000000U | ((uint32_t)imm26 & 0x03ffffffU);
            return true;
        };
        // 根据 blob 新地址反推出该段的平移量（new_vaddr - donor_vaddr）。
        auto find_blob_segment_delta = [&segment_relocations](const PendingBlob& blob, int64_t* out_delta) -> bool {
            if (!out_delta) {
                return false;
            }
            for (const auto& relocation : segment_relocations) {
                if (relocation.donor_memsz == 0) {
                    continue;
                }
                const uint64_t begin = relocation.new_vaddr;
                const uint64_t end = begin + relocation.donor_memsz;
                if ((uint64_t)blob.vaddr >= begin && (uint64_t)blob.vaddr < end) {
                    *out_delta = (int64_t)relocation.new_vaddr - (int64_t)relocation.donor_vaddr;
                    return true;
                }
            }
            return false;
        };

        // 扫描注入的可执行 blob，重写直接 B 跳转到 target 的 .plt 入口。
        size_t patched_tail_branch = 0;
        for (auto& blob : pending_blobs_) {
            if (!blob.executable || blob.bytes.size() < 4) {
                continue;
            }

            int64_t seg_delta = 0;
            const bool has_seg_delta = find_blob_segment_delta(blob, &seg_delta);

            const size_t insn_count = blob.bytes.size() / 4;
            for (size_t insn_idx = 0; insn_idx < insn_count; ++insn_idx) {
                uint32_t insn = 0;
                if (!read_u32_le(blob.bytes, insn_idx * 4, &insn) || !is_b_imm26(insn)) {
                    continue;
                }
                const uint64_t pc = (uint64_t)blob.vaddr + (uint64_t)insn_idx * 4ULL;
                const uint64_t pc_old = has_seg_delta ? (uint64_t)((int64_t)pc - seg_delta) : pc;
                const uint64_t old_target = decode_b_target(insn, pc_old);
                auto it = donor_to_target_plt_entry.find((Elf64_Addr)old_target);
                if (it == donor_to_target_plt_entry.end()) {
                    const uint64_t cur_target = decode_b_target(insn, pc);
                    Elf64_Addr donor_addr = (Elf64_Addr)cur_target;
                    for (const auto& relocation : segment_relocations) {
                        if (relocation.donor_memsz == 0) {
                            continue;
                        }
                        const uint64_t begin = relocation.new_vaddr;
                        const uint64_t end = begin + relocation.donor_memsz;
                        if ((uint64_t)cur_target >= begin && (uint64_t)cur_target < end) {
                            donor_addr = (Elf64_Addr)(relocation.donor_vaddr + ((uint64_t)cur_target - begin));
                            break;
                        }
                    }
                    it = donor_to_target_plt_entry.find(donor_addr);
                }
                if (it == donor_to_target_plt_entry.end()) {
                    continue;
                }
                uint32_t new_insn = 0;
                if (!encode_b_to_target(pc, it->second, &new_insn) ||
                    !write_u32_le(&blob.bytes, insn_idx * 4, new_insn)) {
                    LOGE("Failed to rewrite donor .plt tail branch at insn=%zu", insn_idx);
                    return false;
                }
                ++patched_tail_branch;
            }
        }
        if (patched_tail_branch > 0) {
            LOGI("Rewritten injected direct branches to target .plt entries: %zu", patched_tail_branch);
        }

        if (mirrored_text_target_idx >= 0 &&
            mirrored_text_blob_idx < pending_blobs_.size() &&
            mirrored_text_size > 0) {
            auto* mirrored_sec = sh_table_model_.get((size_t)mirrored_text_target_idx);
            auto& mirrored_blob = pending_blobs_[mirrored_text_blob_idx];
            if (mirrored_sec &&
                mirrored_text_blob_off + mirrored_text_size <= mirrored_blob.bytes.size()) {
                mirrored_sec->payload.assign(mirrored_blob.bytes.begin() + (ptrdiff_t)mirrored_text_blob_off,
                                             mirrored_blob.bytes.begin() + (ptrdiff_t)mirrored_text_blob_off + (ptrdiff_t)mirrored_text_size);
                mirrored_sec->syncHeader();
            }
        }
    }

    // 合并静态符号表：导入 donor 符号并重写地址/节索引，同时跳过冲突符号。
    const int donor_symtab_idx = donor_elf.sectionHeaderModel().findByName(".symtab");
    const int donor_strtab_idx = donor_elf.sectionHeaderModel().findByName(".strtab");
    const int target_symtab_idx = sh_table_model_.findByName(".symtab");
    const int target_strtab_idx = sh_table_model_.findByName(".strtab");

    if (donor_symtab_idx >= 0 && donor_strtab_idx >= 0 &&
        target_symtab_idx >= 0 && target_strtab_idx >= 0) {
        const auto* donor_symtab = dynamic_cast<const zSymbolSection*>(donor_elf.sectionHeaderModel().get((size_t)donor_symtab_idx));
        const auto* donor_strtab = dynamic_cast<const zStrTabSection*>(donor_elf.sectionHeaderModel().get((size_t)donor_strtab_idx));
        auto* target_symtab = dynamic_cast<zSymbolSection*>(sh_table_model_.get((size_t)target_symtab_idx));
        auto* target_strtab = dynamic_cast<zStrTabSection*>(sh_table_model_.get((size_t)target_strtab_idx));

        if (!donor_symtab || !donor_strtab || !target_symtab || !target_strtab) {
            LOGE("Failed to cast symbol/string table sections for symbol merge");
            return false;
        }

        auto find_symbol_index = [](const zSymbolSection* symtab,
                                    const zStrTabSection* strtab,
                                    const char* target_name) -> int {
            if (!symtab || !strtab || !target_name) {
                return -1;
            }
            for (size_t idx = 1; idx < symtab->symbols.size(); ++idx) {
                const Elf64_Sym& sym = symtab->symbols[idx];
                const char* symbol_name = strtab->getStringAt(sym.st_name);
                if (!symbol_name) {
                    continue;
                }
                if (std::strcmp(symbol_name, target_name) == 0) {
                    return (int)idx;
                }
            }
            return -1;
        };

        const int donor_test1_idx = find_symbol_index(donor_symtab, donor_strtab, "test1");
        if (donor_test1_idx < 0) {
            LOGE("Validation failed: missing symbol test1 in donor ELF");
            return false;
        }
        const Elf64_Sym& donor_test1 = donor_symtab->symbols[(size_t)donor_test1_idx];
        if (is_special_shndx(donor_test1.st_shndx)) {
            LOGE("Validation failed: donor test1 has special shndx=%u", donor_test1.st_shndx);
            return false;
        }
        const auto* donor_test1_sec = donor_elf.sectionHeaderModel().get((size_t)donor_test1.st_shndx);
        if (!donor_test1_sec) {
            LOGE("Validation failed: donor test1 section not found");
            return false;
        }
        if (donor_test1_sec->resolved_name != ".text" || (donor_test1_sec->flags & SHF_EXECINSTR) == 0) {
            LOGE("Validation failed: donor test1 is not in executable .text section");
            return false;
        }

        const int target_test2_idx_before = find_symbol_index(target_symtab, target_strtab, "test2");
        if (target_test2_idx_before < 0) {
            LOGE("Validation failed: missing symbol test2 in target ELF before merge");
            return false;
        }
        const Elf64_Sym& target_test2_before = target_symtab->symbols[(size_t)target_test2_idx_before];
        if (is_special_shndx(target_test2_before.st_shndx)) {
            LOGE("Validation failed: target test2 has special shndx=%u before merge", target_test2_before.st_shndx);
            return false;
        }
        const auto* target_test2_sec_before = sh_table_model_.get((size_t)target_test2_before.st_shndx);
        if (!target_test2_sec_before || target_test2_sec_before->resolved_name != ".text" ||
            (target_test2_sec_before->flags & SHF_EXECINSTR) == 0) {
            LOGE("Validation failed: target test2 is not in executable .text section before merge");
            return false;
        }

        auto relocate_symbol_value = [&segment_relocations](Elf64_Addr original) -> Elf64_Addr {
            for (const auto& relocation : segment_relocations) {
                if (relocation.donor_memsz == 0) {
                    continue;
                }
                const uint64_t seg_begin = relocation.donor_vaddr;
                const uint64_t seg_end = relocation.donor_vaddr + relocation.donor_memsz;
                if (original >= seg_begin && original < seg_end) {
                    return (Elf64_Addr)(relocation.new_vaddr + (original - relocation.donor_vaddr));
                }
            }
            return original;
        };

        size_t first_global = target_symtab->symbols.size();
        for (size_t idx = 0; idx < target_symtab->symbols.size(); ++idx) {
            if (ELF64_ST_BIND(target_symtab->symbols[idx].st_info) != STB_LOCAL) {
                first_global = idx;
                break;
            }
        }

        auto make_symbol_dedup_key = [](const char* name, const Elf64_Sym& sym) -> std::string {
            if (!name || name[0] == '\0') {
                return {};
            }
            std::string key(name);
            key.push_back('\x1f');
            key += std::to_string((unsigned)ELF64_ST_BIND(sym.st_info));
            key.push_back('\x1f');
            key += std::to_string((unsigned)ELF64_ST_TYPE(sym.st_info));
            key.push_back('\x1f');
            key += std::to_string((unsigned)(sym.st_other & 0x3));
            return key;
        };

        std::unordered_set<std::string> existing_symbol_keys;
        for (size_t idx = 1; idx < target_symtab->symbols.size(); ++idx) {
            const auto& existing_sym = target_symtab->symbols[idx];
            if (existing_sym.st_name == 0) {
                continue;
            }
            const char* existing_name = target_strtab->getStringAt(existing_sym.st_name);
            const std::string key = make_symbol_dedup_key(existing_name, existing_sym);
            if (!key.empty()) {
                existing_symbol_keys.insert(key);
            }
        }

        std::vector<Elf64_Sym> donor_local_symbols;
        std::vector<Elf64_Sym> donor_global_symbols;
        size_t skipped_duplicate_symbols = 0;
        size_t skipped_unmappable_symbols = 0;

        for (size_t idx = 1; idx < donor_symtab->symbols.size(); ++idx) {
            const Elf64_Sym& donor_sym = donor_symtab->symbols[idx];
            Elf64_Sym merged = donor_sym;

            const char* donor_name_for_log = nullptr;

            if (donor_sym.st_name == 0) {
                merged.st_name = 0;
            } else {
                const char* donor_name = donor_strtab->getStringAt(donor_sym.st_name);
                if (!donor_name) {
                    continue;
                }
                donor_name_for_log = donor_name;

                const std::string dedup_key = make_symbol_dedup_key(donor_name, donor_sym);
                if (!dedup_key.empty() && existing_symbol_keys.find(dedup_key) != existing_symbol_keys.end()) {
                    ++skipped_duplicate_symbols;
                    continue;
                }

                merged.st_name = target_strtab->addString(donor_name);
                if (!dedup_key.empty()) {
                    existing_symbol_keys.insert(dedup_key);
                }
            }

            if (!is_special_shndx(merged.st_shndx)) {
                merged.st_value = relocate_symbol_value(merged.st_value);

                auto direct_mapped_it = donor_section_index_remap.find((uint16_t)donor_sym.st_shndx);
                if (direct_mapped_it != donor_section_index_remap.end()) {
                    merged.st_shndx = direct_mapped_it->second;
                } else {

                    uint16_t remapped_shndx = SHN_UNDEF;
                    bool remapped = false;
                    const auto* donor_src_sec = donor_elf.sectionHeaderModel().get((size_t)donor_sym.st_shndx);
                    if (donor_src_sec) {
                        for (size_t target_sec_idx = 0; target_sec_idx < sh_table_model_.elements.size(); ++target_sec_idx) {
                            const auto* target_sec = sh_table_model_.elements[target_sec_idx].get();
                            if (!target_sec) {
                                continue;
                            }
                            if (target_sec->resolved_name == donor_src_sec->resolved_name &&
                                target_sec->type == donor_src_sec->type &&
                                target_sec->flags == donor_src_sec->flags &&
                                contains_addr_range_u64(target_sec->addr,
                                                        target_sec->size,
                                                        merged.st_value,
                                                        merged.st_size == 0 ? 1 : merged.st_size)) {
                                remapped_shndx = (uint16_t)target_sec_idx;
                                remapped = true;
                                break;
                            }
                        }
                    }
                    if (remapped) {
                        merged.st_shndx = remapped_shndx;
                    } else {
                        const bool is_alloc_symbol = donor_src_sec && ((donor_src_sec->flags & SHF_ALLOC) != 0);
                        const unsigned merged_type = ELF64_ST_TYPE(merged.st_info);
                        if (!is_alloc_symbol || ELF64_ST_BIND(merged.st_info) == STB_LOCAL) {
                            ++skipped_unmappable_symbols;
                            continue;
                        }
                        if (merged_type != STT_FUNC) {
                            merged.st_shndx = SHN_UNDEF;
                            merged.st_value = 0;
                            ++skipped_unmappable_symbols;
                            continue;
                        }
                        LOGE("Failed to remap donor symbol to target section: name=%s shndx=%u value=0x%llx",
                             donor_name_for_log ? donor_name_for_log : "(noname)",
                             (unsigned)donor_sym.st_shndx,
                             (unsigned long long)merged.st_value);
                        return false;
                    }
                }
            }

            if (ELF64_ST_BIND(merged.st_info) == STB_LOCAL) {
                donor_local_symbols.push_back(merged);
            } else {
                donor_global_symbols.push_back(merged);
            }
        }

        if (!donor_local_symbols.empty()) {
            target_symtab->symbols.insert(target_symtab->symbols.begin() + (ptrdiff_t)first_global,
                                          donor_local_symbols.begin(),
                                          donor_local_symbols.end());
            first_global += donor_local_symbols.size();
        }
        if (!donor_global_symbols.empty()) {
            target_symtab->symbols.insert(target_symtab->symbols.end(),
                                          donor_global_symbols.begin(),
                                          donor_global_symbols.end());
        }

        target_symtab->info = (Elf64_Word)first_global;
        target_symtab->syncHeader();
        target_strtab->syncHeader();

        auto is_exec_mapped = [this](Elf64_Addr vaddr, Elf64_Xword size) -> bool {
            if (vaddr == 0) {
                return false;
            }
            const uint64_t checked_size = size == 0 ? 1 : (uint64_t)size;
            for (const auto& ph : programHeaderModel().elements) {
                if (ph.type != PT_LOAD || (ph.flags & PF_X) == 0) {
                    continue;
                }
                if (contains_addr_range_u64(ph.vaddr, ph.memsz, vaddr, checked_size)) {
                    return true;
                }
            }
            return false;
        };

        const char* must_have_symbols[] = {"test1", "test2"};
        for (const char* symbol_name : must_have_symbols) {
            const int idx = find_symbol_index(target_symtab, target_strtab, symbol_name);
            if (idx < 0) {
                LOGE("Validation failed: missing symbol %s after merge", symbol_name);
                return false;
            }
            const Elf64_Sym& sym = target_symtab->symbols[(size_t)idx];
            if (ELF64_ST_TYPE(sym.st_info) == STT_FUNC && !is_exec_mapped(sym.st_value, sym.st_size)) {
                LOGE("Validation failed: symbol %s is not mapped in executable PT_LOAD", symbol_name);
                return false;
            }
        }

        LOGI("Merged donor symbols: local=%zu global=%zu skipped_duplicate=%zu skipped_unmappable=%zu",
             donor_local_symbols.size(),
             donor_global_symbols.size(),
             skipped_duplicate_symbols,
             skipped_unmappable_symbols);
    } else {
        LOGW("Skip symbol merge: missing .symtab/.strtab in donor or target ELF");
    }

    // 第一次重构：先把注入后的段/节布局固化到 file_image_。
    reconstruction_dirty_ = true;
    if (!Reconstruction()) {
        return false;
    }

    {
        auto relocate_old_vaddr_final = [this, &expansion](Elf64_Addr old_vaddr) -> Elf64_Addr {
            if (old_vaddr == 0) {
                return 0;
            }
            for (const auto& state : expansion.load_states) {
                if (state.idx < 0 || (size_t)state.idx >= ph_table_model_.elements.size() || state.old_memsz == 0) {
                    continue;
                }
                const uint64_t begin = (uint64_t)state.old_vaddr;
                const uint64_t end = begin + (uint64_t)state.old_memsz;
                if ((uint64_t)old_vaddr < begin || (uint64_t)old_vaddr >= end) {
                    continue;
                }
                const auto& final_ph = ph_table_model_.elements[(size_t)state.idx];
                return (Elf64_Addr)((uint64_t)final_ph.vaddr + ((uint64_t)old_vaddr - begin));
            }
            return old_vaddr;
        };

        // 地址重写阶段：修复 dynamic、rel[a]、RELR、APS2 等结构中的地址字段。
        std::string rewrite_error;
        if (!zElfAddressRewriter::rewriteAfterAddressShift(this, relocate_old_vaddr_final, &rewrite_error)) {
            LOGE("Address rewrite failed: %s", rewrite_error.c_str());
            return false;
        }

        std::string packed_rewrite_error;
        if (!zElfAddressRewriter::rewritePackedRelocationsAfterShift(this, relocate_old_vaddr_final, &packed_rewrite_error)) {
            LOGE("Packed relocation rewrite failed: %s", packed_rewrite_error.c_str());
            return false;
        }

        // 第二次重构：将地址重写后的 payload 再次固化到最终镜像。
        reconstruction_dirty_ = true;
        if (!Reconstruction()) {
            return false;
        }
    }

    // 最终一致性校验并保存输出文件。
    std::string err;
    if (!validate(&err)) {
        LOGE("Validation failed after injection: %s", err.c_str());
        return false;
    }

    return save(output_path);
}
