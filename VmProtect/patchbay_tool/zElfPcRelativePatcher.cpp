#include "zElfPcRelativePatcher.h"
#include "zElfUtils.h"
#include "zLog.h"

#include <capstone/capstone.h>
#include <capstone/aarch64.h>

namespace {

void emit_u32(std::vector<uint8_t>* out, uint32_t insn) {
    if (!out) {
        return;
    }
    out->push_back((uint8_t)(insn & 0xffU));
    out->push_back((uint8_t)((insn >> 8) & 0xffU));
    out->push_back((uint8_t)((insn >> 16) & 0xffU));
    out->push_back((uint8_t)((insn >> 24) & 0xffU));
}

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

} // namespace

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

    cs_insn* insn = cs_malloc(handle);
    if (!insn) {
        LOGE("Failed to allocate cs_insn for context=%s", context_name ? context_name : "(unknown)");
        cs_close(&handle);
        return false;
    }

    const uint8_t* code = input.data();
    size_t size = input.size();
    uint64_t address = old_pc_base;

    while (size >= 4) {
        const uint64_t insn_addr = address;
        if (!cs_disasm_iter(handle, &code, &size, &address, insn)) {
            const size_t off = (size_t)(insn_addr - old_pc_base);
            uint32_t raw = 0;
            if (!read_u32_le_bytes(input, off, &raw)) {
                cs_free(insn, 1);
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
        const cs_aarch64& arm64 = insn->detail->aarch64;
        const uint32_t raw =
                (uint32_t)insn->bytes[0] |
                ((uint32_t)insn->bytes[1] << 8) |
                ((uint32_t)insn->bytes[2] << 16) |
                ((uint32_t)insn->bytes[3] << 24);

        auto emit_branch_sequence = [&](uint64_t old_target) -> bool {
            const uint64_t new_target = relocate_old_addr(old_target);
            const unsigned scratch = 16;
            emit_movz_movk_sequence(output, scratch, false, new_target);
            emit_u32(output, 0xd61f0000U | ((scratch & 0x1fU) << 5));
            return true;
        };

        if (insn->id == AARCH64_INS_B &&
            arm64.op_count >= 1 &&
            arm64.operands[0].type == AARCH64_OP_IMM &&
            arm64.cc != AArch64CC_AL && arm64.cc != AArch64CC_Invalid) {
            const int inv_cc = invert_arm64_cc(arm64.cc);
            if (inv_cc < 0) {
                cs_free(insn, 1);
                cs_close(&handle);
                return false;
            }
            const int32_t skip_imm19 = 5;
            emit_u32(output, encode_b_cond(skip_imm19, inv_cc));
            if (!emit_branch_sequence((uint64_t)arm64.operands[0].imm)) {
                cs_free(insn, 1);
                cs_close(&handle);
                return false;
            }
            if (stats) {
                ++stats->cond_br;
                ++stats->expanded;
            }
            patched = true;
        } else if ((insn->id == AARCH64_INS_CBZ || insn->id == AARCH64_INS_CBNZ) &&
                   arm64.op_count >= 2 &&
                   arm64.operands[1].type == AARCH64_OP_IMM) {
            const int32_t skip_imm19 = 5;
            const uint32_t inv_raw = raw ^ (1U << 24);
            emit_u32(output, encode_imm19(inv_raw, skip_imm19));
            if (!emit_branch_sequence((uint64_t)arm64.operands[1].imm)) {
                cs_free(insn, 1);
                cs_close(&handle);
                return false;
            }
            if (stats) {
                ++stats->cond_br;
                ++stats->expanded;
            }
            patched = true;
        } else if ((insn->id == AARCH64_INS_TBZ || insn->id == AARCH64_INS_TBNZ) &&
                   arm64.op_count >= 3 &&
                   arm64.operands[2].type == AARCH64_OP_IMM) {
            const int32_t skip_imm14 = 5;
            const uint32_t inv_raw = raw ^ (1U << 24);
            emit_u32(output, encode_imm14(inv_raw, skip_imm14));
            if (!emit_branch_sequence((uint64_t)arm64.operands[2].imm)) {
                cs_free(insn, 1);
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

        if (insn->id == AARCH64_INS_ADRP && arm64.op_count >= 2 &&
            arm64.operands[0].type == AARCH64_OP_REG &&
            arm64.operands[1].type == AARCH64_OP_IMM) {
            bool is_w = false;
            unsigned rd = 0;
            if (!arm64_reg_to_gpr_index(arm64.operands[0].reg, &is_w, &rd)) {
                cs_free(insn, 1);
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
        } else if (insn->id == AARCH64_INS_ADR && arm64.op_count >= 2 &&
                   arm64.operands[0].type == AARCH64_OP_REG &&
                   arm64.operands[1].type == AARCH64_OP_IMM) {
            bool is_w = false;
            unsigned rd = 0;
            if (!arm64_reg_to_gpr_index(arm64.operands[0].reg, &is_w, &rd)) {
                cs_free(insn, 1);
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
                   (insn->id == AARCH64_INS_LDR || insn->id == AARCH64_INS_LDRSW ||
                    insn->id == AARCH64_INS_LDRB || insn->id == AARCH64_INS_LDRH ||
                    insn->id == AARCH64_INS_LDRSB || insn->id == AARCH64_INS_LDRSH)) {
            bool is_w = false;
            unsigned rt = 0;
            unsigned simd_rt = 0;
            SimdClass simd_class = SIMD_INVALID;
            const bool is_gpr = arm64_reg_to_gpr_index(arm64.operands[0].reg, &is_w, &rt);
            const bool is_simd = arm64_reg_to_simd_class(arm64.operands[0].reg, &simd_rt, &simd_class);
            if (!is_gpr && !is_simd) {
                cs_free(insn, 1);
                cs_close(&handle);
                return false;
            }
            const uint64_t old_target = (uint64_t)arm64.operands[1].imm;
            const uint64_t new_target = relocate_old_addr(old_target);
            const unsigned scratch = 16;
            emit_movz_movk_sequence(output, scratch, false, new_target);
            if (is_gpr) {
                bool ok = false;
                if (insn->id == AARCH64_INS_LDRSW) {
                    ok = emit_ldr_reg(output, false, rt, scratch, true);
                } else if (insn->id == AARCH64_INS_LDRB) {
                    ok = emit_ldr_zero_reg(output, rt, scratch, 1);
                } else if (insn->id == AARCH64_INS_LDRH) {
                    ok = emit_ldr_zero_reg(output, rt, scratch, 2);
                } else if (insn->id == AARCH64_INS_LDRSB) {
                    ok = emit_ldr_signed_reg(output, rt, scratch, false, is_w);
                } else if (insn->id == AARCH64_INS_LDRSH) {
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
        } else if (insn->id == AARCH64_INS_PRFM &&
                   arm64.op_count >= 2 &&
                   arm64.operands[1].type == AARCH64_OP_IMM) {
            emit_u32(output, 0xd503201fU);
            if (stats) {
                ++stats->prfm;
            }
            patched = true;
        } else if ((insn->id == AARCH64_INS_B || insn->id == AARCH64_INS_BL) &&
                   arm64.op_count >= 1 &&
                   arm64.operands[0].type == AARCH64_OP_IMM) {
            const uint64_t old_target = (uint64_t)arm64.operands[0].imm;
            const uint64_t new_target = relocate_old_addr(old_target);
            const unsigned scratch = 16;
            emit_movz_movk_sequence(output, scratch, false, new_target);
            const uint32_t br_insn = (insn->id == AARCH64_INS_BL) ? 0xd63f0000U : 0xd61f0000U;
            emit_u32(output, br_insn | ((scratch & 0x1fU) << 5));
            if (stats) {
                if (insn->id == AARCH64_INS_BL) {
                    ++stats->bl;
                } else {
                    ++stats->br;
                }
                ++stats->expanded;
            }
            patched = true;
        }

        if (!patched) {
            emit_u32(output, raw);
        }
    }

    if (size > 0) {
        const size_t off = input.size() - size;
        output->insert(output->end(), input.begin() + (size_t)off, input.end());
    }

    cs_free(insn, 1);
    cs_close(&handle);
    return true;
}
