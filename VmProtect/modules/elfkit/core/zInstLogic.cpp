/*
 * [VMP_FLOW_NOTE] logic 域分发实现。
 * - 该文件仅承载单一域的 ARM64->VM 指令分发实现。
 * - 与 zInst::classifyArm64Domain 分域保持一致。
 */
#include "zInstDispatch.h"

namespace {

// 统一生成 EXTR 类语义：dst = (hi:lo) >> lsb，并按目标宽度收口。
bool tryEmitExtrLike(
    std::vector<uint32_t>& opcode_list,
    std::vector<uint32_t>& reg_id_list,
    std::vector<uint32_t>& type_id_list,
    int dst_reg,
    int hi_reg,
    int lo_reg,
    uint32_t lsb
) {
    if (!isArm64GpReg(dst_reg) || !isArm64GpReg(hi_reg) || !isArm64GpReg(lo_reg)) {
        return false;
    }
    const uint32_t bit_width = isArm64WReg(dst_reg) ? 32u : 64u;
    const uint32_t safe_lsb = lsb % bit_width;
    const uint32_t type_idx = isArm64WReg(dst_reg)
                              ? getOrAddTypeTag(type_id_list, TYPE_TAG_INT32_UNSIGNED)
                              : getOrAddTypeTag(type_id_list, TYPE_TAG_INT64_UNSIGNED);
    const uint32_t dst_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(dst_reg));
    const uint32_t hi_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(hi_reg));
    const uint32_t lo_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(lo_reg));
    if (safe_lsb == 0u) {
        opcode_list = { OP_MOV, lo_idx, dst_idx };
        return true;
    }
    const uint32_t tmp_lo = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(AARCH64_REG_X16));
    const uint32_t tmp_hi = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(AARCH64_REG_X17));
    opcode_list = {
        OP_BINARY_IMM, BIN_LSR, type_idx, lo_idx, safe_lsb, tmp_lo,
        OP_BINARY_IMM, BIN_SHL, type_idx, hi_idx, (bit_width - safe_lsb), tmp_hi,
        OP_BINARY, BIN_OR, type_idx, tmp_lo, tmp_hi, dst_idx
    };
    if (isArm64WReg(dst_reg)) {
        opcode_list.push_back(OP_BINARY_IMM);
        opcode_list.push_back(BIN_AND);
        opcode_list.push_back(type_idx);
        opcode_list.push_back(dst_idx);
        opcode_list.push_back(0xFFFFFFFFu);
        opcode_list.push_back(dst_idx);
    }
    return true;
}

// 统一生成 rhs 取反再与 lhs 组合的位运算（ORN/BIC/BICS/EON）。
bool tryEmitNotRhsBinaryLike(
    std::vector<uint32_t>& opcode_list,
    std::vector<uint32_t>& reg_id_list,
    std::vector<uint32_t>& type_id_list,
    int dst_reg,
    int lhs_reg,
    int rhs_reg,
    uint32_t combine_op
) {
    if (!isArm64GpReg(dst_reg) || !isArm64GpReg(lhs_reg) || !isArm64GpReg(rhs_reg)) {
        return false;
    }
    const bool is_w = isArm64WReg(dst_reg);
    const uint32_t type_idx = is_w
                              ? getOrAddTypeTag(type_id_list, TYPE_TAG_INT32_UNSIGNED)
                              : getOrAddTypeTag(type_id_list, TYPE_TAG_INT64_UNSIGNED);
    const uint32_t dst_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(dst_reg));
    const uint32_t lhs_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(lhs_reg));
    const uint32_t rhs_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(rhs_reg));
    const uint32_t tmp_mask = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(AARCH64_REG_X16));
    const uint32_t tmp_not = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(AARCH64_REG_X17));
    std::vector<uint32_t> mask_ops;
    emitLoadImm(mask_ops, tmp_mask, is_w ? 0xFFFFFFFFull : 0xFFFFFFFFFFFFFFFFull);
    opcode_list.insert(opcode_list.end(), mask_ops.begin(), mask_ops.end());
    opcode_list.push_back(OP_BINARY);
    opcode_list.push_back(BIN_XOR);
    opcode_list.push_back(type_idx);
    opcode_list.push_back(rhs_idx);
    opcode_list.push_back(tmp_mask);
    opcode_list.push_back(tmp_not);
    opcode_list.push_back(OP_BINARY);
    opcode_list.push_back(combine_op);
    opcode_list.push_back(type_idx);
    opcode_list.push_back(lhs_idx);
    opcode_list.push_back(tmp_not);
    opcode_list.push_back(dst_idx);
    if (is_w) {
        opcode_list.push_back(OP_BINARY_IMM);
        opcode_list.push_back(BIN_AND);
        opcode_list.push_back(type_idx);
        opcode_list.push_back(dst_idx);
        opcode_list.push_back(0xFFFFFFFFu);
        opcode_list.push_back(dst_idx);
    }
    return true;
}

} // namespace

bool dispatchArm64LogicCase(
    unsigned int id,
    uint8_t op_count,
    cs_arm64_op* ops,
    cs_detail* detail,
    const cs_insn* insn,
    size_t j,
    uint64_t addr,
    std::vector<uint32_t>& opcode_list,
    std::vector<uint32_t>& reg_id_list,
    std::vector<uint32_t>& type_id_list,
    std::vector<uint64_t>& branch_id_list,
    std::vector<uint64_t>& call_target_list
) {
    // logic 指令分发：由原 Dispatch.inc 迁移为 cpp 函数，避免片段 include。
    (void)detail;
    (void)addr;
    (void)branch_id_list;
    (void)call_target_list;
    switch (id) {
/*
 * [VMP_FLOW_NOTE] dispatch cases for logic.
 * - Grouped by instruction domain.
 */

            case ARM64_INS_SXTB:
            case ARM64_INS_SXTH:
            case ARM64_INS_SXTW:
            case ARM64_INS_UXTB:
            case ARM64_INS_UXTH:
            case ARM64_INS_UXTW: {
                // sxt*/uxt*：按源位宽做符号/零扩展后写入目标寄存器。
                if (op_count >= 2 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG) {
                    bool sign_extend = false;
                    uint32_t src_type_tag = TYPE_TAG_INT32_SIGNED_2;
                    switch (id) {
                        case ARM64_INS_SXTB:
                            sign_extend = true;
                            src_type_tag = TYPE_TAG_INT8_SIGNED;
                            break;
                        case ARM64_INS_SXTH:
                            sign_extend = true;
                            src_type_tag = TYPE_TAG_INT16_SIGNED;
                            break;
                        case ARM64_INS_SXTW:
                            sign_extend = true;
                            src_type_tag = TYPE_TAG_INT32_SIGNED_2;
                            break;
                        case ARM64_INS_UXTB:
                            sign_extend = false;
                            src_type_tag = TYPE_TAG_INT8_UNSIGNED;
                            break;
                        case ARM64_INS_UXTH:
                            sign_extend = false;
                            src_type_tag = TYPE_TAG_INT16_UNSIGNED;
                            break;
                        case ARM64_INS_UXTW:
                            sign_extend = false;
                            src_type_tag = TYPE_TAG_INT32_UNSIGNED;
                            break;
                        default:
                            break;
                    }
                    (void)tryEmitExtendLike(
                        opcode_list,
                        reg_id_list,
                        type_id_list,
                        ops[0].reg,
                        ops[1].reg,
                        sign_extend,
                        src_type_tag
                    );
                }
                break;
            }
            // 位提取别名：UBFX/SBFX。

            case ARM64_INS_ALIAS_UBFX:
            case ARM64_INS_ALIAS_SBFX: {
                // ubfx/sbfx dst, src, #lsb, #width
                if (op_count >= 4 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG &&
                    ops[2].type == AARCH64_OP_IMM &&
                    ops[3].type == AARCH64_OP_IMM) {
                    uint32_t lsb = static_cast<uint32_t>(ops[2].imm);
                    uint32_t width = static_cast<uint32_t>(ops[3].imm);
                    bool sign_extract = (id == ARM64_INS_ALIAS_SBFX);
                    (void)tryEmitBitExtractLike(
                        opcode_list,
                        reg_id_list,
                        type_id_list,
                        ops[0].reg,
                        ops[1].reg,
                        lsb,
                        width,
                        sign_extract
                    );
                }
                break;
            }
            // 位域移动：UBFM/SBFM（先覆盖 non-wrap 常见形态）。

            case ARM64_INS_UBFM:
            case ARM64_INS_SBFM:
            case ARM64_INS_ALIAS_UBFIZ:
            case ARM64_INS_ALIAS_SBFIZ: {
                const bool is_ubfm_family = (id == ARM64_INS_UBFM || id == ARM64_INS_ALIAS_UBFIZ);
                const bool is_insert_alias = (id == ARM64_INS_ALIAS_UBFIZ || id == ARM64_INS_ALIAS_SBFIZ);
                // 先处理别名短操作数形态（不依赖 mnemonic 字符串）：
                // 1) UBFM + op_count=2 常见为 LSL 别名（如 "lsl w8, w8, #1"）。
                // 2) SBFM + op_count=2 常见为 SXT*/UXT* 别名（通过 ops[1].ext 标识扩展类型）。
                if (op_count >= 2 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG) {
                    if (is_ubfm_family) {
                        bool handled_alias = false;
                        // UBFM 也会承载 UXT* 别名（op_count=2，扩展类型写在 ops[1].ext）。
                        if (ops[1].ext == AARCH64_EXT_UXTB ||
                            ops[1].ext == AARCH64_EXT_UXTH ||
                            ops[1].ext == AARCH64_EXT_UXTW) {
                            uint32_t src_type_tag = TYPE_TAG_INT32_UNSIGNED;
                            switch (ops[1].ext) {
                                case AARCH64_EXT_UXTB:
                                    src_type_tag = TYPE_TAG_INT8_UNSIGNED;
                                    break;
                                case AARCH64_EXT_UXTH:
                                    src_type_tag = TYPE_TAG_INT16_UNSIGNED;
                                    break;
                                case AARCH64_EXT_UXTW:
                                default:
                                    src_type_tag = TYPE_TAG_INT32_UNSIGNED;
                                    break;
                            }
                            handled_alias = tryEmitExtendLike(
                                opcode_list,
                                reg_id_list,
                                type_id_list,
                                ops[0].reg,
                                ops[1].reg,
                                false,
                                src_type_tag
                            );
                        }
                        // 非 UXT* 扩展别名时，再尝试 LSL 别名路径。
                        if (!handled_alias) {
                            (void)tryEmitLslLike(opcode_list, reg_id_list, type_id_list, insn[j], op_count, ops);
                        }
                    } else {
                        bool sign_extend = false;
                        uint32_t src_type_tag = TYPE_TAG_INT32_SIGNED_2;
                        bool ext_supported = true;
                        switch (ops[1].ext) {
                            case AARCH64_EXT_SXTB:
                                sign_extend = true;
                                src_type_tag = TYPE_TAG_INT8_SIGNED;
                                break;
                            case AARCH64_EXT_SXTH:
                                sign_extend = true;
                                src_type_tag = TYPE_TAG_INT16_SIGNED;
                                break;
                            case AARCH64_EXT_SXTW:
                                sign_extend = true;
                                src_type_tag = TYPE_TAG_INT32_SIGNED_2;
                                break;
                            case AARCH64_EXT_UXTB:
                                sign_extend = false;
                                src_type_tag = TYPE_TAG_INT8_UNSIGNED;
                                break;
                            case AARCH64_EXT_UXTH:
                                sign_extend = false;
                                src_type_tag = TYPE_TAG_INT16_UNSIGNED;
                                break;
                            case AARCH64_EXT_UXTW:
                                sign_extend = false;
                                src_type_tag = TYPE_TAG_INT32_UNSIGNED;
                                break;
                            default:
                                ext_supported = false;
                                break;
                        }
                        if (ext_supported) {
                            (void)tryEmitExtendLike(
                                opcode_list,
                                reg_id_list,
                                type_id_list,
                                ops[0].reg,
                                ops[1].reg,
                                sign_extend,
                                src_type_tag
                            );
                        }
                    }
                }

                // ubfm/sbfm dst, src, #immr, #imms
                if (opcode_list.empty() &&
                    op_count >= 4 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG &&
                    ops[2].type == AARCH64_OP_IMM &&
                    ops[3].type == AARCH64_OP_IMM) {
                    bool sign_extract = !is_ubfm_family;
                    // 严格模式：通过 alias instruction id 区分“insert 语义”与“move 语义”，
                    // 不再依赖 mnemonic 字符串关键字。
                    if (is_insert_alias) {
                        uint32_t lsb = static_cast<uint32_t>(ops[2].imm);
                        uint32_t width = static_cast<uint32_t>(ops[3].imm);
                        (void)tryEmitBitfieldInsertLike(
                            opcode_list,
                            reg_id_list,
                            type_id_list,
                            ops[0].reg,
                            ops[1].reg,
                            lsb,
                            width,
                            sign_extract
                        );
                    } else {
                        uint32_t bit_width = isArm64WReg(ops[0].reg) ? 32u : 64u;
                        uint32_t immr = static_cast<uint32_t>(ops[2].imm) % bit_width;
                        uint32_t imms = static_cast<uint32_t>(ops[3].imm) % bit_width;
                        (void)tryEmitBitfieldMoveLike(
                            opcode_list,
                            reg_id_list,
                            type_id_list,
                            ops[0].reg,
                            ops[1].reg,
                            immr,
                            imms,
                            sign_extract
                        );
                    }
                }
                break;
            }
            // 直接调用：BL 先记录目标地址，导出阶段统一 remap。

            // 搬运类：MOV/别名 -> tryEmitMovLike。
            case ARM64_INS_MOV: {
                // mov（含别名形态）统一交给 tryEmitMovLike 处理。
                if (op_count >= 2 && ops && ops[0].type == AARCH64_OP_REG) {
                    if (!isArm64GpReg(ops[0].reg)) {
                        // 向量 lane 搬运暂不建模，保守降级为 NOP。
                        opcode_list = { OP_NOP };
                    } else {
                        // GP 目标 + 非 GP 源（如 mov w10, v3.s[1]）当前执行器不建模，降级为 NOP。
                        if (ops[1].type == AARCH64_OP_REG && !isArm64GpReg(ops[1].reg)) {
                            opcode_list = { OP_NOP };
                        } else {
                            (void)tryEmitMovLike(opcode_list, reg_id_list, ops[0].reg, ops[1]);
                        }
                    }
                }
                break;
            }

            // SIMD 立即数搬运：当前执行器不建模向量寄存器，保守降级为 NOP 以保证可翻译。
            case ARM64_INS_MOVI: {
                if (op_count >= 1 && ops && ops[0].type == AARCH64_OP_REG) {
                    if (!isArm64GpReg(ops[0].reg)) {
                        opcode_list = { OP_NOP };
                    } else if (op_count >= 2) {
                        (void)tryEmitMovLike(opcode_list, reg_id_list, ops[0].reg, ops[1]);
                    }
                }
                break;
            }

            case ARM64_INS_MOVZ:
            case ARM64_INS_MOVN: {
                // MOVZ/MOVN：构造立即数并写入目标寄存器。
                if (op_count >= 2 && ops[0].type == AARCH64_OP_REG && ops[1].type == AARCH64_OP_IMM) {
                    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    // MOVZ/MOVN 立即数字段仅占 16bit。
                    uint64_t imm = static_cast<uint64_t>(ops[1].imm) & 0xFFFFull;
                    uint32_t shift = (ops[1].shift.type == AARCH64_SFT_LSL) ? ops[1].shift.value : 0u;
                    // 先拼出基础值，再根据 MOVN 语义做按位取反。
                    uint64_t value = imm << shift;
                    if (id == ARM64_INS_MOVN) {
                        value = ~value;
                    }
                    if (isArm64WReg(ops[0].reg)) {
                        value &= 0xFFFFFFFFull;
                    }
                    emitLoadImm(opcode_list, dst_idx, value);
                }
                break;
            }

            // 位拼接提取：EXTR dst, hi, lo, lsb。
            case ARM64_INS_EXTR: {
                if (op_count >= 4 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG &&
                    ops[2].type == AARCH64_OP_REG &&
                    ops[3].type == AARCH64_OP_IMM) {
                    (void)tryEmitExtrLike(
                        opcode_list,
                        reg_id_list,
                        type_id_list,
                        ops[0].reg,
                        ops[1].reg,
                        ops[2].reg,
                        static_cast<uint32_t>(ops[3].imm)
                    );
                }
                break;
            }

            case ARM64_INS_AND:
            case ARM64_INS_ANDS: {
                // ANDS 需要更新条件标志，这里通过扩展位 BIN_UPDATE_FLAGS 标记。
                static const uint32_t BIN_UPDATE_FLAGS = 0x40u;
                // 形态：and(s) dst, lhs, rhs_or_imm。
                if (op_count >= 3 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG) {
                    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    uint32_t lhs_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].reg));
                    uint32_t op_code = BIN_AND | ((id == ARM64_INS_ANDS) ? BIN_UPDATE_FLAGS : 0u);
                    // op_code 低位是算子，高位附带“更新标志位”语义。
                    uint32_t type_idx = getOrAddTypeTagForRegWidth(type_id_list, ops[0].reg);
                    // 寄存器第三操作数路径。
                    if (ops[2].type == AARCH64_OP_REG) {
                        uint32_t rhs_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[2].reg));
                        opcode_list = { OP_BINARY, op_code, type_idx, lhs_idx, rhs_idx, dst_idx };
                    // 立即数第三操作数路径。
                    } else if (ops[2].type == AARCH64_OP_IMM) {
                        uint32_t imm = static_cast<uint32_t>(ops[2].imm);
                        opcode_list = { OP_BINARY_IMM, op_code, type_idx, lhs_idx, imm, dst_idx };
                    }
                }
                break;
            }

            // 位运算/别名类：ORR 兼容 mov alias。
            case ARM64_INS_ORR: {
                // ORR 既可能是真正位或，也可能是 mov alias（含零寄存器）。
                // Capstone 在别名场景下可能直接给出两操作数：orr-id + "mov dst, src"。
                if (op_count == 2 &&
                    ops[0].type == AARCH64_OP_REG &&
                    (ops[1].type == AARCH64_OP_REG || ops[1].type == AARCH64_OP_IMM)) {
                    (void)tryEmitMovLike(opcode_list, reg_id_list, ops[0].reg, ops[1]);
                } else if (op_count >= 3 &&
                           ops[0].type == AARCH64_OP_REG &&
                           ops[1].type == AARCH64_OP_REG) {
                    // 目标与左操作数寄存器索引。
                    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    uint32_t lhs_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].reg));
                    // 第三操作数是寄存器时优先处理 mov alias。
                    if (ops[2].type == AARCH64_OP_REG) {
                        uint32_t rhs_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[2].reg));
                        // 任一输入为零寄存器时退化为 MOV，减少不必要的位或指令。
                        if (ops[1].reg == AARCH64_REG_WZR || ops[1].reg == AARCH64_REG_XZR) {
                            opcode_list = { OP_MOV, rhs_idx, dst_idx };
                        } else if (ops[2].reg == AARCH64_REG_WZR || ops[2].reg == AARCH64_REG_XZR) {
                            opcode_list = { OP_MOV, lhs_idx, dst_idx };
                        } else {
                            // 常规 ORR -> BIN_OR。
                            opcode_list = { OP_BINARY, BIN_OR, getOrAddTypeTag(type_id_list, TYPE_TAG_INT64_SIGNED), lhs_idx, rhs_idx, dst_idx };
                        }
                    // 第三操作数是立即数时输出 OP_BINARY_IMM。
                    } else if (ops[2].type == AARCH64_OP_IMM) {
                        uint32_t imm = static_cast<uint32_t>(ops[2].imm);
                        opcode_list = { OP_BINARY_IMM, BIN_OR, getOrAddTypeTag(type_id_list, TYPE_TAG_INT64_SIGNED), lhs_idx, imm, dst_idx };
                    }
                }
                break;
            }

            // 位运算：ORN -> dst = lhs | (~rhs)。
            case ARM64_INS_ORN: {
                if (op_count >= 3 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG &&
                    ops[2].type == AARCH64_OP_REG) {
                    (void)tryEmitNotRhsBinaryLike(
                        opcode_list,
                        reg_id_list,
                        type_id_list,
                        ops[0].reg,
                        ops[1].reg,
                        ops[2].reg,
                        BIN_OR
                    );
                }
                break;
            }

            // 位运算：BIC -> dst = lhs & (~rhs)。
            case ARM64_INS_BIC: {
                if (op_count >= 3 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG &&
                    ops[2].type == AARCH64_OP_REG) {
                    (void)tryEmitNotRhsBinaryLike(
                        opcode_list,
                        reg_id_list,
                        type_id_list,
                        ops[0].reg,
                        ops[1].reg,
                        ops[2].reg,
                        BIN_AND
                    );
                }
                break;
            }

            // 位运算+标志：BICS -> dst = lhs & (~rhs)，并更新 NZCV。
            case ARM64_INS_BICS: {
                static const uint32_t BIN_UPDATE_FLAGS = 0x40u;
                if (op_count >= 3 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG &&
                    ops[2].type == AARCH64_OP_REG) {
                    (void)tryEmitNotRhsBinaryLike(
                        opcode_list,
                        reg_id_list,
                        type_id_list,
                        ops[0].reg,
                        ops[1].reg,
                        ops[2].reg,
                        BIN_AND | BIN_UPDATE_FLAGS
                    );
                }
                break;
            }

            // 位运算：EON -> dst = lhs xor (~rhs)。
            case ARM64_INS_EON: {
                if (op_count >= 3 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG &&
                    ops[2].type == AARCH64_OP_REG) {
                    (void)tryEmitNotRhsBinaryLike(
                        opcode_list,
                        reg_id_list,
                        type_id_list,
                        ops[0].reg,
                        ops[1].reg,
                        ops[2].reg,
                        BIN_XOR
                    );
                }
                break;
            }

            // 位运算：EOR -> OP_BINARY/OP_BINARY_IMM(BIN_XOR)。
            case ARM64_INS_EOR: {
                // EOR: dst = lhs xor rhs/imm（含寄存器 LSL 扩展）。
                if (op_count >= 3 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG) {
                    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    uint32_t lhs_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].reg));
                    uint32_t type_idx = getOrAddTypeTagForRegWidth(type_id_list, ops[0].reg);
                    if (ops[2].type == AARCH64_OP_REG) {
                        uint32_t rhs_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[2].reg));
                        if (ops[2].shift.type == AARCH64_SFT_LSL && ops[2].shift.value != 0) {
                            uint32_t tmp_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(AARCH64_REG_X16));
                            opcode_list = {
                                OP_BINARY_IMM,
                                BIN_SHL,
                                type_idx,
                                rhs_idx,
                                static_cast<uint32_t>(ops[2].shift.value),
                                tmp_idx,
                                OP_BINARY,
                                BIN_XOR,
                                type_idx,
                                lhs_idx,
                                tmp_idx,
                                dst_idx
                            };
                        } else {
                            opcode_list = { OP_BINARY, BIN_XOR, type_idx, lhs_idx, rhs_idx, dst_idx };
                        }
                    } else if (ops[2].type == AARCH64_OP_IMM) {
                        uint64_t imm64 = static_cast<uint64_t>(ops[2].imm);
                        if (ops[2].shift.type == AARCH64_SFT_LSL && ops[2].shift.value != 0) {
                            imm64 <<= static_cast<uint32_t>(ops[2].shift.value);
                        }
                        if (isArm64WReg(ops[0].reg)) {
                            imm64 &= 0xFFFFFFFFull;
                        }
                        opcode_list = {
                            OP_BINARY_IMM,
                            BIN_XOR,
                            type_idx,
                            lhs_idx,
                            static_cast<uint32_t>(imm64 & 0xFFFFFFFFull),
                            dst_idx
                        };
                    }
                }
                break;
            }

            // 字节重排：REV（32/64bit 全字节反转）。
            case ARM64_INS_REV: {
                if (op_count >= 2 && ops[0].type == AARCH64_OP_REG && ops[1].type == AARCH64_OP_REG) {
                    (void)tryEmitReverseBytesLike(
                        opcode_list,
                        reg_id_list,
                        type_id_list,
                        ops[0].reg,
                        ops[1].reg,
                        false
                    );
                }
                break;
            }

            // 字节重排：REV16（每个 16bit 半字内交换字节）。
            case ARM64_INS_REV16: {
                if (op_count >= 2 && ops[0].type == AARCH64_OP_REG && ops[1].type == AARCH64_OP_REG) {
                    (void)tryEmitReverseBytesLike(
                        opcode_list,
                        reg_id_list,
                        type_id_list,
                        ops[0].reg,
                        ops[1].reg,
                        true
                    );
                }
                break;
            }
        default:
            return false;
    }
    return true;
}
