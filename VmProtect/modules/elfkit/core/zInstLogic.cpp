/*
 * [VMP_FLOW_NOTE] logic 域分发实现。
 * - 该文件仅承载单一域的 ARM64->VM 指令分发实现。
 * - 与 zInst::classifyArm64Domain 分域保持一致。
 */
#include "zInst.h"

namespace {  // 命名空间入口：收敛内部实现细节，避免对外暴露辅助符号。

// 统一生成 EXTR 类语义：dst = (hi:lo) >> lsb，并按目标宽度收口。
bool tryEmitExtrLike(  // 流程注记：该语句参与当前阶段的数据组织与控制流推进。
    std::vector<uint32_t>& opcode_list,  // 参数声明：该参数参与当前语义分发或结果组装。
    std::vector<uint32_t>& reg_id_list,  // 参数声明：该参数参与当前语义分发或结果组装。
    std::vector<uint32_t>& type_id_list,  // 参数声明：该参数参与当前语义分发或结果组装。
    int dst_reg,  // 参数声明：该参数参与当前语义分发或结果组装。
    int hi_reg,  // 参数声明：该参数参与当前语义分发或结果组装。
    int lo_reg,  // 参数声明：该参数参与当前语义分发或结果组装。
    uint32_t lsb  // 流程注记：该语句参与当前阶段的数据组织与控制流推进。
) {  // 流程注记：该语句参与当前阶段的数据组织与控制流推进。
    if (!isArm64GpReg(dst_reg) || !isArm64GpReg(hi_reg) || !isArm64GpReg(lo_reg)) {  // 分支守卫：满足前置条件后再进入后续处理路径。
        return false;  // 失败出口：当前条件下中止并上抛错误。
    }
    const uint32_t bit_width = isArm64WReg(dst_reg) ? 32u : 64u;  // 状态更新：记录本步骤的中间结果或配置。
    const uint32_t safe_lsb = lsb % bit_width;  // 状态更新：记录本步骤的中间结果或配置。
    const uint32_t type_idx = isArm64WReg(dst_reg)  // 声明行：保持接口签名与实现语义对齐。
                              ? getOrAddTypeTag(type_id_list, TYPE_TAG_INT32_UNSIGNED)  // 声明行：保持接口签名与实现语义对齐。
                              : getOrAddTypeTag(type_id_list, TYPE_TAG_INT64_UNSIGNED);  // 状态更新：记录本步骤的中间结果或配置。
    const uint32_t dst_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(dst_reg));  // 状态更新：记录本步骤的中间结果或配置。
    const uint32_t hi_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(hi_reg));  // 状态更新：记录本步骤的中间结果或配置。
    const uint32_t lo_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(lo_reg));  // 状态更新：记录本步骤的中间结果或配置。
    if (safe_lsb == 0u) {  // 分支守卫：满足前置条件后再进入后续处理路径。
        opcode_list = { OP_MOV, lo_idx, dst_idx };  // 状态更新：记录本步骤的中间结果或配置。
        return true;  // 返回阶段：输出当前路径计算结果。
    }
    const uint32_t tmp_lo = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(AARCH64_REG_X16));  // 状态更新：记录本步骤的中间结果或配置。
    const uint32_t tmp_hi = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(AARCH64_REG_X17));  // 状态更新：记录本步骤的中间结果或配置。
    opcode_list = {  // 流程注记：该语句参与当前阶段的数据组织与控制流推进。
        OP_BINARY_IMM, BIN_LSR, type_idx, lo_idx, safe_lsb, tmp_lo,  // 参数声明：该参数参与当前语义分发或结果组装。
        OP_BINARY_IMM, BIN_SHL, type_idx, hi_idx, (bit_width - safe_lsb), tmp_hi,  // 参数声明：该参数参与当前语义分发或结果组装。
        OP_BINARY, BIN_OR, type_idx, tmp_lo, tmp_hi, dst_idx  // 流程注记：该语句参与当前阶段的数据组织与控制流推进。
    };  // 状态更新：记录本步骤的中间结果或配置。
    if (isArm64WReg(dst_reg)) {  // 分支守卫：满足前置条件后再进入后续处理路径。
        opcode_list.push_back(OP_BINARY_IMM);  // 状态更新：记录本步骤的中间结果或配置。
        opcode_list.push_back(BIN_AND);  // 状态更新：记录本步骤的中间结果或配置。
        opcode_list.push_back(type_idx);  // 状态更新：记录本步骤的中间结果或配置。
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

// 统一发射 tst（ands 两操作数别名）语义：仅更新标志位，结果写入临时寄存器。
bool tryEmitFlagAndLike(
    std::vector<uint32_t>& opcode_list,
    std::vector<uint32_t>& reg_id_list,
    std::vector<uint32_t>& type_id_list,
    const cs_arm64_op& lhs_op,
    const cs_arm64_op& rhs_op
) {
    if (lhs_op.type != AARCH64_OP_REG || !isArm64GpReg(lhs_op.reg)) {
        return false;
    }
    static const uint32_t BIN_UPDATE_FLAGS = 0x40u;
    const uint32_t dst_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(AARCH64_REG_X16));
    const uint32_t type_idx = getOrAddTypeTagForRegWidth(type_id_list, lhs_op.reg);
    const uint32_t lhs_idx = isArm64ZeroReg(lhs_op.reg)
                             ? getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(AARCH64_REG_X17))
                             : getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(lhs_op.reg));
    if (isArm64ZeroReg(lhs_op.reg)) {
        opcode_list = { OP_LOAD_IMM, lhs_idx, 0u };
    } else {
        opcode_list.clear();
    }

    if (rhs_op.type == AARCH64_OP_REG && isArm64GpReg(rhs_op.reg)) {
        const uint32_t rhs_idx = isArm64ZeroReg(rhs_op.reg)
                                 ? getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(AARCH64_REG_X15))
                                 : getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(rhs_op.reg));
        if (isArm64ZeroReg(rhs_op.reg)) {
            opcode_list.push_back(OP_LOAD_IMM);
            opcode_list.push_back(rhs_idx);
            opcode_list.push_back(0u);
        }
        opcode_list.push_back(OP_BINARY);
        opcode_list.push_back(BIN_AND | BIN_UPDATE_FLAGS);
        opcode_list.push_back(type_idx);
        opcode_list.push_back(lhs_idx);
        opcode_list.push_back(rhs_idx);
        opcode_list.push_back(dst_idx);
        return true;
    }

    if (rhs_op.type == AARCH64_OP_IMM) {
        uint64_t imm64 = static_cast<uint64_t>(rhs_op.imm);
        if (rhs_op.shift.type == AARCH64_SFT_LSL && rhs_op.shift.value != 0) {
            imm64 <<= static_cast<uint32_t>(rhs_op.shift.value);
        }
        if (isArm64WReg(lhs_op.reg)) {
            imm64 &= 0xFFFFFFFFull;
        }
        opcode_list.push_back(OP_BINARY_IMM);
        opcode_list.push_back(BIN_AND | BIN_UPDATE_FLAGS);
        opcode_list.push_back(type_idx);
        opcode_list.push_back(lhs_idx);
        opcode_list.push_back(static_cast<uint32_t>(imm64 & 0xFFFFFFFFull));
        opcode_list.push_back(dst_idx);
        return true;
    }

    opcode_list.clear();
    return false;
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

            case ARM64_INS_SXTB: // 指令分支：ARM64_INS_SXTB，在此分支内完成等价 VM 语义映射。
            case ARM64_INS_SXTH: // 指令分支：ARM64_INS_SXTH，在此分支内完成等价 VM 语义映射。
            case ARM64_INS_SXTW: // 指令分支：ARM64_INS_SXTW，在此分支内完成等价 VM 语义映射。
            case ARM64_INS_UXTB: // 指令分支：ARM64_INS_UXTB，在此分支内完成等价 VM 语义映射。
            case ARM64_INS_UXTH: // 指令分支：ARM64_INS_UXTH，在此分支内完成等价 VM 语义映射。
            case ARM64_INS_UXTW: { // 指令分支：ARM64_INS_UXTW，在此分支内完成等价 VM 语义映射。
                // sxt*/uxt*：按源位宽做符号/零扩展后写入目标寄存器。
                if (op_count >= 2 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG) {
                    bool sign_extend = false;
                    uint32_t src_type_tag = TYPE_TAG_INT32_SIGNED_2;
                    switch (id) {
                        case ARM64_INS_SXTB: // 指令分支：ARM64_INS_SXTB，在此分支内完成等价 VM 语义映射。
                            sign_extend = true;
                            src_type_tag = TYPE_TAG_INT8_SIGNED;
                            break;
                        case ARM64_INS_SXTH: // 指令分支：ARM64_INS_SXTH，在此分支内完成等价 VM 语义映射。
                            sign_extend = true;
                            src_type_tag = TYPE_TAG_INT16_SIGNED;
                            break;
                        case ARM64_INS_SXTW: // 指令分支：ARM64_INS_SXTW，在此分支内完成等价 VM 语义映射。
                            sign_extend = true;
                            src_type_tag = TYPE_TAG_INT32_SIGNED_2;
                            break;
                        case ARM64_INS_UXTB: // 指令分支：ARM64_INS_UXTB，在此分支内完成等价 VM 语义映射。
                            sign_extend = false;
                            src_type_tag = TYPE_TAG_INT8_UNSIGNED;
                            break;
                        case ARM64_INS_UXTH: // 指令分支：ARM64_INS_UXTH，在此分支内完成等价 VM 语义映射。
                            sign_extend = false;
                            src_type_tag = TYPE_TAG_INT16_UNSIGNED;
                            break;
                        case ARM64_INS_UXTW: // 指令分支：ARM64_INS_UXTW，在此分支内完成等价 VM 语义映射。
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

            case ARM64_INS_ALIAS_UBFX: // 指令分支：ARM64_INS_ALIAS_UBFX，在此分支内完成等价 VM 语义映射。
            case ARM64_INS_ALIAS_SBFX: { // 指令分支：ARM64_INS_ALIAS_SBFX，在此分支内完成等价 VM 语义映射。
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

            case ARM64_INS_UBFM: // 指令分支：ARM64_INS_UBFM，在此分支内完成等价 VM 语义映射。
            case ARM64_INS_SBFM: // 指令分支：ARM64_INS_SBFM，在此分支内完成等价 VM 语义映射。
            case ARM64_INS_ALIAS_UBFIZ: // 指令分支：ARM64_INS_ALIAS_UBFIZ，在此分支内完成等价 VM 语义映射。
            case ARM64_INS_ALIAS_SBFIZ: { // 指令分支：ARM64_INS_ALIAS_SBFIZ，在此分支内完成等价 VM 语义映射。
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
                            handled_alias = tryEmitLsrLike(opcode_list, reg_id_list, type_id_list, insn[j], op_count, ops);
                        }
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
                        } else {
                            bool handled_alias = tryEmitAsrLike(opcode_list, reg_id_list, type_id_list, insn[j], op_count, ops);
                            if (!handled_alias) {
                                (void)tryEmitLsrLike(opcode_list, reg_id_list, type_id_list, insn[j], op_count, ops);
                            }
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

            case ARM64_INS_ALIAS_LSR: {
                (void)tryEmitLsrLike(opcode_list, reg_id_list, type_id_list, insn[j], op_count, ops);
                break;
            }

            case ARM64_INS_ALIAS_ASR: {
                (void)tryEmitAsrLike(opcode_list, reg_id_list, type_id_list, insn[j], op_count, ops);
                break;
            }

            case ARM64_INS_BFM:
            case ARM64_INS_ALIAS_BFI: {
                // bfi/bfm dst, src, #lsb, #width：保留 dst 其他位并插入源位段。
                if (op_count >= 4 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG &&
                    ops[2].type == AARCH64_OP_IMM &&
                    ops[3].type == AARCH64_OP_IMM) {
                    (void)tryEmitBitfieldInsertIntoDstLike(
                        opcode_list,
                        reg_id_list,
                        type_id_list,
                        ops[0].reg,
                        ops[1].reg,
                        static_cast<uint32_t>(ops[2].imm),
                        static_cast<uint32_t>(ops[3].imm)
                    );
                }
                break;
            }
            // 直接调用：BL 先记录目标地址，导出阶段统一 remap。

            // 搬运类：MOV/别名 -> tryEmitMovLike。
            case ARM64_INS_MOV: { // 指令分支：ARM64_INS_MOV，在此分支内完成等价 VM 语义映射。
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

            // 浮点/向量搬运：GP<->GP 退化为 MOV，其余向量形态当前保守降级为 NOP。
            case ARM64_INS_FMOV:
            case ARM64_INS_ALIAS_FMOV: {
                if (op_count >= 2 && ops && ops[0].type == AARCH64_OP_REG) {
                    if (isArm64GpReg(ops[0].reg) &&
                        ((ops[1].type == AARCH64_OP_REG && isArm64GpReg(ops[1].reg)) ||
                         ops[1].type == AARCH64_OP_IMM)) {
                        (void)tryEmitMovLike(opcode_list, reg_id_list, ops[0].reg, ops[1]);
                    } else {
                        opcode_list = { OP_NOP };
                    }
                }
                break;
            }

            // 向量 lane/元素搬运：当前 VM 执行器不建模 SIMD 寄存器，统一降级为 NOP。
            case ARM64_INS_INS:
            case ARM64_INS_INSR:
            case ARM64_INS_MOVA:
            case ARM64_INS_UMOV:
            case ARM64_INS_SMOV:
            case ARM64_INS_DUP: {
                opcode_list = { OP_NOP };
                break;
            }

            // SIMD 立即数搬运：当前执行器不建模向量寄存器，保守降级为 NOP 以保证可翻译。
            case ARM64_INS_MOVI: { // 指令分支：ARM64_INS_MOVI，在此分支内完成等价 VM 语义映射。
                if (op_count >= 1 && ops && ops[0].type == AARCH64_OP_REG) {
                    if (!isArm64GpReg(ops[0].reg)) {
                        opcode_list = { OP_NOP };
                    } else if (op_count >= 2) {
                        (void)tryEmitMovLike(opcode_list, reg_id_list, ops[0].reg, ops[1]);
                    }
                }
                break;
            }

            case ARM64_INS_MOVZ: // 指令分支：ARM64_INS_MOVZ，在此分支内完成等价 VM 语义映射。
            case ARM64_INS_MOVN: { // 指令分支：ARM64_INS_MOVN，在此分支内完成等价 VM 语义映射。
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
            case ARM64_INS_EXTR: { // 指令分支：ARM64_INS_EXTR，在此分支内完成等价 VM 语义映射。
                // ror 别名常见为 EXTR + 两操作数 + shift 元信息。
                if (op_count == 2 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG) {
                    (void)tryEmitRorLike(opcode_list, reg_id_list, type_id_list, insn[j], op_count, ops);
                } else if (op_count >= 4 &&
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

            case ARM64_INS_FCVT:
            case ARM64_INS_FCMP:
            case ARM64_INS_CMEQ:
            case ARM64_INS_CMHI:
            case ARM64_INS_CMHS:
            case ARM64_INS_CMGT:
            case ARM64_INS_CMLT:
            case ARM64_INS_BIT:
            case ARM64_INS_BSL:
            case ARM64_INS_SHL:
            case ARM64_INS_SHLL:
            case ARM64_INS_SHLL2:
            case ARM64_INS_USHR:
            case ARM64_INS_USHLL:
            case ARM64_INS_USHLL2:
            case ARM64_INS_SHRN:
            case ARM64_INS_XTN:
            case ARM64_INS_FNEG:
            case ARM64_INS_FDIV:
            case ARM64_INS_FADD:
            case ARM64_INS_FMUL:
            case ARM64_INS_SCVTF:
            case ARM64_INS_FCVTZS:
            case ARM64_INS_UCVTF:
            case ARM64_INS_FCVTAS:
                // 浮点/SIMD 比较与移位当前不进入 VM 语义建模，先保守降级为 NOP。
                opcode_list = { OP_NOP };
                break;

            case ARM64_INS_NOT: {
                if (op_count >= 2 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG &&
                    isArm64GpReg(ops[0].reg) &&
                    isArm64GpReg(ops[1].reg)) {
                    (void)tryEmitBitwiseNotLike(
                        opcode_list,
                        reg_id_list,
                        type_id_list,
                        ops[0].reg,
                        ops[1].reg
                    );
                } else {
                    opcode_list = { OP_NOP };
                }
                break;
            }

            case ARM64_INS_AND: // 指令分支：ARM64_INS_AND，在此分支内完成等价 VM 语义映射。
            case ARM64_INS_ALIAS_TST:
            case ARM64_INS_ANDS: { // 指令分支：ARM64_INS_ANDS，在此分支内完成等价 VM 语义映射。
                // ANDS 需要更新条件标志，这里通过扩展位 BIN_UPDATE_FLAGS 标记。
                static const uint32_t BIN_UPDATE_FLAGS = 0x40u;
                // tst alias：ands lhs, rhs/imm，仅更新标志位。
                if ((id == ARM64_INS_ANDS || id == ARM64_INS_ALIAS_TST) &&
                    op_count == 2 &&
                    ops[0].type == AARCH64_OP_REG &&
                    (ops[1].type == AARCH64_OP_REG || ops[1].type == AARCH64_OP_IMM)) {
                    (void)tryEmitFlagAndLike(
                        opcode_list,
                        reg_id_list,
                        type_id_list,
                        ops[0],
                        ops[1]
                    );
                    break;
                }
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
            case ARM64_INS_ALIAS_ORR:
            case ARM64_INS_ORR: { // 指令分支：ARM64_INS_ORR，在此分支内完成等价 VM 语义映射。
                // ORR 既可能是真正位或，也可能是 mov alias（含零寄存器）。
                // Capstone 在别名场景下可能直接给出两操作数：orr-id + "mov dst, src"。
                if (op_count == 2 &&
                    ops[0].type == AARCH64_OP_REG &&
                    (ops[1].type == AARCH64_OP_REG || ops[1].type == AARCH64_OP_IMM)) {
                    if (!isArm64GpReg(ops[0].reg) ||
                        (ops[1].type == AARCH64_OP_REG && !isArm64GpReg(ops[1].reg))) {
                        opcode_list = { OP_NOP };
                    } else {
                        (void)tryEmitMovLike(opcode_list, reg_id_list, ops[0].reg, ops[1]);
                    }
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
            case ARM64_INS_ALIAS_MVN:
            case ARM64_INS_ORN: { // 指令分支：ARM64_INS_ORN，在此分支内完成等价 VM 语义映射。
                // mvn alias：orn dst, src（等价 dst = ~src）。
                if (op_count == 2 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG) {
                    if (!isArm64GpReg(ops[0].reg) || !isArm64GpReg(ops[1].reg)) {
                        opcode_list = { OP_NOP };
                    } else {
                        (void)tryEmitBitwiseNotLike(
                            opcode_list,
                            reg_id_list,
                            type_id_list,
                            ops[0].reg,
                            ops[1].reg
                        );
                    }
                } else if (op_count >= 3 &&
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
            case ARM64_INS_BIC: { // 指令分支：ARM64_INS_BIC，在此分支内完成等价 VM 语义映射。
                if (op_count >= 3 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG &&
                    ops[2].type == AARCH64_OP_REG) {
                    if (!isArm64GpReg(ops[0].reg) ||
                        !isArm64GpReg(ops[1].reg) ||
                        !isArm64GpReg(ops[2].reg)) {
                        opcode_list = { OP_NOP };
                    } else {
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
                }
                break;
            }

            // 位运算+标志：BICS -> dst = lhs & (~rhs)，并更新 NZCV。
            case ARM64_INS_BICS: { // 指令分支：ARM64_INS_BICS，在此分支内完成等价 VM 语义映射。
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
            case ARM64_INS_EON: { // 指令分支：ARM64_INS_EON，在此分支内完成等价 VM 语义映射。
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
            case ARM64_INS_EOR: { // 指令分支：ARM64_INS_EOR，在此分支内完成等价 VM 语义映射。
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
            case ARM64_INS_REV: { // 指令分支：ARM64_INS_REV，在此分支内完成等价 VM 语义映射。
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
            case ARM64_INS_REV16: { // 指令分支：ARM64_INS_REV16，在此分支内完成等价 VM 语义映射。
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
