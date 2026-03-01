/*
 * [VMP_FLOW_NOTE] arith 域分发实现。
 * - 该文件仅承载单一域的 ARM64->VM 指令分发实现。
 * - 与 zInst::classifyArm64Domain 分域保持一致。
 */
#include "zInstDispatch.h"

namespace {

// 统一发射 MADD/MSUB：dst = (lhs * rhs) +/- addend。
bool tryEmitMaddMsubLike(
    std::vector<uint32_t>& opcode_list,
    std::vector<uint32_t>& reg_id_list,
    std::vector<uint32_t>& type_id_list,
    int dst_reg,
    int lhs_reg,
    int rhs_reg,
    int addend_reg,
    bool is_sub
) {
    if (!isArm64GpReg(dst_reg) ||
        !isArm64GpReg(lhs_reg) ||
        !isArm64GpReg(rhs_reg) ||
        !isArm64GpReg(addend_reg)) {
        return false;
    }
    const uint32_t dst_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(dst_reg));
    const uint32_t lhs_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(lhs_reg));
    const uint32_t rhs_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(rhs_reg));
    const uint32_t add_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(addend_reg));
    const uint32_t type_idx = getOrAddTypeTagForRegWidth(type_id_list, dst_reg);
    const uint32_t tmp_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(AARCH64_REG_X16));
    opcode_list = {
        OP_BINARY, BIN_MUL, type_idx, lhs_idx, rhs_idx, tmp_idx,
        OP_BINARY, is_sub ? BIN_SUB : BIN_ADD, type_idx,
        is_sub ? add_idx : tmp_idx,
        is_sub ? tmp_idx : add_idx,
        dst_idx
    };
    return true;
}

// 统一发射 UDIV/SDIV。
bool tryEmitIdivLike(
    std::vector<uint32_t>& opcode_list,
    std::vector<uint32_t>& reg_id_list,
    std::vector<uint32_t>& type_id_list,
    int dst_reg,
    int lhs_reg,
    int rhs_reg,
    bool signed_div
) {
    if (!isArm64GpReg(dst_reg) || !isArm64GpReg(lhs_reg) || !isArm64GpReg(rhs_reg)) {
        return false;
    }
    const uint32_t dst_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(dst_reg));
    const uint32_t lhs_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(lhs_reg));
    const uint32_t rhs_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(rhs_reg));
    const uint32_t type_idx = isArm64WReg(dst_reg)
                              ? getOrAddTypeTag(type_id_list, signed_div ? TYPE_TAG_INT32_SIGNED_2 : TYPE_TAG_INT32_UNSIGNED)
                              : getOrAddTypeTag(type_id_list, signed_div ? TYPE_TAG_INT64_SIGNED : TYPE_TAG_INT64_UNSIGNED);
    opcode_list = { OP_BINARY, BIN_IDIV, type_idx, lhs_idx, rhs_idx, dst_idx };
    return true;
}

// 统一发射“更新标志位”的二元运算（cmn/tst 等别名共享）。
bool tryEmitFlagBinaryLike(
    std::vector<uint32_t>& opcode_list,
    std::vector<uint32_t>& reg_id_list,
    std::vector<uint32_t>& type_id_list,
    const cs_arm64_op& lhs_op,
    const cs_arm64_op& rhs_op,
    uint32_t binary_op
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
        opcode_list.push_back(binary_op | BIN_UPDATE_FLAGS);
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
        opcode_list.push_back(binary_op | BIN_UPDATE_FLAGS);
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

bool dispatchArm64ArithCase(
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
    // arith 指令分发：由原 Dispatch.inc 迁移为 cpp 函数，避免片段 include。
    (void)detail;
    (void)addr;
    (void)branch_id_list;
    (void)call_target_list;
    switch (id) {
/*
 * [VMP_FLOW_NOTE] dispatch cases for arith.
 * - Grouped by instruction domain.
 */

            case ARM64_INS_SUB: {
                // SUB: dst = lhs - rhs/imm
                if (op_count >= 3 && ops[0].type == AARCH64_OP_REG && ops[1].type == AARCH64_OP_REG) {
                    // 目标与左操作数都必须先映射到 VM 寄存器索引。
                    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    uint32_t lhs_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].reg));
                    if (ops[2].type == AARCH64_OP_IMM) {
                        // 立即数路径：输出 OP_BINARY_IMM。
                        uint32_t imm = static_cast<uint32_t>(ops[2].imm);
                        opcode_list = { OP_BINARY_IMM, BIN_SUB, getOrAddTypeTag(type_id_list, TYPE_TAG_INT64_SIGNED), lhs_idx, imm, dst_idx };
                    } else if (ops[2].type == AARCH64_OP_REG) {
                        // 寄存器路径：输出 OP_BINARY。
                        uint32_t rhs_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[2].reg));
                        opcode_list = { OP_BINARY, BIN_SUB, getOrAddTypeTag(type_id_list, TYPE_TAG_INT64_SIGNED), lhs_idx, rhs_idx, dst_idx };
                    }
                }
                break;
            }
            // 存储类：STR -> OP_SET_FIELD。

            case ARM64_INS_ADD:
            case ARM64_INS_ADDS: {
                // ADDS 需要更新条件标志，这里通过扩展位 BIN_UPDATE_FLAGS 标记。
                static const uint32_t BIN_UPDATE_FLAGS = 0x40u;
                // ADD/ADDS: dst = lhs + rhs/imm
                if (op_count >= 3 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG) {
                    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    uint32_t lhs_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].reg));
                    // op_code 低位是算子，高位附带“更新标志位”语义。
                    uint32_t op_code = BIN_ADD | ((id == ARM64_INS_ADDS) ? BIN_UPDATE_FLAGS : 0u);
                    // 类型按目标寄存器宽度推导，保持 w/x 语义一致。
                    uint32_t type_idx = getOrAddTypeTagForRegWidth(type_id_list, ops[0].reg);
                    if (ops[2].type == AARCH64_OP_IMM) {
                        // 立即数加法：支持 AArch64 immediate 的 LSL 折叠。
                        uint64_t imm64 = static_cast<uint64_t>(ops[2].imm);
                        if (ops[2].shift.type == AARCH64_SFT_LSL && ops[2].shift.value != 0) {
                            imm64 <<= static_cast<uint32_t>(ops[2].shift.value);
                        }
                        if (isArm64WReg(ops[0].reg)) {
                            // w 寄存器路径按 32 位截断立即数。
                            imm64 &= 0xFFFFFFFFull;
                        }
                        opcode_list = {
                            OP_BINARY_IMM,
                            op_code,
                            type_idx,
                            lhs_idx,
                            static_cast<uint32_t>(imm64 & 0xFFFFFFFFull),
                            dst_idx
                        };
                    } else if (ops[2].type == AARCH64_OP_REG) {
                        // 寄存器加法：若存在 lsl #imm，先移位再相加。
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
                                op_code,
                                type_idx,
                                lhs_idx,
                                tmp_idx,
                                dst_idx
                            };
                        } else {
                            opcode_list = { OP_BINARY, op_code, type_idx, lhs_idx, rhs_idx, dst_idx };
                        }
                    }
                }
                break;
            }

            case ARM64_INS_MOVK: {
                // MOVK：保留原值其它位，仅覆盖 16bit 片段。
                if (op_count >= 2 && ops[0].type == AARCH64_OP_REG && ops[1].type == AARCH64_OP_IMM) {
                    // 目标寄存器索引（写回位置）。
                    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    // MOVK immediate 仅低 16 位有效。
                    uint64_t imm = static_cast<uint64_t>(ops[1].imm) & 0xFFFFull;
                    // LSL 位移来自操作数 shift 字段。
                    uint32_t shift = (ops[1].shift.type == AARCH64_SFT_LSL) ? ops[1].shift.value : 0u;
                    // 目标片段值（已移位到目标 bit 区间）。
                    uint64_t imm_val = imm << shift;
                    // 清位掩码：目标片段位置为 0，其它位为 1。
                    uint64_t mask = ~(0xFFFFull << shift);
                    if (isArm64WReg(ops[0].reg)) {
                        // 32 位目标寄存器只保留低 32 位。
                        imm_val &= 0xFFFFFFFFull;
                        mask &= 0xFFFFFFFFull;
                    }

                    // 使用 x16/x17 作为临时寄存器拼接“mask + 新片段”。
                    uint32_t tmp1 = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(AARCH64_REG_X16));
                    uint32_t tmp2 = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(AARCH64_REG_X17));
                    uint32_t type_idx = getOrAddTypeTag(type_id_list, TYPE_TAG_INT64_SIGNED);

                    std::vector<uint32_t> temp;
                    // 第一步：加载 mask 并对 dst 执行 AND，清空目标位段。
                    emitLoadImm(temp, tmp1, mask);
                    opcode_list.insert(opcode_list.end(), temp.begin(), temp.end());
                    opcode_list.push_back(OP_BINARY);
                    opcode_list.push_back(BIN_AND);
                    opcode_list.push_back(type_idx);
                    opcode_list.push_back(dst_idx);
                    opcode_list.push_back(tmp1);
                    opcode_list.push_back(dst_idx);

                    temp.clear();
                    // 第二步：加载新片段并与 dst 做 OR 合并。
                    emitLoadImm(temp, tmp2, imm_val);
                    opcode_list.insert(opcode_list.end(), temp.begin(), temp.end());
                    opcode_list.push_back(OP_BINARY);
                    opcode_list.push_back(BIN_OR);
                    opcode_list.push_back(type_idx);
                    opcode_list.push_back(dst_idx);
                    opcode_list.push_back(tmp2);
                    opcode_list.push_back(dst_idx);
                }
                break;
            }
            // 算术类：MUL -> OP_BINARY(BIN_MUL)。

            // 算术类：ADD/ADDS -> OP_BINARY/OP_BINARY_IMM(BIN_ADD)。
            case ARM64_INS_LSL:
            case ARM64_INS_LSLR:
            case ARM64_INS_ALIAS_LSL: {
                // 统一处理左移：覆盖三操作数、两操作数+shift 等结构化形态。
                (void)tryEmitLslLike(opcode_list, reg_id_list, type_id_list, insn[j], op_count, ops);
                break;
            }

            case ARM64_INS_LSR: {
                // 统一处理逻辑右移：覆盖三操作数、两操作数+shift 等结构化形态。
                (void)tryEmitLsrLike(opcode_list, reg_id_list, type_id_list, insn[j], op_count, ops);
                break;
            }

            case ARM64_INS_ASR: {
                // 统一处理算术右移：覆盖三操作数、两操作数+shift 等结构化形态。
                (void)tryEmitAsrLike(opcode_list, reg_id_list, type_id_list, insn[j], op_count, ops);
                break;
            }

            case ARM64_INS_ROR: {
                // 统一处理循环右移：优先覆盖 immediate 形态。
                (void)tryEmitRorLike(opcode_list, reg_id_list, type_id_list, insn[j], op_count, ops);
                break;
            }

            case ARM64_INS_CLZ: {
                // CLZ：统计前导零，映射到 OP_UNARY(UNARY_CLZ)。
                if (op_count >= 2 &&
                    ops &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG &&
                    isArm64GpReg(ops[0].reg) &&
                    isArm64GpReg(ops[1].reg) &&
                    !isArm64ZeroReg(ops[0].reg)) {
                    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    uint32_t src_idx = 0;
                    if (isArm64ZeroReg(ops[1].reg)) {
                        // clz wzr/xzr 恒等于位宽：先把 src 临时置 0，再交由运行时计数。
                        src_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(AARCH64_REG_X16));
                        opcode_list = { OP_LOAD_IMM, src_idx, 0 };
                    } else {
                        src_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].reg));
                    }
                    uint32_t type_idx = isArm64WReg(ops[0].reg)
                                        ? getOrAddTypeTag(type_id_list, TYPE_TAG_INT32_UNSIGNED)
                                        : getOrAddTypeTag(type_id_list, TYPE_TAG_INT64_UNSIGNED);
                    opcode_list.push_back(OP_UNARY);
                    opcode_list.push_back(UNARY_CLZ);
                    opcode_list.push_back(type_idx);
                    opcode_list.push_back(src_idx);
                    opcode_list.push_back(dst_idx);
                }
                break;
            }

            // 位段写入类：MOVK 通过 AND/OR 组合实现片段覆盖。
            case ARM64_INS_MUL: {
                // 纯寄存器三操作数乘法。
                if (op_count >= 3 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG &&
                    ops[2].type == AARCH64_OP_REG) {
                    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    uint32_t lhs_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].reg));
                    uint32_t rhs_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[2].reg));
                    uint32_t type_idx = getOrAddTypeTagForRegWidth(type_id_list, ops[0].reg);
                    opcode_list = { OP_BINARY, BIN_MUL, type_idx, lhs_idx, rhs_idx, dst_idx };
                }
                break;
            }

            // 乘加：MADD -> dst = (lhs * rhs) + addend。
            case ARM64_INS_MADD: {
                // Capstone 常把 "mul dst, lhs, rhs" 记作 MADD 别名（隐式 addend=xzr），
                // 此时 op_count=3，需要按纯乘法落地。
                if (op_count >= 3 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG &&
                    ops[2].type == AARCH64_OP_REG &&
                    (op_count < 4 || ops[3].type != AARCH64_OP_REG)) {
                    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    uint32_t lhs_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].reg));
                    uint32_t rhs_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[2].reg));
                    uint32_t type_idx = getOrAddTypeTagForRegWidth(type_id_list, ops[0].reg);
                    opcode_list = { OP_BINARY, BIN_MUL, type_idx, lhs_idx, rhs_idx, dst_idx };
                } else if (op_count >= 4 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG &&
                    ops[2].type == AARCH64_OP_REG &&
                    ops[3].type == AARCH64_OP_REG) {
                    (void)tryEmitMaddMsubLike(
                        opcode_list,
                        reg_id_list,
                        type_id_list,
                        ops[0].reg,
                        ops[1].reg,
                        ops[2].reg,
                        ops[3].reg,
                        false
                    );
                }
                break;
            }

            // 乘减：MSUB -> dst = addend - (lhs * rhs)。
            case ARM64_INS_MSUB: {
                if (op_count >= 4 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG &&
                    ops[2].type == AARCH64_OP_REG &&
                    ops[3].type == AARCH64_OP_REG) {
                    (void)tryEmitMaddMsubLike(
                        opcode_list,
                        reg_id_list,
                        type_id_list,
                        ops[0].reg,
                        ops[1].reg,
                        ops[2].reg,
                        ops[3].reg,
                        true
                    );
                }
                break;
            }

            // 长乘（无符号）：UMULL -> dst = (uint32)lhs * (uint32)rhs。
            case ARM64_INS_UMULL: {
                if (op_count >= 3 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG &&
                    ops[2].type == AARCH64_OP_REG) {
                    (void)tryEmitWideningMulAddLike(
                        opcode_list,
                        reg_id_list,
                        type_id_list,
                        ops[0].reg,
                        ops[1].reg,
                        ops[2].reg,
                        AARCH64_REG_XZR,
                        false,
                        false
                    );
                }
                break;
            }

            // 长乘（有符号）：SMULL -> dst = (int32)lhs * (int32)rhs。
            case ARM64_INS_SMULL: {
                if (op_count >= 3 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG &&
                    ops[2].type == AARCH64_OP_REG) {
                    (void)tryEmitWideningMulAddLike(
                        opcode_list,
                        reg_id_list,
                        type_id_list,
                        ops[0].reg,
                        ops[1].reg,
                        ops[2].reg,
                        AARCH64_REG_XZR,
                        false,
                        true
                    );
                }
                break;
            }

            // 长乘加（无符号）：UMADDL -> dst = ((uint32)lhs*(uint32)rhs) + addend。
            case ARM64_INS_UMADDL: {
                if (op_count >= 4 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG &&
                    ops[2].type == AARCH64_OP_REG &&
                    ops[3].type == AARCH64_OP_REG) {
                    (void)tryEmitWideningMulAddLike(
                        opcode_list,
                        reg_id_list,
                        type_id_list,
                        ops[0].reg,
                        ops[1].reg,
                        ops[2].reg,
                        ops[3].reg,
                        true,
                        false
                    );
                }
                break;
            }

            // 长乘加（有符号）：SMADDL -> dst = ((int32)lhs*(int32)rhs) + addend。
            case ARM64_INS_SMADDL: {
                if (op_count >= 4 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG &&
                    ops[2].type == AARCH64_OP_REG &&
                    ops[3].type == AARCH64_OP_REG) {
                    (void)tryEmitWideningMulAddLike(
                        opcode_list,
                        reg_id_list,
                        type_id_list,
                        ops[0].reg,
                        ops[1].reg,
                        ops[2].reg,
                        ops[3].reg,
                        true,
                        true
                    );
                }
                break;
            }

            // 高位长乘（无符号）：UMULH -> (lhs * rhs) >> 64。
            case ARM64_INS_UMULH: {
                if (op_count >= 3 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG &&
                    ops[2].type == AARCH64_OP_REG) {
                    (void)tryEmitMulHighLike(
                        opcode_list,
                        reg_id_list,
                        type_id_list,
                        ops[0].reg,
                        ops[1].reg,
                        ops[2].reg,
                        false
                    );
                }
                break;
            }

            // 高位长乘（有符号）：SMULH -> signed_high64(lhs * rhs)。
            case ARM64_INS_SMULH: {
                if (op_count >= 3 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG &&
                    ops[2].type == AARCH64_OP_REG) {
                    (void)tryEmitMulHighLike(
                        opcode_list,
                        reg_id_list,
                        type_id_list,
                        ops[0].reg,
                        ops[1].reg,
                        ops[2].reg,
                        true
                    );
                }
                break;
            }

            // 无符号除法：UDIV -> dst = lhs / rhs。
            case ARM64_INS_UDIV: {
                if (op_count >= 3 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG &&
                    ops[2].type == AARCH64_OP_REG) {
                    (void)tryEmitIdivLike(
                        opcode_list,
                        reg_id_list,
                        type_id_list,
                        ops[0].reg,
                        ops[1].reg,
                        ops[2].reg,
                        false
                    );
                }
                break;
            }

            // 有符号除法：SDIV -> dst = lhs / rhs。
            case ARM64_INS_SDIV: {
                if (op_count >= 3 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG &&
                    ops[2].type == AARCH64_OP_REG) {
                    (void)tryEmitIdivLike(
                        opcode_list,
                        reg_id_list,
                        type_id_list,
                        ops[0].reg,
                        ops[1].reg,
                        ops[2].reg,
                        true
                    );
                }
                break;
            }

            // 地址构造类：ADR -> 直接加载绝对地址立即数。
            case ARM64_INS_ADR: {
                if (op_count >= 2 && ops[0].type == AARCH64_OP_REG && ops[1].type == AARCH64_OP_IMM) {
                    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    uint64_t imm = static_cast<uint64_t>(ops[1].imm);
                    emitLoadImm(opcode_list, dst_idx, imm);
                }
                break;
            }

            // 地址构造类：ADRP -> OP_ADRP。
            case ARM64_INS_ADRP: {
                // ADRP：提取页对齐基址，拆成高低 32bit 存入 OP_ADRP。
                if (op_count >= 2 && ops[0].type == AARCH64_OP_REG && ops[1].type == AARCH64_OP_IMM) {
                    // 目标寄存器索引。
                    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    // 立即数按页对齐（低 12 位清零）。
                    uint64_t imm = static_cast<uint64_t>(ops[1].imm);
                    imm &= ~0xFFFULL;
                    // 按协议拆分成 low32/high32。
                    opcode_list = { OP_ADRP, dst_idx,
                                    static_cast<uint32_t>(imm & 0xFFFFFFFFull),
                    static_cast<uint32_t>((imm >> 32) & 0xFFFFFFFFull) };
                }
                break;
            }

            // 系统寄存器读取：当前保守降级为零写入。
            case ARM64_INS_MRS: {
                // MRS 暂不模拟系统寄存器语义，先降级为目标寄存器写 0。
                if (op_count >= 1 && ops[0].type == AARCH64_OP_REG) {
                    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    opcode_list = { OP_LOAD_IMM, dst_idx, 0 };
                }
                break;
            }

            case ARM64_INS_HINT:

            case ARM64_INS_CLREX:

            case ARM64_INS_BRK:

            case ARM64_INS_SVC:
                // 系统/调试类指令在当前单线程回归场景下保守降级为 NOP。
                opcode_list = { OP_NOP };
                break;

            case ARM64_INS_SUBS: {
                // SUBS：与 SUB 类似，但需要更新条件标志。
                static const uint32_t BIN_UPDATE_FLAGS = 0x40u;
                // cmp alias：Capstone 常把 "cmp lhs, rhs/imm" 记作 SUBS（op_count=2）。
                if (op_count == 2 &&
                    ops[0].type == AARCH64_OP_REG &&
                    (ops[1].type == AARCH64_OP_REG || ops[1].type == AARCH64_OP_IMM)) {
                    (void)tryEmitCmpLike(opcode_list, reg_id_list, type_id_list, op_count, ops);
                    break;
                }
                // 目标/左值都必须是寄存器操作数。
                if (op_count >= 3 && ops[0].type == AARCH64_OP_REG && ops[1].type == AARCH64_OP_REG) {
                    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    uint32_t lhs_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].reg));
                    // 立即数版本 -> OP_BINARY_IMM。
                    if (ops[2].type == AARCH64_OP_IMM) {
                        uint32_t imm = static_cast<uint32_t>(ops[2].imm);
                        opcode_list = { OP_BINARY_IMM, BIN_SUB | BIN_UPDATE_FLAGS, getOrAddTypeTag(type_id_list, TYPE_TAG_INT64_SIGNED), lhs_idx, imm, dst_idx };
                    // 寄存器版本 -> OP_BINARY。
                    } else if (ops[2].type == AARCH64_OP_REG) {
                        uint32_t rhs_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[2].reg));
                        opcode_list = { OP_BINARY, BIN_SUB | BIN_UPDATE_FLAGS, getOrAddTypeTag(type_id_list, TYPE_TAG_INT64_SIGNED), lhs_idx, rhs_idx, dst_idx };
                    }
                }
                break;
            }
        default:
            return false;
    }
    return true;
}
