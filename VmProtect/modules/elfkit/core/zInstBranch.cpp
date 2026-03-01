/*
 * [VMP_FLOW_NOTE] branch 域分发实现。
 * - 该文件仅承载单一域的 ARM64->VM 指令分发实现。
 * - 与 zInst::classifyArm64Domain 分域保持一致。
 */
#include "zInstDispatch.h"

bool dispatchArm64BranchCase(
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
    // branch 指令分发：由原 Dispatch.inc 迁移为 cpp 函数，避免片段 include。
    (void)detail;
    (void)addr;
    (void)branch_id_list;
    (void)call_target_list;
    switch (id) {
/*
 * [VMP_FLOW_NOTE] dispatch cases for branch.
 * - Grouped by instruction domain.
 */

            case ARM64_INS_RET:
                // 约定 ret 返回 x0。
                // OP_RETURN 布局：{opcode, ret_count, ret_reg...}。
                opcode_list = { OP_RETURN, 1, getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(AARCH64_REG_X0)) };
                break;

            case ARM64_INS_BR:
                // br lr 视为 ret，同样返回 x0。
                if (op_count >= 1 && ops[0].type == AARCH64_OP_REG && (ops[0].reg == AARCH64_REG_LR || ops[0].reg == AARCH64_REG_X30)) {
                    opcode_list = { OP_RETURN, 1, getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(AARCH64_REG_X0)) };
                } else if (op_count >= 1 &&
                           ops[0].type == AARCH64_OP_REG &&
                           isArm64GpReg(ops[0].reg) &&
                           !isArm64ZeroReg(ops[0].reg)) {
                    // 通用间接跳转语义：br xN -> 运行时按“目标地址->PC”查表跳转。
                    uint32_t target_reg = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    opcode_list = { OP_BRANCH_REG, target_reg };
                }
                break;
            // 间接调用：BLR -> OP_CALL（func 在寄存器）。

            case ARM64_INS_BLR: {
                // BLR：间接调用，按当前约定打包 x0-x5 六个参数寄存器。
                if (op_count >= 1 && ops[0].type == AARCH64_OP_REG) {
                    // 被调函数地址寄存器。
                    uint32_t func_reg = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    // ABI 参数寄存器 x0..x5。
                    uint32_t x0 = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(AARCH64_REG_X0));
                    uint32_t x1 = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(AARCH64_REG_X1));
                    uint32_t x2 = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(AARCH64_REG_X2));
                    uint32_t x3 = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(AARCH64_REG_X3));
                    uint32_t x4 = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(AARCH64_REG_X4));
                    uint32_t x5 = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(AARCH64_REG_X5));
                    // OP_CALL 布局：{opcode, isDirect=0, argc=6, retc=1, ret0=x0, func, arg0..arg5}。
                    opcode_list = { OP_CALL, 0, 6, 1, x0, func_reg, x0, x1, x2, x3, x4, x5 };
                }
                break;
            }
            // 跳转类：B/B.cond -> OP_BRANCH / OP_BRANCH_IF_CC。

            case ARM64_INS_B: {
                // B / B.cond：按条件码分派到 OP_BRANCH 或 OP_BRANCH_IF_CC。
                if (op_count >= 1 && ops[0].type == AARCH64_OP_IMM && detail) {
                    // 取出 Capstone 解码的条件码。
                    arm64_cc cc = detail->aarch64.cc;
                    // 条件码映射沿用 ARM64 cc 编号，运行时由 OP_BRANCH_IF_CC 解释。
                    switch (cc) {
                        case ARM64_CC_EQ:
                        case ARM64_CC_NE:
                        case ARM64_CC_HS:
                        case ARM64_CC_LO:
                        case ARM64_CC_MI:
                        case ARM64_CC_PL:
                        case ARM64_CC_VS:
                        case ARM64_CC_VC:
                        case ARM64_CC_HI:
                        case ARM64_CC_LS:
                        case ARM64_CC_GE:
                        case ARM64_CC_LT:
                        case ARM64_CC_GT:
                        case ARM64_CC_LE: {
                            // 条件跳转：记录目标地址并输出条件分支。
                            uint64_t target_addr = static_cast<uint64_t>(ops[0].imm);
                            // target_addr 先映射到 branch_id，后续统一回填 PC。
                            uint32_t branch_id = getOrAddBranch(branch_id_list, target_addr);
                            opcode_list = { OP_BRANCH_IF_CC, static_cast<uint32_t>(cc), branch_id };
                            break;
                        }
                        case ARM64_CC_AL:
                        case ARM64_CC_INVALID: {
                            // 无条件跳转：直接输出 OP_BRANCH。
                            uint64_t target_addr = static_cast<uint64_t>(ops[0].imm);
                            // 无条件分支同样复用 branch_id 列表。
                            uint32_t branch_id = getOrAddBranch(branch_id_list, target_addr);
                            opcode_list = { OP_BRANCH, branch_id };
                            break;
                        }
                        default:
                            // 未支持条件码保持 opcode 为空，走后续失败路径。
                            break;
                    }
                }
                break;
            }
            // 条件选择：CSEL 展开为 mov + conditional branch + mov。

            case ARM64_INS_CSEL: {
                if (detail &&
                    op_count >= 3 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG &&
                    ops[2].type == AARCH64_OP_REG) {
                    // CSEL 语义：条件成立时 dst 取 src_true，否则取 src_false。
                    // 这里展开成：dst=src_true; if(cond) goto next; dst=src_false;
                    // 选择条件码并准备“下一条地址”作为 true-path 跳过点。
                    arm64_cc cc = detail->aarch64.cc;
                    const uint64_t next_addr = addr + (insn[j].size == 0 ? 4 : static_cast<uint64_t>(insn[j].size));
                    std::vector<uint32_t> csel_ops;

                    switch (cc) {
                        case ARM64_CC_EQ:
                        case ARM64_CC_NE:
                        case ARM64_CC_HS:
                        case ARM64_CC_LO:
                        case ARM64_CC_MI:
                        case ARM64_CC_PL:
                        case ARM64_CC_VS:
                        case ARM64_CC_VC:
                        case ARM64_CC_HI:
                        case ARM64_CC_LS:
                        case ARM64_CC_GE:
                        case ARM64_CC_LT:
                        case ARM64_CC_GT:
                        case ARM64_CC_LE: {
                            // 先写 true 值，保证条件成立时不再覆盖 dst。
                            if (appendAssignRegOrZero(csel_ops, reg_id_list, ops[0].reg, ops[1].reg)) {
                                uint32_t branch_id = getOrAddBranch(branch_id_list, next_addr);
                                // 若条件满足，直接跳过后续 false 赋值路径。
                                csel_ops.push_back(OP_BRANCH_IF_CC);
                                csel_ops.push_back(static_cast<uint32_t>(cc));
                                csel_ops.push_back(branch_id);
                                // 条件不满足时再写入 false 分支寄存器值。
                                if (appendAssignRegOrZero(csel_ops, reg_id_list, ops[0].reg, ops[2].reg)) {
                                    opcode_list = std::move(csel_ops);
                                }
                            }
                            break;
                        }
                        case ARM64_CC_AL:
                        case ARM64_CC_INVALID: {
                            if (appendAssignRegOrZero(csel_ops, reg_id_list, ops[0].reg, ops[1].reg)) {
                                opcode_list = std::move(csel_ops);
                            }
                            break;
                        }
                        default:
                            // 未支持条件码保持 opcode 为空，走后续失败路径。
                            break;
                    }
                }
                break;
            }
            // 条件选择并自增：CSINC 展开为 csel + (false 分支自增)。

            case ARM64_INS_CBZ:
            case ARM64_INS_CBNZ: {
                // CBZ/CBNZ：先做“cmp reg, #0”更新 NZCV，再走条件跳转。
                // CBZ 语义=EQ（零），CBNZ 语义=NE（非零）。
                if (op_count >= 2 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_IMM &&
                    isArm64GpReg(ops[0].reg)) {
                    uint64_t target_addr = static_cast<uint64_t>(ops[1].imm);
                    uint32_t branch_id = getOrAddBranch(branch_id_list, target_addr);
                    // 零寄存器特殊语义：CBZ wzr/xzr 恒成立，CBNZ 恒不成立。
                    if (isArm64ZeroReg(ops[0].reg)) {
                        opcode_list = (id == ARM64_INS_CBZ)
                                      ? std::vector<uint32_t>{ OP_BRANCH, branch_id }
                                      : std::vector<uint32_t>{ OP_NOP };
                        break;
                    }

                    uint32_t src_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    // 用临时寄存器承接常量 0 和比较结果，避免污染源寄存器。
                    uint32_t tmp_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(AARCH64_REG_X16));
                    uint32_t type_idx = getOrAddTypeTagForRegWidth(type_id_list, ops[0].reg);
                    uint32_t cond_cc = (id == ARM64_INS_CBZ)
                                       ? static_cast<uint32_t>(ARM64_CC_EQ)
                                       : static_cast<uint32_t>(ARM64_CC_NE);
                    opcode_list = {
                        OP_LOAD_IMM, tmp_idx, 0,
                        OP_CMP, type_idx, src_idx, tmp_idx, tmp_idx, CMP_EQ,
                        OP_BRANCH_IF_CC, cond_cc, branch_id
                    };
                }
                break;
            }

            case ARM64_INS_TBZ:
            case ARM64_INS_TBNZ: {
                // TBZ/TBNZ：拆成“右移取位 + 与 1 + 条件分支”三段 VM 指令。
                static const uint32_t BIN_UPDATE_FLAGS = 0x40u;
                if (op_count >= 3 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_IMM &&
                    ops[2].type == AARCH64_OP_IMM) {
                    uint32_t src_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    uint32_t tmp_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(AARCH64_REG_X16));
                    uint32_t type_idx = getOrAddTypeTag(type_id_list, TYPE_TAG_INT64_SIGNED);
                    uint32_t bit = static_cast<uint32_t>(ops[1].imm) & 63u;
                    // bit 只允许 0..63，超范围按掩码截断。
                    uint64_t target_addr = static_cast<uint64_t>(ops[2].imm);
                    uint32_t branch_id = getOrAddBranch(branch_id_list, target_addr);
                    // TBZ 跳零（EQ），TBNZ 跳非零（NE）。
                    uint32_t cond_cc = (id == ARM64_INS_TBZ)
                                       ? static_cast<uint32_t>(ARM64_CC_EQ)
                                       : static_cast<uint32_t>(ARM64_CC_NE);
                    opcode_list = {
                        OP_BINARY_IMM, BIN_LSR, type_idx, src_idx, bit, tmp_idx,
                        OP_BINARY_IMM, BIN_AND | BIN_UPDATE_FLAGS, type_idx, tmp_idx, 1, tmp_idx,
                        OP_BRANCH_IF_CC, cond_cc, branch_id
                    };
                }
                break;
            }
            // 算术+标志：SUBS 与 SUB 类似，但必须更新 NZCV。

            case ARM64_INS_BL: {
                // BL：本地只记录目标地址索引，稍后可 remap 到全局 branch_addr_list。
                if (op_count >= 1 && ops[0].type == AARCH64_OP_IMM) {
                    // 目标地址来自立即数操作数。
                    uint64_t target_addr = static_cast<uint64_t>(ops[0].imm);
                    // BL 使用 call_target_list，不混入本地分支表 branch_id_list。
                    uint32_t branch_id = getOrAddBranch(call_target_list, target_addr);
                    // OP_BL 参数是 call_target_list 下标。
                    opcode_list = { OP_BL, branch_id };
                }
                break;
            }
            // 成对读取：LDP 拆成两条 OP_GET_FIELD。

            case ARM64_INS_CSINC: {
                // CSINC 有两类常见落地：
                // 1) 真正四元语义（Capstone operands 常为 3 个寄存器 + cc）；
                // 2) CSET 别名（Capstone 可能给出 id=CSINC + op_count=1）。
                if (detail &&
                    op_count == 1 &&
                    ops[0].type == AARCH64_OP_REG &&
                    isArm64GpReg(ops[0].reg) &&
                    !isArm64ZeroReg(ops[0].reg)) {
                    // cset dst, cc:
                    // cond 为真 -> dst=1
                    // cond 为假 -> dst=0
                    arm64_cc cc = detail->aarch64.cc;
                    const uint64_t next_addr = addr + (insn[j].size == 0 ? 4 : static_cast<uint64_t>(insn[j].size));
                    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    switch (cc) {
                        case ARM64_CC_EQ:
                        case ARM64_CC_NE:
                        case ARM64_CC_HS:
                        case ARM64_CC_LO:
                        case ARM64_CC_MI:
                        case ARM64_CC_PL:
                        case ARM64_CC_VS:
                        case ARM64_CC_VC:
                        case ARM64_CC_HI:
                        case ARM64_CC_LS:
                        case ARM64_CC_GE:
                        case ARM64_CC_LT:
                        case ARM64_CC_GT:
                        case ARM64_CC_LE: {
                            uint32_t branch_id = getOrAddBranch(branch_id_list, next_addr);
                            opcode_list = {
                                OP_LOAD_IMM, dst_idx, 1,
                                OP_BRANCH_IF_CC, static_cast<uint32_t>(cc), branch_id,
                                OP_LOAD_IMM, dst_idx, 0
                            };
                            break;
                        }
                        case ARM64_CC_AL:
                        case ARM64_CC_INVALID:
                            opcode_list = { OP_LOAD_IMM, dst_idx, 1 };
                            break;
                        default:
                            break;
                    }
                } else if (detail &&
                           op_count >= 3 &&
                           ops[0].type == AARCH64_OP_REG &&
                           ops[1].type == AARCH64_OP_REG &&
                           ops[2].type == AARCH64_OP_REG &&
                           isArm64GpReg(ops[0].reg) &&
                           !isArm64ZeroReg(ops[0].reg)) {
                    // csinc dst, t, f, cc:
                    // cond 为真 -> dst=t
                    // cond 为假 -> dst=f+1
                    arm64_cc cc = detail->aarch64.cc;
                    const uint64_t next_addr = addr + (insn[j].size == 0 ? 4 : static_cast<uint64_t>(insn[j].size));
                    std::vector<uint32_t> csinc_ops;
                    switch (cc) {
                        case ARM64_CC_EQ:
                        case ARM64_CC_NE:
                        case ARM64_CC_HS:
                        case ARM64_CC_LO:
                        case ARM64_CC_MI:
                        case ARM64_CC_PL:
                        case ARM64_CC_VS:
                        case ARM64_CC_VC:
                        case ARM64_CC_HI:
                        case ARM64_CC_LS:
                        case ARM64_CC_GE:
                        case ARM64_CC_LT:
                        case ARM64_CC_GT:
                        case ARM64_CC_LE: {
                            if (appendAssignRegOrZero(csinc_ops, reg_id_list, ops[0].reg, ops[1].reg)) {
                                uint32_t branch_id = getOrAddBranch(branch_id_list, next_addr);
                                csinc_ops.push_back(OP_BRANCH_IF_CC);
                                csinc_ops.push_back(static_cast<uint32_t>(cc));
                                csinc_ops.push_back(branch_id);
                                if (appendAssignRegOrZero(csinc_ops, reg_id_list, ops[0].reg, ops[2].reg) &&
                                    appendAddImmSelf(csinc_ops, reg_id_list, type_id_list, ops[0].reg, 1u)) {
                                    opcode_list = std::move(csinc_ops);
                                }
                            }
                            break;
                        }
                        case ARM64_CC_AL:
                        case ARM64_CC_INVALID: {
                            if (appendAssignRegOrZero(csinc_ops, reg_id_list, ops[0].reg, ops[1].reg)) {
                                opcode_list = std::move(csinc_ops);
                            }
                            break;
                        }
                        default:
                            break;
                    }
                }
                break;
            }

            // 条件选择并取反：CSINV（cond=true -> t，cond=false -> ~f）。
            case ARM64_INS_CSINV: {
                if (detail &&
                    op_count >= 3 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG &&
                    ops[2].type == AARCH64_OP_REG &&
                    isArm64GpReg(ops[0].reg) &&
                    !isArm64ZeroReg(ops[0].reg)) {
                    arm64_cc cc = detail->aarch64.cc;
                    const uint64_t next_addr = addr + (insn[j].size == 0 ? 4 : static_cast<uint64_t>(insn[j].size));
                    std::vector<uint32_t> csinv_ops;
                    switch (cc) {
                        case ARM64_CC_EQ:
                        case ARM64_CC_NE:
                        case ARM64_CC_HS:
                        case ARM64_CC_LO:
                        case ARM64_CC_MI:
                        case ARM64_CC_PL:
                        case ARM64_CC_VS:
                        case ARM64_CC_VC:
                        case ARM64_CC_HI:
                        case ARM64_CC_LS:
                        case ARM64_CC_GE:
                        case ARM64_CC_LT:
                        case ARM64_CC_GT:
                        case ARM64_CC_LE: {
                            if (appendAssignRegOrZero(csinv_ops, reg_id_list, ops[0].reg, ops[1].reg)) {
                                uint32_t branch_id = getOrAddBranch(branch_id_list, next_addr);
                                csinv_ops.push_back(OP_BRANCH_IF_CC);
                                csinv_ops.push_back(static_cast<uint32_t>(cc));
                                csinv_ops.push_back(branch_id);
                                std::vector<uint32_t> not_ops;
                                if (tryEmitBitwiseNotLike(not_ops, reg_id_list, type_id_list, ops[0].reg, ops[2].reg)) {
                                    csinv_ops.insert(csinv_ops.end(), not_ops.begin(), not_ops.end());
                                    opcode_list = std::move(csinv_ops);
                                }
                            }
                            break;
                        }
                        case ARM64_CC_AL: {
                            if (appendAssignRegOrZero(csinv_ops, reg_id_list, ops[0].reg, ops[1].reg)) {
                                opcode_list = std::move(csinv_ops);
                            }
                            break;
                        }
                        case ARM64_CC_INVALID: {
                            std::vector<uint32_t> not_ops;
                            if (tryEmitBitwiseNotLike(not_ops, reg_id_list, type_id_list, ops[0].reg, ops[2].reg)) {
                                opcode_list = std::move(not_ops);
                            }
                            break;
                        }
                        default:
                            break;
                    }
                }
                break;
            }

            case ARM64_INS_ALIAS_CSET: {
                // CSET：条件成立写 1，否则写 0。
                // 展开为：dst=1; if(cc) goto next; dst=0;
                if (detail &&
                    op_count >= 1 &&
                    ops[0].type == AARCH64_OP_REG &&
                    isArm64GpReg(ops[0].reg) &&
                    !isArm64ZeroReg(ops[0].reg)) {
                    arm64_cc cc = detail->aarch64.cc;
                    const uint64_t next_addr = addr + (insn[j].size == 0 ? 4 : static_cast<uint64_t>(insn[j].size));
                    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    std::vector<uint32_t> cset_ops;
                    switch (cc) {
                        case ARM64_CC_EQ:
                        case ARM64_CC_NE:
                        case ARM64_CC_HS:
                        case ARM64_CC_LO:
                        case ARM64_CC_MI:
                        case ARM64_CC_PL:
                        case ARM64_CC_VS:
                        case ARM64_CC_VC:
                        case ARM64_CC_HI:
                        case ARM64_CC_LS:
                        case ARM64_CC_GE:
                        case ARM64_CC_LT:
                        case ARM64_CC_GT:
                        case ARM64_CC_LE: {
                            uint32_t branch_id = getOrAddBranch(branch_id_list, next_addr);
                            cset_ops = {
                                OP_LOAD_IMM, dst_idx, 1,
                                OP_BRANCH_IF_CC, static_cast<uint32_t>(cc), branch_id,
                                OP_LOAD_IMM, dst_idx, 0
                            };
                            opcode_list = std::move(cset_ops);
                            break;
                        }
                        case ARM64_CC_AL:
                        case ARM64_CC_INVALID:
                            opcode_list = { OP_LOAD_IMM, dst_idx, 1 };
                            break;
                        default:
                            break;
                    }
                }
                break;
            }
        default:
            return false;
    }
    return true;
}

