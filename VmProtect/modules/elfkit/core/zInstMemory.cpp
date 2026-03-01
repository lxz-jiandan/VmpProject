/*
 * [VMP_FLOW_NOTE] memory 域分发实现。
 * - 该文件仅承载单一域的 ARM64->VM 指令分发实现。
 * - 与 zInst::classifyArm64Domain 分域保持一致。
 */
#include "zInstDispatch.h"

bool dispatchArm64MemoryCase(
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
    // memory 指令分发：由原 Dispatch.inc 迁移为 cpp 函数，避免片段 include。
    (void)detail;
    (void)addr;
    (void)branch_id_list;
    (void)call_target_list;
    switch (id) {
/*
 * [VMP_FLOW_NOTE] dispatch cases for memory.
 * - Grouped by instruction domain.
 */

            case ARM64_INS_STR: {
                // STR: 映射为 OP_SET_FIELD(base + offset <- value)。
                if (op_count >= 2 && ops[0].type == AARCH64_OP_REG && ops[1].type == AARCH64_OP_MEM) {
                    // mem.disp 是相对基址偏移，按 int32 读取后再写入 word。
                    int32_t offset = static_cast<int32_t>(ops[1].mem.disp);
                    // 若写入源为零寄存器，使用 -1 作为“写 0”的约定哨兵值。
                    uint32_t value_reg_idx = (ops[0].reg == AARCH64_REG_WZR || ops[0].reg == AARCH64_REG_XZR)
                                             ? static_cast<uint32_t>(-1)
                                             : getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    opcode_list = {
                        OP_SET_FIELD,
                        getOrAddTypeTagForRegWidth(type_id_list, ops[0].reg),
                        getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].mem.base)),
                        static_cast<uint32_t>(offset),
                        value_reg_idx
                    };
                }
                break;
            }
            // 存储类：STRB -> OP_SET_FIELD(type=INT8_UNSIGNED)。

            case ARM64_INS_LDR: {
                // LDR: 映射为 OP_GET_FIELD(dst <- *(base+offset))。
                if (op_count >= 2 && ops[0].type == AARCH64_OP_REG && ops[1].type == AARCH64_OP_MEM) {
                    // 读取偏移同样来自 mem.disp。
                    int32_t offset = static_cast<int32_t>(ops[1].mem.disp);
                    opcode_list = {
                        OP_GET_FIELD,
                        getOrAddTypeTagForRegWidth(type_id_list, ops[0].reg),
                        getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].mem.base)),
                        static_cast<uint32_t>(offset),
                        getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg))
                    };
                }
                break;
            }
            // 读取类：LDRB -> OP_GET_FIELD(type=INT8_UNSIGNED)。

            case ARM64_INS_STP: {
                // STP：拆成两个连续 OP_SET_FIELD。
                if (op_count >= 3 && ops[0].type == AARCH64_OP_REG && ops[1].type == AARCH64_OP_REG && ops[2].type == AARCH64_OP_MEM) {
                    // 两次写入的起始地址偏移。
                    int32_t offset = static_cast<int32_t>(ops[2].mem.disp);
                    // 共同基址寄存器索引。
                    uint32_t base_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[2].mem.base));
                    // pair_size 根据寄存器宽度判定（w*=4, x*=8）。
                    uint32_t pair_size = (ops[0].reg >= AARCH64_REG_W0 && ops[0].reg <= AARCH64_REG_W30) ? 4u : 8u;
                    // 类型标签与 pair_size 一致。
                    uint32_t type_tag = (pair_size == 4)
                                        ? getOrAddTypeTag(type_id_list, TYPE_TAG_INT32_SIGNED_2)
                                        : getOrAddTypeTag(type_id_list, TYPE_TAG_INT64_SIGNED);
                    // 零寄存器写入时使用 -1 哨兵，后续由 appendAssignRegOrZero 语义处理。
                    uint32_t val1 = (ops[0].reg == AARCH64_REG_WZR || ops[0].reg == AARCH64_REG_XZR)
                                    ? static_cast<uint32_t>(-1)
                                    : getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    uint32_t val2 = (ops[1].reg == AARCH64_REG_WZR || ops[1].reg == AARCH64_REG_XZR)
                                    ? static_cast<uint32_t>(-1)
                                    : getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].reg));
                    // 输出两条连续 OP_SET_FIELD，偏移分别是 offset 与 offset + pair_size。
                    opcode_list = {
                        OP_SET_FIELD, type_tag, base_idx, static_cast<uint32_t>(offset), val1,
                        OP_SET_FIELD, type_tag, base_idx, static_cast<uint32_t>(offset + static_cast<int32_t>(pair_size)), val2
                    };
                }
                break;
            }
            // 非扩展寻址存储：STUR -> OP_SET_FIELD。

            case ARM64_INS_LDP: {
                // LDP：拆成两个连续 OP_GET_FIELD。
                if (op_count >= 3 && ops[0].type == AARCH64_OP_REG && ops[1].type == AARCH64_OP_REG && ops[2].type == AARCH64_OP_MEM) {
                    // 基址 + 位移。
                    int32_t offset = static_cast<int32_t>(ops[2].mem.disp);
                    uint32_t base_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[2].mem.base));
                    // 依据目标寄存器宽度推导单元素字节数。
                    uint32_t pair_size = (ops[0].reg >= AARCH64_REG_W0 && ops[0].reg <= AARCH64_REG_W30) ? 4u : 8u;
                    // 读取类型标签与目标寄存器索引。
                    uint32_t type_tag = (pair_size == 4)
                                        ? getOrAddTypeTag(type_id_list, TYPE_TAG_INT32_SIGNED_2)
                                        : getOrAddTypeTag(type_id_list, TYPE_TAG_INT64_SIGNED);
                    uint32_t dst1 = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    uint32_t dst2 = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].reg));
                    // 第一条读取 offset，第二条读取 offset + pair_size。
                    opcode_list = {
                        OP_GET_FIELD, type_tag, base_idx, static_cast<uint32_t>(offset), dst1,
                        OP_GET_FIELD, type_tag, base_idx, static_cast<uint32_t>(offset + static_cast<int32_t>(pair_size)), dst2
                    };
                }
                break;
            }

            case ARM64_INS_STRB: {
                // STRB：按 8bit 无符号语义写入 base+offset。
                if (op_count >= 2 && ops[0].type == AARCH64_OP_REG && ops[1].type == AARCH64_OP_MEM) {
                    int32_t offset = static_cast<int32_t>(ops[1].mem.disp);
                    uint32_t value_reg_idx = (ops[0].reg == AARCH64_REG_WZR || ops[0].reg == AARCH64_REG_XZR)
                                             ? static_cast<uint32_t>(-1)
                                             : getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    opcode_list = {
                        OP_SET_FIELD,
                        getOrAddTypeTag(type_id_list, TYPE_TAG_INT8_UNSIGNED),
                        getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].mem.base)),
                        static_cast<uint32_t>(offset),
                        value_reg_idx
                    };
                }
                break;
            }

            // 存储类：STRH -> OP_SET_FIELD(type=INT16_UNSIGNED)。
            case ARM64_INS_STRH: {
                // STRH：按 16bit 无符号语义写入 base+offset。
                if (op_count >= 2 && ops[0].type == AARCH64_OP_REG && ops[1].type == AARCH64_OP_MEM) {
                    int32_t offset = static_cast<int32_t>(ops[1].mem.disp);
                    uint32_t value_reg_idx = (ops[0].reg == AARCH64_REG_WZR || ops[0].reg == AARCH64_REG_XZR)
                                             ? static_cast<uint32_t>(-1)
                                             : getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    opcode_list = {
                        OP_SET_FIELD,
                        getOrAddTypeTag(type_id_list, TYPE_TAG_INT16_UNSIGNED),
                        getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].mem.base)),
                        static_cast<uint32_t>(offset),
                        value_reg_idx
                    };
                }
                break;
            }

            // 读取类：LDR -> OP_GET_FIELD。
            case ARM64_INS_LDRB: {
                // LDRB：按 8bit 无符号语义从 base+offset 读取到目标寄存器。
                if (op_count >= 2 && ops[0].type == AARCH64_OP_REG && ops[1].type == AARCH64_OP_MEM) {
                    int32_t offset = static_cast<int32_t>(ops[1].mem.disp);
                    opcode_list = {
                        OP_GET_FIELD,
                        getOrAddTypeTag(type_id_list, TYPE_TAG_INT8_UNSIGNED),
                        getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].mem.base)),
                        static_cast<uint32_t>(offset),
                        getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg))
                    };
                }
                break;
            }

            // 读取类：LDRH -> OP_GET_FIELD(type=INT16_UNSIGNED)。
            case ARM64_INS_LDRH: {
                // LDRH：按 16bit 无符号语义从 base+offset 读取到目标寄存器。
                if (op_count >= 2 && ops[0].type == AARCH64_OP_REG && ops[1].type == AARCH64_OP_MEM) {
                    int32_t offset = static_cast<int32_t>(ops[1].mem.disp);
                    opcode_list = {
                        OP_GET_FIELD,
                        getOrAddTypeTag(type_id_list, TYPE_TAG_INT16_UNSIGNED),
                        getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].mem.base)),
                        static_cast<uint32_t>(offset),
                        getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg))
                    };
                }
                break;
            }

            // 成对存储：STP 拆成两条 OP_SET_FIELD。
            case ARM64_INS_STUR: {
                // STUR：非扩展寻址的 store，映射为 OP_SET_FIELD。
                if (op_count >= 2 && ops[0].type == AARCH64_OP_REG && ops[1].type == AARCH64_OP_MEM) {
                    // 内存偏移可正可负，这里按带符号位移读取。
                    int32_t offset = static_cast<int32_t>(ops[1].mem.disp);
                    // 对零寄存器写入用 -1 哨兵表达“写 0”。
                    uint32_t value_reg_idx = (ops[0].reg == AARCH64_REG_WZR || ops[0].reg == AARCH64_REG_XZR)
                                             ? static_cast<uint32_t>(-1)
                                             : getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    // OP_SET_FIELD 参数顺序：type/base/offset/value。
                    opcode_list = {
                        OP_SET_FIELD,
                        getOrAddTypeTagForRegWidth(type_id_list, ops[0].reg),
                        getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].mem.base)),
                        static_cast<uint32_t>(offset),
                        value_reg_idx
                    };
                }
                break;
            }

            // 非扩展寻址字节存储：STURB -> OP_SET_FIELD(type=INT8_UNSIGNED)。
            case ARM64_INS_STURB: {
                // STURB：按 8bit 写入内存。
                if (op_count >= 2 && isArm64GpReg(ops[0].reg) && isArm64GpReg(ops[1].mem.base)) {
                    // 字节存储同样采用 base + disp 计算地址。
                    int32_t offset = static_cast<int32_t>(ops[1].mem.disp);
                    // 对零寄存器写入用 -1 哨兵表达“写 0”。
                    uint32_t value_reg_idx = (ops[0].reg == AARCH64_REG_WZR || ops[0].reg == AARCH64_REG_XZR)
                                             ? static_cast<uint32_t>(-1)
                                             : getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    opcode_list = {
                        OP_SET_FIELD,
                        getOrAddTypeTag(type_id_list, TYPE_TAG_INT8_UNSIGNED),
                        getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].mem.base)),
                        static_cast<uint32_t>(offset),
                        value_reg_idx
                    };
                }
                break;
            }

            // 非扩展寻址半字存储：STURH -> OP_SET_FIELD(type=INT16_UNSIGNED)。
            case ARM64_INS_STURH: {
                // STURH：按 16bit 写入内存。
                if (op_count >= 2 && isArm64GpReg(ops[0].reg) && isArm64GpReg(ops[1].mem.base)) {
                    int32_t offset = static_cast<int32_t>(ops[1].mem.disp);
                    uint32_t value_reg_idx = (ops[0].reg == AARCH64_REG_WZR || ops[0].reg == AARCH64_REG_XZR)
                                             ? static_cast<uint32_t>(-1)
                                             : getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    opcode_list = {
                        OP_SET_FIELD,
                        getOrAddTypeTag(type_id_list, TYPE_TAG_INT16_UNSIGNED),
                        getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].mem.base)),
                        static_cast<uint32_t>(offset),
                        value_reg_idx
                    };
                }
                break;
            }

            // release 字节存储：STLRB -> OP_ATOMIC_STORE(type=INT8_UNSIGNED, order=RELEASE)。
            case ARM64_INS_STLRB: {
                // STLRB：按 release 内存序执行 8bit 原子写入。
                if (op_count >= 2 && isArm64GpReg(ops[0].reg) && isArm64GpReg(ops[1].mem.base)) {
                    int32_t offset = static_cast<int32_t>(ops[1].mem.disp);
                    uint32_t value_reg_idx = (ops[0].reg == AARCH64_REG_WZR || ops[0].reg == AARCH64_REG_XZR)
                                             ? static_cast<uint32_t>(-1)
                                             : getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    opcode_list = {
                        OP_ATOMIC_STORE,
                        getOrAddTypeTag(type_id_list, TYPE_TAG_INT8_UNSIGNED),
                        getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].mem.base)),
                        static_cast<uint32_t>(offset),
                        value_reg_idx,
                        VM_MEM_ORDER_RELEASE
                    };
                }
                break;
            }

            // release 半字存储：STLRH -> OP_ATOMIC_STORE(type=INT16_UNSIGNED, order=RELEASE)。
            case ARM64_INS_STLRH: {
                // STLRH：按 release 内存序执行 16bit 原子写入。
                if (op_count >= 2 && isArm64GpReg(ops[0].reg) && isArm64GpReg(ops[1].mem.base)) {
                    int32_t offset = static_cast<int32_t>(ops[1].mem.disp);
                    uint32_t value_reg_idx = (ops[0].reg == AARCH64_REG_WZR || ops[0].reg == AARCH64_REG_XZR)
                                             ? static_cast<uint32_t>(-1)
                                             : getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    opcode_list = {
                        OP_ATOMIC_STORE,
                        getOrAddTypeTag(type_id_list, TYPE_TAG_INT16_UNSIGNED),
                        getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].mem.base)),
                        static_cast<uint32_t>(offset),
                        value_reg_idx,
                        VM_MEM_ORDER_RELEASE
                    };
                }
                break;
            }

            // release 字/双字存储：STLR -> OP_ATOMIC_STORE(type=reg-width, order=RELEASE)。
            case ARM64_INS_STLR: {
                // STLR：按 release 内存序执行原子写入。
                if (op_count >= 2 && isArm64GpReg(ops[0].reg) && isArm64GpReg(ops[1].mem.base)) {
                    int32_t offset = static_cast<int32_t>(ops[1].mem.disp);
                    uint32_t value_reg_idx = (ops[0].reg == AARCH64_REG_WZR || ops[0].reg == AARCH64_REG_XZR)
                                             ? static_cast<uint32_t>(-1)
                                             : getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    const uint32_t type_idx = isArm64WReg(ops[0].reg)
                                              ? getOrAddTypeTag(type_id_list, TYPE_TAG_INT32_UNSIGNED)
                                              : getOrAddTypeTag(type_id_list, TYPE_TAG_INT64_SIGNED);
                    opcode_list = {
                        OP_ATOMIC_STORE,
                        type_idx,
                        getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].mem.base)),
                        static_cast<uint32_t>(offset),
                        value_reg_idx,
                        VM_MEM_ORDER_RELEASE
                    };
                }
                break;
            }

            // 独占 release 存储：STLXR -> OP_ATOMIC_STORE + status=0。
            case ARM64_INS_STLXR: {
                if (op_count >= 3 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG &&
                    ops[2].type == AARCH64_OP_MEM) {
                    (void)tryEmitAtomicStoreExclusiveLike(
                        opcode_list,
                        reg_id_list,
                        type_id_list,
                        ops[0].reg,
                        ops[1].reg,
                        ops[2].mem.base,
                        static_cast<int32_t>(ops[2].mem.disp),
                        VM_MEM_ORDER_RELEASE
                    );
                }
                break;
            }

            // 独占 relaxed 存储：STXR -> OP_ATOMIC_STORE + status=0。
            case ARM64_INS_STXR: {
                if (op_count >= 3 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_REG &&
                    ops[2].type == AARCH64_OP_MEM) {
                    (void)tryEmitAtomicStoreExclusiveLike(
                        opcode_list,
                        reg_id_list,
                        type_id_list,
                        ops[0].reg,
                        ops[1].reg,
                        ops[2].mem.base,
                        static_cast<int32_t>(ops[2].mem.disp),
                        VM_MEM_ORDER_RELAXED
                    );
                }
                break;
            }

            // 非扩展寻址读取：LDUR -> OP_GET_FIELD。
            case ARM64_INS_LDUR: {
                // LDUR：非扩展寻址的 load，映射为 OP_GET_FIELD。
                if (op_count >= 2 && ops[0].type == AARCH64_OP_REG && ops[1].type == AARCH64_OP_MEM) {
                    // 内存偏移可正可负，这里按带符号位移读取。
                    int32_t offset = static_cast<int32_t>(ops[1].mem.disp);
                    // OP_GET_FIELD 参数顺序：type/base/offset/dst。
                    opcode_list = {
                        OP_GET_FIELD,
                        getOrAddTypeTagForRegWidth(type_id_list, ops[0].reg),
                        getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].mem.base)),
                        static_cast<uint32_t>(offset),
                        getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg))
                    };
                }
                break;
            }

            // 独占 acquire 读取：LDAXR -> OP_ATOMIC_LOAD。
            case ARM64_INS_LDAXR: {
                if (op_count >= 2 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_MEM) {
                    (void)tryEmitAtomicLoadExclusiveLike(
                        opcode_list,
                        reg_id_list,
                        type_id_list,
                        ops[0].reg,
                        ops[1].mem.base,
                        static_cast<int32_t>(ops[1].mem.disp),
                        VM_MEM_ORDER_ACQUIRE
                    );
                }
                break;
            }

            // 独占 relaxed 读取：LDXR -> OP_ATOMIC_LOAD。
            case ARM64_INS_LDXR: {
                if (op_count >= 2 &&
                    ops[0].type == AARCH64_OP_REG &&
                    ops[1].type == AARCH64_OP_MEM) {
                    (void)tryEmitAtomicLoadExclusiveLike(
                        opcode_list,
                        reg_id_list,
                        type_id_list,
                        ops[0].reg,
                        ops[1].mem.base,
                        static_cast<int32_t>(ops[1].mem.disp),
                        VM_MEM_ORDER_RELAXED
                    );
                }
                break;
            }

            // 原子 acquire 字节读取：LDARB -> OP_ATOMIC_LOAD(type=INT8_UNSIGNED, order=ACQUIRE)。
            case ARM64_INS_LDARB: {
                // LDARB：按 acquire 内存序执行 8bit 原子读取。
                if (op_count >= 2 && isArm64GpReg(ops[0].reg) && isArm64GpReg(ops[1].mem.base)) {
                    int32_t offset = static_cast<int32_t>(ops[1].mem.disp);
                    opcode_list = {
                        OP_ATOMIC_LOAD,
                        getOrAddTypeTag(type_id_list, TYPE_TAG_INT8_UNSIGNED),
                        getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].mem.base)),
                        static_cast<uint32_t>(offset),
                        VM_MEM_ORDER_ACQUIRE,
                        getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg))
                    };
                }
                break;
            }

            // 原子 acquire 半字读取：LDARH -> OP_ATOMIC_LOAD(type=INT16_UNSIGNED, order=ACQUIRE)。
            case ARM64_INS_LDARH: {
                // LDARH：按 acquire 内存序执行 16bit 原子读取。
                if (op_count >= 2 && isArm64GpReg(ops[0].reg) && isArm64GpReg(ops[1].mem.base)) {
                    int32_t offset = static_cast<int32_t>(ops[1].mem.disp);
                    opcode_list = {
                        OP_ATOMIC_LOAD,
                        getOrAddTypeTag(type_id_list, TYPE_TAG_INT16_UNSIGNED),
                        getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].mem.base)),
                        static_cast<uint32_t>(offset),
                        VM_MEM_ORDER_ACQUIRE,
                        getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg))
                    };
                }
                break;
            }

            // 原子 acquire 字/双字读取：LDAR -> OP_ATOMIC_LOAD(type=reg-width, order=ACQUIRE)。
            case ARM64_INS_LDAR: {
                // LDAR：按 acquire 内存序执行原子读取。
                if (op_count >= 2 && isArm64GpReg(ops[0].reg) && isArm64GpReg(ops[1].mem.base)) {
                    int32_t offset = static_cast<int32_t>(ops[1].mem.disp);
                    const uint32_t type_idx = isArm64WReg(ops[0].reg)
                                              ? getOrAddTypeTag(type_id_list, TYPE_TAG_INT32_UNSIGNED)
                                              : getOrAddTypeTag(type_id_list, TYPE_TAG_INT64_SIGNED);
                    opcode_list = {
                        OP_ATOMIC_LOAD,
                        type_idx,
                        getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].mem.base)),
                        static_cast<uint32_t>(offset),
                        VM_MEM_ORDER_ACQUIRE,
                        getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg))
                    };
                }
                break;
            }

            // 非扩展寻址 8bit 读取：LDURB。
            case ARM64_INS_LDURB: {
                // LDURB：按 8bit 无符号类型读取。
                if (op_count >= 2 && ops[0].type == AARCH64_OP_REG && ops[1].type == AARCH64_OP_MEM) {
                    // 字节读取同样采用 base + disp 计算地址。
                    int32_t offset = static_cast<int32_t>(ops[1].mem.disp);
                    // 类型固定使用 TYPE_TAG_INT8_UNSIGNED。
                    opcode_list = {
                        OP_GET_FIELD,
                        getOrAddTypeTag(type_id_list, TYPE_TAG_INT8_UNSIGNED),
                        getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].mem.base)),
                        static_cast<uint32_t>(offset),
                        getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg))
                    };
                }
                break;
            }

            // 非扩展寻址 16bit 读取：LDURH。
            case ARM64_INS_LDURH: {
                // LDURH：按 16bit 无符号类型读取。
                if (op_count >= 2 && ops[0].type == AARCH64_OP_REG && ops[1].type == AARCH64_OP_MEM) {
                    int32_t offset = static_cast<int32_t>(ops[1].mem.disp);
                    opcode_list = {
                        OP_GET_FIELD,
                        getOrAddTypeTag(type_id_list, TYPE_TAG_INT16_UNSIGNED),
                        getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].mem.base)),
                        static_cast<uint32_t>(offset),
                        getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg))
                    };
                }
                break;
            }

            // 非扩展寻址有符号 32bit 读取并扩展到 64 位：LDURSW。
            case ARM64_INS_LDURSW:
            case ARM64_INS_ALIAS_LDURSW: {
                // LDURSW：与 LDRSW 语义一致，仅寻址编码不同（仍按 base+disp 处理）。
                if (op_count >= 2 && ops[0].type == AARCH64_OP_REG && ops[1].type == AARCH64_OP_MEM) {
                    int32_t offset = static_cast<int32_t>(ops[1].mem.disp);
                    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    uint32_t src_type_idx = getOrAddTypeTag(type_id_list, TYPE_TAG_INT32_SIGNED_2);
                    opcode_list = {
                        OP_GET_FIELD,
                        src_type_idx,
                        getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].mem.base)),
                        static_cast<uint32_t>(offset),
                        dst_idx
                    };
                    if (!isArm64WReg(ops[0].reg)) {
                        uint32_t dst_type_idx = getOrAddTypeTag(type_id_list, TYPE_TAG_INT64_SIGNED);
                        opcode_list.push_back(OP_SIGN_EXTEND);
                        opcode_list.push_back(src_type_idx);
                        opcode_list.push_back(dst_type_idx);
                        opcode_list.push_back(dst_idx);
                        opcode_list.push_back(dst_idx);
                    }
                }
                break;
            }

            // 有符号 8bit 读取：LDRSB。
            case ARM64_INS_LDRSB: {
                // LDRSB：按 int8 读取并符号扩展；目标是 w 寄存器时再做 32 位收口。
                if (op_count >= 2 && ops[0].type == AARCH64_OP_REG && ops[1].type == AARCH64_OP_MEM) {
                    int32_t offset = static_cast<int32_t>(ops[1].mem.disp);
                    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    opcode_list = {
                        OP_GET_FIELD,
                        getOrAddTypeTag(type_id_list, TYPE_TAG_INT8_SIGNED),
                        getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].mem.base)),
                        static_cast<uint32_t>(offset),
                        dst_idx
                    };
                    if (isArm64WReg(ops[0].reg)) {
                        opcode_list.push_back(OP_BINARY_IMM);
                        opcode_list.push_back(BIN_AND);
                        opcode_list.push_back(getOrAddTypeTag(type_id_list, TYPE_TAG_INT32_UNSIGNED));
                        opcode_list.push_back(dst_idx);
                        opcode_list.push_back(0xFFFFFFFFu);
                        opcode_list.push_back(dst_idx);
                    }
                }
                break;
            }

            // 有符号 16bit 读取：LDRSH。
            case ARM64_INS_LDRSH: {
                // LDRSH：按 int16 读取并符号扩展；目标是 w 寄存器时再做 32 位收口。
                if (op_count >= 2 && ops[0].type == AARCH64_OP_REG && ops[1].type == AARCH64_OP_MEM) {
                    int32_t offset = static_cast<int32_t>(ops[1].mem.disp);
                    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    opcode_list = {
                        OP_GET_FIELD,
                        getOrAddTypeTag(type_id_list, TYPE_TAG_INT16_SIGNED),
                        getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].mem.base)),
                        static_cast<uint32_t>(offset),
                        dst_idx
                    };
                    if (isArm64WReg(ops[0].reg)) {
                        opcode_list.push_back(OP_BINARY_IMM);
                        opcode_list.push_back(BIN_AND);
                        opcode_list.push_back(getOrAddTypeTag(type_id_list, TYPE_TAG_INT32_UNSIGNED));
                        opcode_list.push_back(dst_idx);
                        opcode_list.push_back(0xFFFFFFFFu);
                        opcode_list.push_back(dst_idx);
                    }
                }
                break;
            }

            // 有符号 32bit 读取并扩展到 64 位：LDRSW。
            case ARM64_INS_LDRSW: {
                // LDRSW：先以 int32 读取，再在 x 目标寄存器路径做显式符号扩展。
                if (op_count >= 2 && ops[0].type == AARCH64_OP_REG && ops[1].type == AARCH64_OP_MEM) {
                    int32_t offset = static_cast<int32_t>(ops[1].mem.disp);
                    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    uint32_t src_type_idx = getOrAddTypeTag(type_id_list, TYPE_TAG_INT32_SIGNED_2);
                    opcode_list = {
                        OP_GET_FIELD,
                        src_type_idx,
                        getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].mem.base)),
                        static_cast<uint32_t>(offset),
                        dst_idx
                    };
                    if (!isArm64WReg(ops[0].reg)) {
                        // x 目标需要把低 32 位有符号值扩展为 64 位。
                        uint32_t dst_type_idx = getOrAddTypeTag(type_id_list, TYPE_TAG_INT64_SIGNED);
                        opcode_list.push_back(OP_SIGN_EXTEND);
                        opcode_list.push_back(src_type_idx);
                        opcode_list.push_back(dst_type_idx);
                        opcode_list.push_back(dst_idx);
                        opcode_list.push_back(dst_idx);
                    }
                }
                break;
            }
            // 扩展指令族：SXT*/UXT*。
        default:
            return false;
    }
    return true;
}
