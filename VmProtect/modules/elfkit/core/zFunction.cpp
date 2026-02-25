/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - 函数级翻译与编码实现，含指令解析、IR/VM 映射与导出。
 * - 加固链路位置：离线翻译核心。
 * - 输入：单个函数机器码。
 * - 输出：可供 VmEngine 执行的编码 payload。
 */
#include "zFunction.h"
#include "zLog.h"
// std::move / std::pair 等。
#include <utility>
// snprintf。
#include <cstdio>
// PRIu64/PRIx64。
#include <cinttypes>
// strcmp/memcpy。
#include <cstring>
// unique_ptr。
#include <memory>
// std::map。
#include <map>
// std::find 等。
#include <algorithm>
// back_inserter。
#include <iterator>
// isspace 等字符分类函数。
#include <cctype>
// strtoull。
#include <cstdlib>
// Capstone C API。
#include <capstone/capstone.h>
// AArch64 指令/操作数枚举。
#include <capstone/arm64.h>

namespace {
// 匿名命名空间：仅本编译单元可见的辅助常量与函数。

enum : uint32_t {
    // VM 指令主操作码定义（离线翻译输出使用）。
    OP_END = 0, OP_BINARY = 1, OP_TYPE_CONVERT = 2, OP_LOAD_CONST = 3, OP_STORE_CONST = 4,
    OP_GET_ELEMENT = 5, OP_ALLOC_RETURN = 6, OP_STORE = 7, OP_LOAD_CONST64 = 8, OP_NOP = 9,
    OP_COPY = 10, OP_GET_FIELD = 11, OP_CMP = 12, OP_SET_FIELD = 13, OP_RESTORE_REG = 14,
    OP_CALL = 15, OP_RETURN = 16, OP_BRANCH = 17, OP_BRANCH_IF = 18, OP_ALLOC_MEMORY = 19,
    OP_MOV = 20, OP_LOAD_IMM = 21, OP_DYNAMIC_CAST = 22, OP_UNARY = 23, OP_PHI = 24, OP_SELECT = 25,
    OP_MEMCPY = 26, OP_MEMSET = 27, OP_STRLEN = 28, OP_FETCH_NEXT = 29, OP_CALL_INDIRECT = 30,
    OP_SWITCH = 31, OP_GET_PTR = 32, OP_BITCAST = 33, OP_SIGN_EXTEND = 34, OP_ZERO_EXTEND = 35,
    OP_TRUNCATE = 36, OP_FLOAT_EXTEND = 37, OP_FLOAT_TRUNCATE = 38, OP_INT_TO_FLOAT = 39,
    OP_ARRAY_ELEM = 40, OP_FLOAT_TO_INT = 41, OP_READ = 42, OP_WRITE = 43, OP_LEA = 44,
    OP_ATOMIC_ADD = 45, OP_ATOMIC_SUB = 46, OP_ATOMIC_XCHG = 47, OP_ATOMIC_CAS = 48,
    OP_FENCE = 49, OP_UNREACHABLE = 50, OP_ALLOC_VSP = 51, OP_BINARY_IMM = 52,
    OP_BRANCH_IF_CC = 53, OP_SET_RETURN_PC = 54, OP_BL = 55, OP_ADRP = 56,
};

enum : uint32_t {
    // OP_BINARY / OP_BINARY_IMM 的子操作码定义。
    BIN_XOR = 0, BIN_SUB = 1, BIN_ASR = 2, BIN_DIV = 3, BIN_ADD = 4, BIN_OR = 5,
    BIN_MOD = 6, BIN_IDIV = 7, BIN_FMOD = 8, BIN_MUL = 9, BIN_LSR = 0xA, BIN_SHL = 0xB, BIN_AND = 0xC,
};

enum : uint32_t {
    // 运行时类型标签（当前仅使用少量整型标签）。
    TYPE_TAG_INT32_SIGNED_2 = 4,
    TYPE_TAG_INT8_UNSIGNED = 0x15,
    TYPE_TAG_INT64_SIGNED = 0xE,
};

struct zUnencodedBytecode {
    // 未编码中间表示：既可导出 txt/bin，也可作为翻译缓存。
    uint32_t registerCount = 0;
    std::vector<uint32_t> regList;
    uint32_t typeCount = 0;
    std::vector<uint32_t> typeTags;
    uint32_t initValueCount = 0;
    std::map<uint64_t, std::vector<uint32_t>> instByAddress;
    std::map<uint64_t, std::string> asmByAddress;
    uint32_t instCount = 0;
    uint32_t branchCount = 0;
    std::vector<uint32_t> branchWords;
    std::vector<uint64_t> branchAddrWords;
    bool translationOk = true;
    std::string translationError;
};

template<typename ... Args>
static std::string strFormat(const std::string& format, Args ... args) {
    // 两次 snprintf：第一次计算长度，第二次写入内容。
    int size_buf = std::snprintf(nullptr, 0, format.c_str(), args...) + 1;
    if (size_buf <= 0) return std::string();
    std::unique_ptr<char[]> buf(new(std::nothrow) char[size_buf]);
    if (!buf) return std::string();
    std::snprintf(buf.get(), static_cast<size_t>(size_buf), format.c_str(), args...);
    return std::string(buf.get(), buf.get() + size_buf - 1);
}

static uint32_t arm64CapstoneToArchIndex(unsigned int reg) {
    // 把 Capstone 寄存器枚举映射到 VM 侧统一索引。
    if (reg == AARCH64_REG_SP || reg == AARCH64_REG_WSP) return 31;
    if (reg == AARCH64_REG_FP || reg == AARCH64_REG_X29) return 29;
    if (reg == AARCH64_REG_LR || reg == AARCH64_REG_X30) return 30;
    if (reg >= AARCH64_REG_W0 && reg <= AARCH64_REG_W30) return static_cast<uint32_t>(reg - AARCH64_REG_W0);
    if (reg >= AARCH64_REG_X0 && reg <= AARCH64_REG_X28) return static_cast<uint32_t>(reg - AARCH64_REG_X0);
    return 0;
}

static uint32_t getOrAddReg(std::vector<uint32_t>& reg_id_list, uint32_t reg) {
    // 返回寄存器在 reg_id_list 中的索引，不存在则追加。
    for (size_t k = 0; k < reg_id_list.size(); k++) {
        if (reg_id_list[k] == reg) return static_cast<uint32_t>(k);
    }
    reg_id_list.push_back(reg);
    return static_cast<uint32_t>(reg_id_list.size() - 1);
}

static bool isArm64WReg(unsigned int reg) {
    // 判断是否 32 位通用寄存器（w0-w30/wsp/wzr）。
    return (reg >= AARCH64_REG_W0 && reg <= AARCH64_REG_W30) ||
           reg == AARCH64_REG_WSP || reg == AARCH64_REG_WZR;
}

static bool isArm64GpReg(unsigned int reg) {
    // 判断是否通用寄存器（含 sp/fp/lr/零寄存器）。
    if (reg == AARCH64_REG_SP || reg == AARCH64_REG_WSP ||
        reg == AARCH64_REG_FP || reg == AARCH64_REG_X29 ||
        reg == AARCH64_REG_LR || reg == AARCH64_REG_X30 ||
        reg == AARCH64_REG_WZR || reg == AARCH64_REG_XZR) {
        return true;
    }
    return (reg >= AARCH64_REG_W0 && reg <= AARCH64_REG_W30) ||
           (reg >= AARCH64_REG_X0 && reg <= AARCH64_REG_X28);
}

// 统一判断 ARM64 的零寄存器（wzr/xzr）。
static bool isArm64ZeroReg(unsigned int reg) {
    return reg == AARCH64_REG_WZR || reg == AARCH64_REG_XZR;
}

// 根据立即数宽度生成 OP_LOAD_IMM / OP_LOAD_CONST64。
static void emitLoadImm(std::vector<uint32_t>& opcode_list, uint32_t dst_idx, uint64_t imm) {
    if (imm <= 0xFFFFFFFFull) {
        // 32 位可表达：直接走 OP_LOAD_IMM，字数更短。
        opcode_list = { OP_LOAD_IMM, dst_idx, static_cast<uint32_t>(imm) };
    } else {
        // 超过 32 位：拆成低/高 32 位写入 OP_LOAD_CONST64。
        opcode_list = { OP_LOAD_CONST64, dst_idx,
                        static_cast<uint32_t>(imm & 0xFFFFFFFFull),
                        static_cast<uint32_t>((imm >> 32) & 0xFFFFFFFFull) };
    }
}

static bool tryEmitMovLike(
    std::vector<uint32_t>& opcode_list,
    std::vector<uint32_t>& reg_id_list,
    unsigned int dst_reg,
    const cs_arm64_op& src_op
) {
    // 统一处理 mov/orr alias 等“搬运”语义指令。
    if (!isArm64GpReg(dst_reg) || dst_reg == AARCH64_REG_WZR || dst_reg == AARCH64_REG_XZR) {
        // 目标不是可写通用寄存器时直接拒绝翻译。
        return false;
    }

    // 先拿到目标寄存器在 VM 寄存器表中的索引。
    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(dst_reg));
    if (src_op.type == AARCH64_OP_REG) {
        if (!isArm64GpReg(src_op.reg)) {
            // 源寄存器不是通用寄存器，当前不处理。
            return false;
        }
        if (src_op.reg == AARCH64_REG_WZR || src_op.reg == AARCH64_REG_XZR) {
            // mov dst, wzr/xzr -> dst = 0。
            opcode_list = { OP_LOAD_IMM, dst_idx, 0 };
            return true;
        }
        // 普通寄存器搬运。
        uint32_t src_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(src_op.reg));
        opcode_list = { OP_MOV, src_idx, dst_idx };
        return true;
    }
    if (src_op.type == AARCH64_OP_IMM) {
        // 立即数路径：支持 LSL 移位并按目标寄存器宽度截断。
        uint64_t imm = static_cast<uint64_t>(src_op.imm);
        if (src_op.shift.type == AARCH64_SFT_LSL && src_op.shift.value != 0) {
            // 立即数带 LSL 时在离线翻译阶段预先折叠。
            imm <<= src_op.shift.value;
        }
        if (isArm64WReg(dst_reg)) {
            // 写入 w 寄存器时截断到低 32 位。
            imm &= 0xFFFFFFFFull;
        }
        emitLoadImm(opcode_list, dst_idx, imm);
        return !opcode_list.empty();
    }
    return false;
}

// 追加“dst = src”语义，兼容 src 为 wzr/xzr 的零值写入。
static bool appendAssignRegOrZero(
    std::vector<uint32_t>& opcode_list,
    std::vector<uint32_t>& reg_id_list,
    unsigned int dst_reg,
    unsigned int src_reg
) {
    if (!isArm64GpReg(dst_reg) || isArm64ZeroReg(dst_reg)) {
        // 目标必须是可写通用寄存器，不能是零寄存器。
        return false;
    }
    if (!isArm64GpReg(src_reg)) {
        // 源必须是通用寄存器。
        return false;
    }

    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(dst_reg));
    if (isArm64ZeroReg(src_reg)) {
        // src 为 wzr/xzr 时，降级为显式加载 0。
        opcode_list.push_back(OP_LOAD_IMM);
        opcode_list.push_back(dst_idx);
        opcode_list.push_back(0);
        return true;
    }

    uint32_t src_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(src_reg));
    // 常规寄存器赋值走 OP_MOV。
    opcode_list.push_back(OP_MOV);
    opcode_list.push_back(src_idx);
    opcode_list.push_back(dst_idx);
    return true;
}

static uint32_t getOrAddTypeTag(std::vector<uint32_t>& type_id_list, uint32_t type_tag) {
    // 返回类型标签在 type_id_list 中的索引，不存在则追加。
    for (size_t k = 0; k < type_id_list.size(); k++) {
        if (type_id_list[k] == type_tag) return static_cast<uint32_t>(k);
    }
    type_id_list.push_back(type_tag);
    return static_cast<uint32_t>(type_id_list.size() - 1);
}

static uint32_t getOrAddTypeTagForRegWidth(std::vector<uint32_t>& type_id_list, unsigned int reg) {
    // 32 位寄存器映射到 int32 标签，其余走 int64 标签。
    const bool is_wide32 = isArm64WReg(reg);
    return getOrAddTypeTag(type_id_list, is_wide32 ? TYPE_TAG_INT32_SIGNED_2 : TYPE_TAG_INT64_SIGNED);
}

static uint32_t getOrAddBranch(std::vector<uint64_t>& branch_id_list, uint64_t target_arm_addr) {
    // 分支目标地址去重并返回索引，供 OP_BRANCH/OP_BRANCH_IF_CC 复用。
    for (size_t k = 0; k < branch_id_list.size(); k++) {
        if (branch_id_list[k] == target_arm_addr) return static_cast<uint32_t>(k);
    }
    branch_id_list.push_back(target_arm_addr);
    return static_cast<uint32_t>(branch_id_list.size() - 1);
}

static zUnencodedBytecode buildUnencodedByCapstone(csh handle, const uint8_t* code, size_t size, uint64_t base_addr) {
    // Capstone 翻译主流程：
    // ARM64 指令流 -> 未编码 VM opcode（按地址分组）。
    zUnencodedBytecode unencoded;
    // initValueCount 当前固定为 0，保留字段以兼容旧格式。
    unencoded.initValueCount = 0;
    // 分支统计/表项初始化为 0。
    unencoded.branchCount = 0;
    unencoded.branchWords.clear();
    unencoded.branchAddrWords.clear();

    std::vector<uint32_t> reg_id_list;
    std::vector<uint32_t> type_id_list;

    // 打开 Capstone 详细模式，后续依赖操作数信息做指令映射。
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_insn* insn = nullptr;
    // 第四个参数传 0 表示“尽可能反汇编到末尾”。
    size_t count = cs_disasm(handle, code, size, base_addr, 0, &insn);
    if (count == 0 || !insn) {
        unencoded.translationOk = false;
        unencoded.translationError = "capstone disasm failed";
        return unencoded;
    }

    for (int i = 0; i < 31; i++) {
        // 预放入 x0..x30，保证后续索引稳定。
        reg_id_list.push_back(static_cast<uint32_t>(i));
    }

    // 在指令流头部插入运行时约定的初始化指令。
    (void)getOrAddReg(reg_id_list, 0);
    unencoded.instByAddress[0] = { OP_ALLOC_RETURN, 0, 0, 0, 0 };

    uint32_t vfp_idx = getOrAddReg(reg_id_list, 29);
    uint32_t vsp_idx = getOrAddReg(reg_id_list, 31);
    unencoded.instByAddress[1] = { OP_ALLOC_VSP, 0, 0, 0, vfp_idx, vsp_idx };

    // 本地跳转目标表：仅供 OP_BRANCH/OP_BRANCH_IF_CC 使用。
    std::vector<uint64_t> branch_id_list;
    // 调用目标表：仅供 OP_BL 使用，导出阶段会统一 remap 到共享 branch_addr_list。
    std::vector<uint64_t> call_target_list;
    bool translation_aborted = false;

    // 遍历反汇编结果，把 ARM64 指令翻译成 VM opcode 序列。
    for (size_t j = 0; j < count; j++) {
        // 当前 ARM 指令地址（用于最终映射到 instByAddress）。
        uint64_t addr = insn[j].address;
        // Capstone 指令 ID（主分派依据）。
        unsigned int id = insn[j].id;
        // 详细信息包含操作数与条件码等扩展字段。
        cs_detail* detail = insn[j].detail;
        uint8_t op_count = detail ? detail->aarch64.op_count : 0;
        cs_arm64_op* ops = detail ? reinterpret_cast<cs_arm64_op*>(detail->aarch64.operands) : nullptr;
        // 这条 ARM 指令映射得到的 VM opcode 序列。
        std::vector<uint32_t> opcode_list;
        // 默认认为 instruction id 可识别，若落入 default 则会改为 false。
        bool instruction_id_handled = true;

        switch (id) {
            // 算术类：SUB -> OP_BINARY/OP_BINARY_IMM(BIN_SUB)。
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
            // 读取类：LDR -> OP_GET_FIELD。
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
            // 算术类：ADD -> OP_BINARY/OP_BINARY_IMM(BIN_ADD)。
            case ARM64_INS_ADD: {
                // ADD: dst = lhs + rhs/imm
                if (op_count >= 3 && ops[0].type == AARCH64_OP_REG && ops[1].type == AARCH64_OP_REG) {
                    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    uint32_t lhs_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].reg));
                    if (ops[2].type == AARCH64_OP_IMM) {
                        // 立即数加法。
                        uint32_t imm = static_cast<uint32_t>(ops[2].imm);
                        opcode_list = { OP_BINARY_IMM, BIN_ADD, getOrAddTypeTag(type_id_list, TYPE_TAG_INT64_SIGNED), lhs_idx, imm, dst_idx };
                    } else if (ops[2].type == AARCH64_OP_REG) {
                        // 寄存器加法。
                        uint32_t rhs_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[2].reg));
                        opcode_list = { OP_BINARY, BIN_ADD, getOrAddTypeTag(type_id_list, TYPE_TAG_INT32_SIGNED_2), lhs_idx, rhs_idx, dst_idx };
                    }
                }
                break;
            }
            case ARM64_INS_LSL:
            case ARM64_INS_LSLR:
            case ARM64_INS_ALIAS_LSL: {
                // 统一处理左移：支持寄存器移位与立即数移位两种形态。
                if (op_count >= 2 && ops[0].type == AARCH64_OP_REG && ops[1].type == AARCH64_OP_REG) {
                    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                    uint32_t lhs_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].reg));
                    uint32_t type_idx = getOrAddTypeTag(type_id_list, TYPE_TAG_INT64_SIGNED);
                    if (op_count >= 3) {
                        if (ops[2].type == AARCH64_OP_IMM) {
                            // 显式立即数移位。
                            opcode_list = {
                                OP_BINARY_IMM,
                                BIN_SHL,
                                type_idx,
                                lhs_idx,
                                static_cast<uint32_t>(ops[2].imm),
                                dst_idx
                            };
                        } else if (ops[2].type == AARCH64_OP_REG) {
                            // 寄存器移位。
                            uint32_t rhs_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[2].reg));
                            opcode_list = { OP_BINARY, BIN_SHL, type_idx, lhs_idx, rhs_idx, dst_idx };
                        }
                    } else if (ops[1].shift.type == AARCH64_SFT_LSL) {
                        // 部分反汇编会把移位信息挂在第二操作数的 shift 字段。
                        opcode_list = {
                            OP_BINARY_IMM,
                            BIN_SHL,
                            type_idx,
                            lhs_idx,
                            static_cast<uint32_t>(ops[1].shift.value),
                            dst_idx
                        };
                    }
                }
                break;
            }
            // 搬运类：MOV/别名 -> tryEmitMovLike。
            case ARM64_INS_MOV: {
                // mov（含别名形态）统一交给 tryEmitMovLike 处理。
                if (op_count >= 2 && ops && ops[0].type == AARCH64_OP_REG) {
                    (void)tryEmitMovLike(opcode_list, reg_id_list, ops[0].reg, ops[1]);
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
            // 位段写入类：MOVK 通过 AND/OR 组合实现片段覆盖。
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
                if (op_count >= 3 && ops[0].type == AARCH64_OP_REG && ops[1].type == AARCH64_OP_REG) {
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
            case ARM64_INS_RET:
                // 约定 ret 返回 x0。
                // OP_RETURN 布局：{opcode, ret_count, ret_reg...}。
                opcode_list = { OP_RETURN, 1, getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(AARCH64_REG_X0)) };
                break;
            case ARM64_INS_BR:
                // br lr 视为 ret，同样返回 x0。
                if (op_count >= 1 && ops[0].type == AARCH64_OP_REG && (ops[0].reg == AARCH64_REG_LR || ops[0].reg == AARCH64_REG_X30)) {
                    opcode_list = { OP_RETURN, 1, getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(AARCH64_REG_X0)) };
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
            case ARM64_INS_SUBS: {
                // SUBS：与 SUB 类似，但需要更新条件标志。
                static const uint32_t BIN_UPDATE_FLAGS = 0x40u;
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
            // 成对存储：STP 拆成两条 OP_SET_FIELD。
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
            // 直接调用：BL 先记录目标地址，导出阶段统一 remap。
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
            default:
                instruction_id_handled = false;
                // 某些 capstone 版本会把 LSL 记为不同 ID，但 mnemonic 仍是 lsl。
                if (insn[j].mnemonic && std::strcmp(insn[j].mnemonic, "lsl") == 0) {
                    // 这里和 ARM64_INS_LSL 分支保持同构，避免版本差异导致漏翻译。
                    if (op_count >= 2 && ops[0].type == AARCH64_OP_REG && ops[1].type == AARCH64_OP_REG) {
                        // 目标与左值寄存器索引。
                        uint32_t dst_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
                        uint32_t lhs_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].reg));
                        // LSL 统一按 64 位整型标签编码。
                        uint32_t type_idx = getOrAddTypeTag(type_id_list, TYPE_TAG_INT64_SIGNED);
                        if (op_count >= 3) {
                            if (ops[2].type == AARCH64_OP_IMM) {
                                // lsl dst, lhs, #imm。
                                opcode_list = {
                                    OP_BINARY_IMM,
                                    BIN_SHL,
                                    type_idx,
                                    lhs_idx,
                                    static_cast<uint32_t>(ops[2].imm),
                                    dst_idx
                                };
                            } else if (ops[2].type == AARCH64_OP_REG) {
                                // lsl dst, lhs, rhs。
                                // 寄存器位移量由 rhs 在运行时给出。
                                uint32_t rhs_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[2].reg));
                                opcode_list = { OP_BINARY, BIN_SHL, type_idx, lhs_idx, rhs_idx, dst_idx };
                            }
                        } else if (ops[1].shift.type == AARCH64_SFT_LSL) {
                            // lsl alias 场景：移位量挂在第二操作数 shift 字段。
                            opcode_list = {
                                OP_BINARY_IMM,
                                BIN_SHL,
                                type_idx,
                                lhs_idx,
                                static_cast<uint32_t>(ops[1].shift.value),
                                dst_idx
                            };
                        }
                        // 只要成功翻译出 opcode，即视为已处理。
                        if (!opcode_list.empty()) {
                            instruction_id_handled = true;
                            break;
                        }
                    }
                }
                break;
        }

        // 兼容 Capstone 把 mov 归类为其它指令 ID（例如 orr alias）的情况。
        if (opcode_list.empty() &&
            op_count >= 2 && ops &&
            insn[j].mnemonic &&
            std::strcmp(insn[j].mnemonic, "mov") == 0 &&
            ops[0].type == AARCH64_OP_REG) {
            (void)tryEmitMovLike(opcode_list, reg_id_list, ops[0].reg, ops[1]);
        }

        // 兼容 Capstone 把 mul/and/ldrsw 归类到其它指令 ID 或 alias 的情况。
        if (opcode_list.empty() &&
            op_count >= 3 && ops &&
            insn[j].mnemonic &&
            std::strcmp(insn[j].mnemonic, "mul") == 0 &&
            ops[0].type == AARCH64_OP_REG &&
            ops[1].type == AARCH64_OP_REG &&
            ops[2].type == AARCH64_OP_REG) {
            // mul mnemonic fallback：统一映射为 BIN_MUL。
            uint32_t dst_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
            uint32_t lhs_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].reg));
            uint32_t rhs_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[2].reg));
            uint32_t type_idx = getOrAddTypeTagForRegWidth(type_id_list, ops[0].reg);
            opcode_list = { OP_BINARY, BIN_MUL, type_idx, lhs_idx, rhs_idx, dst_idx };
        }

        // 当 switch(id) 未产出翻译时，尝试按 mnemonic 再做一层兼容兜底。
        if (opcode_list.empty() &&
            op_count >= 3 && ops &&
            insn[j].mnemonic &&
            std::strcmp(insn[j].mnemonic, "and") == 0 &&
            ops[0].type == AARCH64_OP_REG &&
            ops[1].type == AARCH64_OP_REG) {
            // and mnemonic fallback：兜底兼容不同 capstone 指令 ID 分类。
            uint32_t dst_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg));
            uint32_t lhs_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].reg));
            uint32_t type_idx = getOrAddTypeTagForRegWidth(type_id_list, ops[0].reg);
            // 第三操作数为寄存器时生成 OP_BINARY。
            if (ops[2].type == AARCH64_OP_REG) {
                uint32_t rhs_idx = getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[2].reg));
                opcode_list = { OP_BINARY, BIN_AND, type_idx, lhs_idx, rhs_idx, dst_idx };
            // 第三操作数为立即数时生成 OP_BINARY_IMM。
            } else if (ops[2].type == AARCH64_OP_IMM) {
                uint32_t imm = static_cast<uint32_t>(ops[2].imm);
                opcode_list = { OP_BINARY_IMM, BIN_AND, type_idx, lhs_idx, imm, dst_idx };
            }
        }

        // ldrsw 兼容路径：某些版本不通过 ARM64_INS_LDRSW 分支命中。
        if (opcode_list.empty() &&
            op_count >= 2 && ops &&
            insn[j].mnemonic &&
            std::strcmp(insn[j].mnemonic, "ldrsw") == 0 &&
            ops[0].type == AARCH64_OP_REG &&
            ops[1].type == AARCH64_OP_MEM) {
            // ldrsw fallback：按 32 位有符号值读取，再由目标寄存器解释宽度。
            // 地址计算规则：base + disp。
            int32_t offset = static_cast<int32_t>(ops[1].mem.disp);
            opcode_list = {
                OP_GET_FIELD,
                getOrAddTypeTag(type_id_list, TYPE_TAG_INT32_SIGNED_2),
                getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].mem.base)),
                static_cast<uint32_t>(offset),
                getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg))
            };
        }

        // ldursw 兼容路径：与 ldrsw 同语义，不同寻址编码。
        if (opcode_list.empty() &&
            op_count >= 2 && ops &&
            insn[j].mnemonic &&
            std::strcmp(insn[j].mnemonic, "ldursw") == 0 &&
            ops[0].type == AARCH64_OP_REG &&
            ops[1].type == AARCH64_OP_MEM) {
            // ldursw fallback：与 ldrsw 类似，仅寻址模式不同。
            // 地址计算规则同样是 base + disp。
            int32_t offset = static_cast<int32_t>(ops[1].mem.disp);
            opcode_list = {
                OP_GET_FIELD,
                getOrAddTypeTag(type_id_list, TYPE_TAG_INT32_SIGNED_2),
                getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[1].mem.base)),
                static_cast<uint32_t>(offset),
                getOrAddReg(reg_id_list, arm64CapstoneToArchIndex(ops[0].reg))
            };
        }

        // csel 兼容路径：补偿“mnemonic 命中但 instruction id 未命中”的情况。
        if (opcode_list.empty() &&
            detail &&
            op_count >= 3 && ops &&
            insn[j].mnemonic &&
            std::strcmp(insn[j].mnemonic, "csel") == 0 &&
            ops[0].type == AARCH64_OP_REG &&
            ops[1].type == AARCH64_OP_REG &&
            ops[2].type == AARCH64_OP_REG) {
            // 兼容某些 Capstone 版本把 csel 归到其它 instruction id 的情况。
            // 读取 ARM64 条件码，后续直接透传给 OP_BRANCH_IF_CC。
            arm64_cc cc = detail->aarch64.cc;
            // next_addr 指向 csel 之后一条 ARM 指令地址，作为“跳过 false 赋值”的目标。
            const uint64_t next_addr = addr + (insn[j].size == 0 ? 4 : static_cast<uint64_t>(insn[j].size));
            // csel_ops 承载展开后的三段式 VM 片段。
            std::vector<uint32_t> csel_ops;
            switch (cc) {
                // 条件成立时：先赋 true，再条件跳过 false 赋值。
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
                    // csel dst, t, f, cc -> dst=t; if(cc) goto next; dst=f;
                    // 第一步：先写入 true 分支值（保持与硬件 csel 先验结果一致）。
                    if (appendAssignRegOrZero(csel_ops, reg_id_list, ops[0].reg, ops[1].reg)) {
                        // 第二步：注册跳转目标，并写入条件跳转 opcode。
                        uint32_t branch_id = getOrAddBranch(branch_id_list, next_addr);
                        csel_ops.push_back(OP_BRANCH_IF_CC);
                        csel_ops.push_back(static_cast<uint32_t>(cc));
                        csel_ops.push_back(branch_id);
                        // 第三步：条件不满足时覆盖为 false 分支值。
                        if (appendAssignRegOrZero(csel_ops, reg_id_list, ops[0].reg, ops[2].reg)) {
                            // 三段拼装完成后整体提交。
                            opcode_list = std::move(csel_ops);
                        }
                    }
                    break;
                }
                case ARM64_CC_AL:
                case ARM64_CC_INVALID: {
                    // AL/INVALID 退化为直接赋 true 分支值。
                    if (appendAssignRegOrZero(csel_ops, reg_id_list, ops[0].reg, ops[1].reg)) {
                        // 无条件分支不需要插入 OP_BRANCH_IF_CC。
                        opcode_list = std::move(csel_ops);
                    }
                    break;
                }
                default:
                    // 未支持条件码保持 opcode 为空，进入统一失败处理。
                    break;
            }
        }

        if (opcode_list.empty()) {
            // 空 opcode 代表本条指令无法翻译，立即失败并记录现场信息。
            // instruction_id_handled=true 表示“识别了指令，但操作数形态未覆盖”。
            const char* reason = instruction_id_handled
                                 ? "recognized instruction but operand pattern is not translated"
                                 : "unsupported instruction id";
            unencoded.translationOk = false;
            // 错误文本包含地址、mnemonic、操作数字符串与失败原因，便于离线排查。
            unencoded.translationError = strFormat(
                "translate failed at 0x%" PRIx64 ": %s %s (%s, op_count=%u)",
                addr,
                insn[j].mnemonic ? insn[j].mnemonic : "",
                insn[j].op_str ? insn[j].op_str : "",
                reason,
                static_cast<unsigned>(op_count)
            );
            LOGE("%s", unencoded.translationError.c_str());
            // 出错即中止整段翻译，避免生成半有效字节码。
            translation_aborted = true;
            break;
        }

        // 保存翻译结果。
        unencoded.instByAddress[addr] = std::move(opcode_list);
        // 同步保存可读反汇编文本，便于后续 dump/诊断。
        std::string asm_line(insn[j].mnemonic ? insn[j].mnemonic : "");
        // 如果存在操作数字符串，则拼成 "mnemonic op_str" 形式。
        if (insn[j].op_str && insn[j].op_str[0] != '\0') {
            asm_line += ' ';
            asm_line += insn[j].op_str;
        }
        // 与 instByAddress 使用同一地址键，确保可一一对照。
        unencoded.asmByAddress[addr] = std::move(asm_line);
    }

    if (translation_aborted) {
        // 失败路径也要释放 Capstone 指令缓存。
        cs_free(insn, count);
        return unencoded;
    }

    std::map<uint64_t, uint32_t> addr_to_pc;
    uint32_t pc = 0;
    // 把“地址 -> 扁平 PC(word 下标)”预先建表。
    for (const auto& kv : unencoded.instByAddress) {
        // 当前地址对应的第一条 opcode word 下标。
        addr_to_pc[kv.first] = pc;
        // pc 累加本地址下 opcode 总字数。
        pc += static_cast<uint32_t>(kv.second.size());
    }

    // BL 目标地址列表直接落入 branchAddrWords（后续可 remap 为全局表）。
    unencoded.branchAddrWords = call_target_list;
    unencoded.branchWords.clear();
    // 本地 branch 目标地址转换为 VM PC。
    for (uint64_t arm_addr : branch_id_list) {
        auto it = addr_to_pc.find(arm_addr);
        // 找不到目标地址时写 0，交由后续校验或执行期处理。
        unencoded.branchWords.push_back(it != addr_to_pc.end() ? it->second : 0u);
    }
    unencoded.branchCount = static_cast<uint32_t>(unencoded.branchWords.size());

    cs_free(insn, count);

    unencoded.regList = std::move(reg_id_list);
    unencoded.registerCount = static_cast<uint32_t>(unencoded.regList.size());
    // 运行时执行器至少期望前四个参数寄存器槽存在。
    if (unencoded.registerCount < 4) unencoded.registerCount = 4;

    unencoded.typeTags = std::move(type_id_list);
    // typeCount 是运行时 type 表长度。
    unencoded.typeCount = static_cast<uint32_t>(unencoded.typeTags.size());

    unencoded.instCount = 0;
    for (const auto& kv : unencoded.instByAddress) {
        // instCount 统计的是“opcode word 数”，不是 ARM 指令条数。
        unencoded.instCount += static_cast<uint32_t>(kv.second.size());
    }

    return unencoded;
}

}

void zFunction::setUnencodedCache(
    uint32_t register_count,
    std::vector<uint32_t> reg_id_list,
    uint32_t type_count,
    std::vector<uint32_t> type_tags,
    uint32_t init_value_count,
    std::map<uint64_t, std::vector<uint32_t>> inst_by_address,
    std::map<uint64_t, std::string> asm_by_address,
    uint32_t inst_count,
    uint32_t branch_count,
    std::vector<uint32_t> branch_words,
    std::vector<uint64_t> branch_addr_words
) const {
    // 统一缓存入口：文本导入和 capstone 导出都复用这份缓存结构。
    // 下面成员赋值按“计数 -> 列表 -> 映射 -> 状态位”顺序组织，便于排查。
    register_count_cache_ = register_count;
    register_ids_cache_ = std::move(reg_id_list);
    type_count_cache_ = type_count;
    type_tags_cache_ = std::move(type_tags);
    init_value_count_cache_ = init_value_count;
    inst_words_by_addr_cache_ = std::move(inst_by_address);
    asm_text_by_addr_cache_ = std::move(asm_by_address);
    inst_count_cache_ = inst_count;
    branch_count_cache_ = branch_count;
    branch_words_cache_ = std::move(branch_words);
    branch_addrs_cache_ = std::move(branch_addr_words);
    unencoded_translate_ok_ = true;
    unencoded_translate_error_.clear();
    unencoded_ready_ = true;
}

// 确保未编码缓存可用：优先复用缓存，缺失时再由机器码反推。
void zFunction::ensureUnencodedReady() const {
    // 已有缓存则直接复用。
    if (unencoded_ready_) return;

    // 没有原始机器码时，写入空缓存，避免后续重复判空分支。
    if (!data() || size() == 0) {
        // 空函数不进入 Capstone，直接标记失败并缓存空结构。
        setUnencodedCache(0, {}, 0, {}, 0, {}, {}, 0, 0, {}, {});
        unencoded_translate_ok_ = false;
        unencoded_translate_error_ = "function bytes are empty";
        return;
    }

    // 初始化 Capstone 句柄。
    csh handle = 0;
    if (cs_open(CS_ARCH_AARCH64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        // Capstone 初始化失败时同样设置空缓存，保证后续访问稳定。
        setUnencodedCache(0, {}, 0, {}, 0, {}, {}, 0, 0, {}, {});
        unencoded_translate_ok_ = false;
        unencoded_translate_error_ = "capstone cs_open failed";
        return;
    }

    // 由机器码翻译出中间结构。
    zUnencodedBytecode unencoded = buildUnencodedByCapstone(handle, data(), size(), offset());
    // 翻译后立即关闭句柄，避免资源泄漏。
    cs_close(&handle);

    // 翻译失败时仍写入空缓存，确保对象状态自洽。
    if (!unencoded.translationOk) {
        // 失败路径写空缓存，避免调用方读到半成品字段。
        setUnencodedCache(0, {}, 0, {}, 0, {}, {}, 0, 0, {}, {});
        unencoded_translate_ok_ = false;
        unencoded_translate_error_ = unencoded.translationError.empty()
                                     ? "capstone translation failed"
                                     : unencoded.translationError;
        LOGE("ensureUnencodedReady failed for %s: %s",
             function_name.c_str(),
             unencoded_translate_error_.c_str());
        return;
    }

    // 解析完成后一次性更新缓存。
    setUnencodedCache(
            // 寄存器总数。
            unencoded.registerCount,
            // 寄存器索引表。
            std::move(unencoded.regList),
            // 类型数量。
            unencoded.typeCount,
            // 类型标签表。
            std::move(unencoded.typeTags),
            // 初始化值数量（当前固定 0）。
            unencoded.initValueCount,
            // 地址 -> opcode words。
            std::move(unencoded.instByAddress),
            // 地址 -> asm 文本。
            std::move(unencoded.asmByAddress),
            // opcode 总字数。
            unencoded.instCount,
            // 本地分支数量。
            unencoded.branchCount,
            // 本地分支 pc 索引表。
            std::move(unencoded.branchWords),
            // BL 目标地址表。
            std::move(unencoded.branchAddrWords)
    );
}
