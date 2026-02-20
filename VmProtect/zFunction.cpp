#include "zFunction.h"
#include "zLog.h"
#include <utility>
#include <sstream>
#include <fstream>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <memory>
#include <map>
#include <algorithm>
#include <iterator>
#include <cctype>
#include <cstdlib>
#include <unordered_map>
#include <capstone/capstone.h>
#include <capstone/arm64.h>

namespace {

enum : uint32_t {
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
    BIN_XOR = 0, BIN_SUB = 1, BIN_ASR = 2, BIN_DIV = 3, BIN_ADD = 4, BIN_OR = 5,
    BIN_MOD = 6, BIN_IDIV = 7, BIN_FMOD = 8, BIN_MUL = 9, BIN_LSR = 0xA, BIN_SHL = 0xB, BIN_AND = 0xC,
};

enum : uint32_t {
    TYPE_TAG_INT32_SIGNED_2 = 4,
    TYPE_TAG_INT8_UNSIGNED = 0x15,
    TYPE_TAG_INT64_SIGNED = 0xE,
};

struct zUnencodedBytecode {
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

struct zUnencodedBinHeader {
    uint32_t magic = 0;
    uint32_t version = 0;
    uint32_t registerCount = 0;
    uint32_t regCount = 0;
    uint32_t typeCount = 0;
    uint32_t initValueCount = 0;
    uint32_t instLineCount = 0;
    uint32_t instCount = 0;
    uint32_t branchCount = 0;
    uint32_t branchAddrCount = 0;
};

static constexpr uint32_t Z_UNENCODED_BIN_MAGIC = 0x4642555A;
static constexpr uint32_t Z_UNENCODED_BIN_VERSION = 2;

static const char* getOpcodeName(uint32_t op) {
    switch (op) {
        case 0: return "OP_END";
        case 1: return "OP_BINARY";
        case 2: return "OP_TYPE_CONVERT";
        case 3: return "OP_LOAD_CONST";
        case 4: return "OP_STORE_CONST";
        case 5: return "OP_GET_ELEMENT";
        case 6: return "OP_ALLOC_RETURN";
        case 7: return "OP_STORE";
        case 8: return "OP_LOAD_CONST64";
        case 9: return "OP_NOP";
        case 10: return "OP_COPY";
        case 11: return "OP_GET_FIELD";
        case 12: return "OP_CMP";
        case 13: return "OP_SET_FIELD";
        case 14: return "OP_RESTORE_REG";
        case 15: return "OP_CALL";
        case 16: return "OP_RETURN";
        case 17: return "OP_BRANCH";
        case 18: return "OP_BRANCH_IF";
        case 19: return "OP_ALLOC_MEMORY";
        case 20: return "OP_MOV";
        case 21: return "OP_LOAD_IMM";
        case 22: return "OP_DYNAMIC_CAST";
        case 23: return "OP_UNARY";
        case 24: return "OP_PHI";
        case 25: return "OP_SELECT";
        case 26: return "OP_MEMCPY";
        case 27: return "OP_MEMSET";
        case 28: return "OP_STRLEN";
        case 29: return "OP_FETCH_NEXT";
        case 30: return "OP_CALL_INDIRECT";
        case 31: return "OP_SWITCH";
        case 32: return "OP_GET_PTR";
        case 33: return "OP_BITCAST";
        case 34: return "OP_SIGN_EXTEND";
        case 35: return "OP_ZERO_EXTEND";
        case 36: return "OP_TRUNCATE";
        case 37: return "OP_FLOAT_EXTEND";
        case 38: return "OP_FLOAT_TRUNCATE";
        case 39: return "OP_INT_TO_FLOAT";
        case 40: return "OP_ARRAY_ELEM";
        case 41: return "OP_FLOAT_TO_INT";
        case 42: return "OP_READ";
        case 43: return "OP_WRITE";
        case 44: return "OP_LEA";
        case 45: return "OP_ATOMIC_ADD";
        case 46: return "OP_ATOMIC_SUB";
        case 47: return "OP_ATOMIC_XCHG";
        case 48: return "OP_ATOMIC_CAS";
        case 49: return "OP_FENCE";
        case 50: return "OP_UNREACHABLE";
        case 51: return "OP_ALLOC_VSP";
        case 52: return "OP_BINARY_IMM";
        case 53: return "OP_BRANCH_IF_CC";
        case 54: return "OP_SET_RETURN_PC";
        case 55: return "OP_BL";
        case 56: return "OP_ADRP";
        default: return "OP_UNKNOWN";
    }
}

template<typename ... Args>
static std::string str_format(const std::string& format, Args ... args) {
    // 两次 snprintf：第一次计算长度，第二次写入内容。
    int size_buf = std::snprintf(nullptr, 0, format.c_str(), args...) + 1;
    if (size_buf <= 0) return std::string();
    std::unique_ptr<char[]> buf(new(std::nothrow) char[size_buf]);
    if (!buf) return std::string();
    std::snprintf(buf.get(), static_cast<size_t>(size_buf), format.c_str(), args...);
    return std::string(buf.get(), buf.get() + size_buf - 1);
}

static std::string formatOpcodeList(const std::vector<uint32_t>& opcode_list, bool trailing_comma = true) {
    // 导出文本时使用统一缩进，保证生成文件可读性稳定。
    std::string result = "        ";
    for (size_t i = 0; i < opcode_list.size(); i++) {
        if (i > 0) result += " ";
        result += std::to_string(opcode_list[i]);
        if (i + 1 < opcode_list.size()) result += ",";
    }
    if (trailing_comma && !opcode_list.empty()) result += ",";
    return result;
}

static std::string formatComment(const char* op_name, const char* asm_str, size_t op_name_width = 20) {
    // 形如：// OP_BINARY_IMM   0x1dd08: sub sp, sp, #0x20
    std::string result = "// ";
    result += op_name;

    if (asm_str && asm_str[0] != '\0') {
        size_t op_name_len = std::strlen(op_name);
        if (op_name_len < op_name_width) {
            result.append(op_name_width - op_name_len, ' ');
        }
        result += asm_str;
    }

    return result;
}

static std::string formatInstructionLine(
    const std::vector<uint32_t>& opcode_list,
    const char* op_name,
    const char* asm_str,
    size_t comment_column = 50,
    size_t op_name_width = 20
) {
    std::string line = formatOpcodeList(opcode_list, true);

    size_t current_len = line.length();
    if (current_len < comment_column) {
        line.append(comment_column - current_len, ' ');
    } else {
        line += "  ";
    }

    line += formatComment(op_name, asm_str, op_name_width);
    return line;
}

static uint32_t arm64_capstone_to_arch_index(unsigned int reg) {
    if (reg == ARM64_REG_SP || reg == ARM64_REG_WSP) return 31;
    if (reg == ARM64_REG_FP || reg == ARM64_REG_X29) return 29;
    if (reg == ARM64_REG_LR || reg == ARM64_REG_X30) return 30;
    if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) return static_cast<uint32_t>(reg - ARM64_REG_W0);
    if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28) return static_cast<uint32_t>(reg - ARM64_REG_X0);
    return 0;
}

static uint32_t getOrAddReg(std::vector<uint32_t>& reg_id_list, uint32_t reg) {
    for (size_t k = 0; k < reg_id_list.size(); k++) {
        if (reg_id_list[k] == reg) return static_cast<uint32_t>(k);
    }
    reg_id_list.push_back(reg);
    return static_cast<uint32_t>(reg_id_list.size() - 1);
}

static bool is_arm64_w_reg(unsigned int reg) {
    return (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) ||
           reg == ARM64_REG_WSP || reg == ARM64_REG_WZR;
}

static bool is_arm64_gp_reg(unsigned int reg) {
    if (reg == ARM64_REG_SP || reg == ARM64_REG_WSP ||
        reg == ARM64_REG_FP || reg == ARM64_REG_X29 ||
        reg == ARM64_REG_LR || reg == ARM64_REG_X30 ||
        reg == ARM64_REG_WZR || reg == ARM64_REG_XZR) {
        return true;
    }
    return (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) ||
           (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28);
}

// 统一判断 ARM64 的零寄存器（wzr/xzr）。
static bool is_arm64_zero_reg(unsigned int reg) {
    return reg == ARM64_REG_WZR || reg == ARM64_REG_XZR;
}

// 根据立即数宽度生成 OP_LOAD_IMM / OP_LOAD_CONST64。
static void emitLoadImm(std::vector<uint32_t>& opcode_list, uint32_t dst_idx, uint64_t imm) {
    if (imm <= 0xFFFFFFFFull) {
        opcode_list = { OP_LOAD_IMM, dst_idx, static_cast<uint32_t>(imm) };
    } else {
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
    if (!is_arm64_gp_reg(dst_reg) || dst_reg == ARM64_REG_WZR || dst_reg == ARM64_REG_XZR) {
        return false;
    }

    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(dst_reg));
    if (src_op.type == ARM64_OP_REG) {
        if (!is_arm64_gp_reg(src_op.reg)) {
            return false;
        }
        if (src_op.reg == ARM64_REG_WZR || src_op.reg == ARM64_REG_XZR) {
            opcode_list = { OP_LOAD_IMM, dst_idx, 0 };
            return true;
        }
        uint32_t src_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(src_op.reg));
        opcode_list = { OP_MOV, src_idx, dst_idx };
        return true;
    }
    if (src_op.type == ARM64_OP_IMM) {
        uint64_t imm = static_cast<uint64_t>(src_op.imm);
        if (src_op.shift.type == ARM64_SFT_LSL && src_op.shift.value != 0) {
            imm <<= src_op.shift.value;
        }
        if (is_arm64_w_reg(dst_reg)) {
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
    if (!is_arm64_gp_reg(dst_reg) || is_arm64_zero_reg(dst_reg)) {
        return false;
    }
    if (!is_arm64_gp_reg(src_reg)) {
        return false;
    }

    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(dst_reg));
    if (is_arm64_zero_reg(src_reg)) {
        opcode_list.push_back(OP_LOAD_IMM);
        opcode_list.push_back(dst_idx);
        opcode_list.push_back(0);
        return true;
    }

    uint32_t src_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(src_reg));
    opcode_list.push_back(OP_MOV);
    opcode_list.push_back(src_idx);
    opcode_list.push_back(dst_idx);
    return true;
}

static uint32_t getOrAddTypeTag(std::vector<uint32_t>& type_id_list, uint32_t type_tag) {
    for (size_t k = 0; k < type_id_list.size(); k++) {
        if (type_id_list[k] == type_tag) return static_cast<uint32_t>(k);
    }
    type_id_list.push_back(type_tag);
    return static_cast<uint32_t>(type_id_list.size() - 1);
}

static uint32_t getOrAddTypeTagForRegWidth(std::vector<uint32_t>& type_id_list, unsigned int reg) {
    const bool is_wide32 = is_arm64_w_reg(reg);
    return getOrAddTypeTag(type_id_list, is_wide32 ? TYPE_TAG_INT32_SIGNED_2 : TYPE_TAG_INT64_SIGNED);
}

static uint32_t getOrAddBranch(std::vector<uint64_t>& branch_id_list, uint64_t target_arm_addr) {
    for (size_t k = 0; k < branch_id_list.size(); k++) {
        if (branch_id_list[k] == target_arm_addr) return static_cast<uint32_t>(k);
    }
    branch_id_list.push_back(target_arm_addr);
    return static_cast<uint32_t>(branch_id_list.size() - 1);
}

static std::vector<uint32_t> flattenInstByAddress(const std::map<uint64_t, std::vector<uint32_t>>& instByAddress);
static uint64_t inferFunctionAddress(const zUnencodedBytecode& unencoded);

static bool buildEncodedDataFromUnencoded(const zUnencodedBytecode& unencoded, zFunctionData& out, std::string* error) {
    // 仅做字段映射与基础校验，不在这里执行额外语义推导。
    out = zFunctionData{};
    out.marker = 0;
    out.register_count = unencoded.registerCount;
    out.first_inst_count = 0;
    out.type_count = unencoded.typeCount;
    out.type_tags = unencoded.typeTags;
    out.init_value_count = unencoded.initValueCount;
    if (out.init_value_count != 0) {
        if (error) {
            *error = "init_value_count != 0 is not supported by current exporter";
        }
        return false;
    }
    out.inst_words = flattenInstByAddress(unencoded.instByAddress);
    out.inst_count = static_cast<uint32_t>(out.inst_words.size());
    out.branch_count = unencoded.branchCount;
    out.branch_words = unencoded.branchWords;
    out.branch_addrs = unencoded.branchAddrWords;
    out.function_offset = inferFunctionAddress(unencoded);
    return out.validate(error);
}

static zUnencodedBytecode buildUnencodedByCapstone(csh handle, const uint8_t* code, size_t size, uint64_t base_addr) {
    zUnencodedBytecode unencoded;
    unencoded.initValueCount = 0;
    unencoded.branchCount = 0;
    unencoded.branchWords.clear();
    unencoded.branchAddrWords.clear();

    std::vector<uint32_t> reg_id_list;
    std::vector<uint32_t> type_id_list;

    // 打开 Capstone 详细模式，后续依赖操作数信息做指令映射。
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_insn* insn = nullptr;
    size_t count = cs_disasm(handle, code, size, base_addr, 0, &insn);
    if (count == 0 || !insn) {
        unencoded.translationOk = false;
        unencoded.translationError = "capstone disasm failed";
        return unencoded;
    }

    for (int i = 0; i < 31; i++) {
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
        uint64_t addr = insn[j].address;
        unsigned int id = insn[j].id;
        cs_detail* detail = insn[j].detail;
        uint8_t op_count = detail ? detail->aarch64.op_count : 0;
        cs_arm64_op* ops = detail ? reinterpret_cast<cs_arm64_op*>(detail->aarch64.operands) : nullptr;
        std::vector<uint32_t> opcode_list;
        bool instruction_id_handled = true;

        switch (id) {
            case ARM64_INS_SUB: {
                if (op_count >= 3 && ops[0].type == ARM64_OP_REG && ops[1].type == ARM64_OP_REG) {
                    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[0].reg));
                    uint32_t lhs_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[1].reg));
                    if (ops[2].type == ARM64_OP_IMM) {
                        uint32_t imm = static_cast<uint32_t>(ops[2].imm);
                        opcode_list = { OP_BINARY_IMM, BIN_SUB, getOrAddTypeTag(type_id_list, TYPE_TAG_INT64_SIGNED), lhs_idx, imm, dst_idx };
                    } else if (ops[2].type == ARM64_OP_REG) {
                        uint32_t rhs_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[2].reg));
                        opcode_list = { OP_BINARY, BIN_SUB, getOrAddTypeTag(type_id_list, TYPE_TAG_INT64_SIGNED), lhs_idx, rhs_idx, dst_idx };
                    }
                }
                break;
            }
            case ARM64_INS_STR: {
                if (op_count >= 2 && ops[0].type == ARM64_OP_REG && ops[1].type == ARM64_OP_MEM) {
                    int32_t offset = static_cast<int32_t>(ops[1].mem.disp);
                    uint32_t value_reg_idx = (ops[0].reg == ARM64_REG_WZR || ops[0].reg == ARM64_REG_XZR)
                                             ? static_cast<uint32_t>(-1)
                                             : getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[0].reg));
                    opcode_list = {
                        OP_SET_FIELD,
                        getOrAddTypeTagForRegWidth(type_id_list, ops[0].reg),
                        getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[1].mem.base)),
                        static_cast<uint32_t>(offset),
                        value_reg_idx
                    };
                }
                break;
            }
            case ARM64_INS_STRB: {
                if (op_count >= 2 && ops[0].type == ARM64_OP_REG && ops[1].type == ARM64_OP_MEM) {
                    int32_t offset = static_cast<int32_t>(ops[1].mem.disp);
                    uint32_t value_reg_idx = (ops[0].reg == ARM64_REG_WZR || ops[0].reg == ARM64_REG_XZR)
                                             ? static_cast<uint32_t>(-1)
                                             : getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[0].reg));
                    opcode_list = {
                        OP_SET_FIELD,
                        getOrAddTypeTag(type_id_list, TYPE_TAG_INT8_UNSIGNED),
                        getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[1].mem.base)),
                        static_cast<uint32_t>(offset),
                        value_reg_idx
                    };
                }
                break;
            }
            case ARM64_INS_LDR: {
                if (op_count >= 2 && ops[0].type == ARM64_OP_REG && ops[1].type == ARM64_OP_MEM) {
                    int32_t offset = static_cast<int32_t>(ops[1].mem.disp);
                    opcode_list = {
                        OP_GET_FIELD,
                        getOrAddTypeTagForRegWidth(type_id_list, ops[0].reg),
                        getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[1].mem.base)),
                        static_cast<uint32_t>(offset),
                        getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[0].reg))
                    };
                }
                break;
            }
            case ARM64_INS_LDRB: {
                if (op_count >= 2 && ops[0].type == ARM64_OP_REG && ops[1].type == ARM64_OP_MEM) {
                    int32_t offset = static_cast<int32_t>(ops[1].mem.disp);
                    opcode_list = {
                        OP_GET_FIELD,
                        getOrAddTypeTag(type_id_list, TYPE_TAG_INT8_UNSIGNED),
                        getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[1].mem.base)),
                        static_cast<uint32_t>(offset),
                        getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[0].reg))
                    };
                }
                break;
            }
            case ARM64_INS_ADD: {
                if (op_count >= 3 && ops[0].type == ARM64_OP_REG && ops[1].type == ARM64_OP_REG) {
                    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[0].reg));
                    uint32_t lhs_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[1].reg));
                    if (ops[2].type == ARM64_OP_IMM) {
                        uint32_t imm = static_cast<uint32_t>(ops[2].imm);
                        opcode_list = { OP_BINARY_IMM, BIN_ADD, getOrAddTypeTag(type_id_list, TYPE_TAG_INT64_SIGNED), lhs_idx, imm, dst_idx };
                    } else if (ops[2].type == ARM64_OP_REG) {
                        uint32_t rhs_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[2].reg));
                        opcode_list = { OP_BINARY, BIN_ADD, getOrAddTypeTag(type_id_list, TYPE_TAG_INT32_SIGNED_2), lhs_idx, rhs_idx, dst_idx };
                    }
                }
                break;
            }
            case ARM64_INS_LSL:
            case ARM64_INS_LSLR:
            case ARM64_INS_ALIAS_LSL: {
                if (op_count >= 2 && ops[0].type == ARM64_OP_REG && ops[1].type == ARM64_OP_REG) {
                    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[0].reg));
                    uint32_t lhs_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[1].reg));
                    uint32_t type_idx = getOrAddTypeTag(type_id_list, TYPE_TAG_INT64_SIGNED);
                    if (op_count >= 3) {
                        if (ops[2].type == ARM64_OP_IMM) {
                            opcode_list = {
                                OP_BINARY_IMM,
                                BIN_SHL,
                                type_idx,
                                lhs_idx,
                                static_cast<uint32_t>(ops[2].imm),
                                dst_idx
                            };
                        } else if (ops[2].type == ARM64_OP_REG) {
                            uint32_t rhs_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[2].reg));
                            opcode_list = { OP_BINARY, BIN_SHL, type_idx, lhs_idx, rhs_idx, dst_idx };
                        }
                    } else if (ops[1].shift.type == ARM64_SFT_LSL) {
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
            case ARM64_INS_MOV: {
                if (op_count >= 2 && ops && ops[0].type == ARM64_OP_REG) {
                    (void)tryEmitMovLike(opcode_list, reg_id_list, ops[0].reg, ops[1]);
                }
                break;
            }
            case ARM64_INS_MOVZ:
            case ARM64_INS_MOVN: {
                if (op_count >= 2 && ops[0].type == ARM64_OP_REG && ops[1].type == ARM64_OP_IMM) {
                    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[0].reg));
                    uint64_t imm = static_cast<uint64_t>(ops[1].imm) & 0xFFFFull;
                    uint32_t shift = (ops[1].shift.type == ARM64_SFT_LSL) ? ops[1].shift.value : 0u;
                    uint64_t value = imm << shift;
                    if (id == ARM64_INS_MOVN) {
                        value = ~value;
                    }
                    if (is_arm64_w_reg(ops[0].reg)) {
                        value &= 0xFFFFFFFFull;
                    }
                    emitLoadImm(opcode_list, dst_idx, value);
                }
                break;
            }
            case ARM64_INS_MOVK: {
                if (op_count >= 2 && ops[0].type == ARM64_OP_REG && ops[1].type == ARM64_OP_IMM) {
                    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[0].reg));
                    uint64_t imm = static_cast<uint64_t>(ops[1].imm) & 0xFFFFull;
                    uint32_t shift = (ops[1].shift.type == ARM64_SFT_LSL) ? ops[1].shift.value : 0u;
                    uint64_t imm_val = imm << shift;
                    uint64_t mask = ~(0xFFFFull << shift);
                    if (is_arm64_w_reg(ops[0].reg)) {
                        imm_val &= 0xFFFFFFFFull;
                        mask &= 0xFFFFFFFFull;
                    }

                    uint32_t tmp1 = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ARM64_REG_X16));
                    uint32_t tmp2 = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ARM64_REG_X17));
                    uint32_t type_idx = getOrAddTypeTag(type_id_list, TYPE_TAG_INT64_SIGNED);

                    std::vector<uint32_t> temp;
                    emitLoadImm(temp, tmp1, mask);
                    opcode_list.insert(opcode_list.end(), temp.begin(), temp.end());
                    opcode_list.push_back(OP_BINARY);
                    opcode_list.push_back(BIN_AND);
                    opcode_list.push_back(type_idx);
                    opcode_list.push_back(dst_idx);
                    opcode_list.push_back(tmp1);
                    opcode_list.push_back(dst_idx);

                    temp.clear();
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
            case ARM64_INS_MUL: {
                if (op_count >= 3 &&
                    ops[0].type == ARM64_OP_REG &&
                    ops[1].type == ARM64_OP_REG &&
                    ops[2].type == ARM64_OP_REG) {
                    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[0].reg));
                    uint32_t lhs_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[1].reg));
                    uint32_t rhs_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[2].reg));
                    uint32_t type_idx = getOrAddTypeTagForRegWidth(type_id_list, ops[0].reg);
                    opcode_list = { OP_BINARY, BIN_MUL, type_idx, lhs_idx, rhs_idx, dst_idx };
                }
                break;
            }
            case ARM64_INS_AND:
            case ARM64_INS_ANDS: {
                static const uint32_t BIN_UPDATE_FLAGS = 0x40u;
                if (op_count >= 3 &&
                    ops[0].type == ARM64_OP_REG &&
                    ops[1].type == ARM64_OP_REG) {
                    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[0].reg));
                    uint32_t lhs_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[1].reg));
                    uint32_t op_code = BIN_AND | ((id == ARM64_INS_ANDS) ? BIN_UPDATE_FLAGS : 0u);
                    uint32_t type_idx = getOrAddTypeTagForRegWidth(type_id_list, ops[0].reg);
                    if (ops[2].type == ARM64_OP_REG) {
                        uint32_t rhs_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[2].reg));
                        opcode_list = { OP_BINARY, op_code, type_idx, lhs_idx, rhs_idx, dst_idx };
                    } else if (ops[2].type == ARM64_OP_IMM) {
                        uint32_t imm = static_cast<uint32_t>(ops[2].imm);
                        opcode_list = { OP_BINARY_IMM, op_code, type_idx, lhs_idx, imm, dst_idx };
                    }
                }
                break;
            }
            case ARM64_INS_ORR: {
                if (op_count >= 3 && ops[0].type == ARM64_OP_REG && ops[1].type == ARM64_OP_REG) {
                    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[0].reg));
                    uint32_t lhs_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[1].reg));
                    if (ops[2].type == ARM64_OP_REG) {
                        uint32_t rhs_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[2].reg));
                        if (ops[1].reg == ARM64_REG_WZR || ops[1].reg == ARM64_REG_XZR) {
                            opcode_list = { OP_MOV, rhs_idx, dst_idx };
                        } else if (ops[2].reg == ARM64_REG_WZR || ops[2].reg == ARM64_REG_XZR) {
                            opcode_list = { OP_MOV, lhs_idx, dst_idx };
                        } else {
                            opcode_list = { OP_BINARY, BIN_OR, getOrAddTypeTag(type_id_list, TYPE_TAG_INT64_SIGNED), lhs_idx, rhs_idx, dst_idx };
                        }
                    } else if (ops[2].type == ARM64_OP_IMM) {
                        uint32_t imm = static_cast<uint32_t>(ops[2].imm);
                        opcode_list = { OP_BINARY_IMM, BIN_OR, getOrAddTypeTag(type_id_list, TYPE_TAG_INT64_SIGNED), lhs_idx, imm, dst_idx };
                    }
                }
                break;
            }
            case ARM64_INS_ADRP: {
                if (op_count >= 2 && ops[0].type == ARM64_OP_REG && ops[1].type == ARM64_OP_IMM) {
                    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[0].reg));
                    uint64_t imm = static_cast<uint64_t>(ops[1].imm);
                    imm &= ~0xFFFULL;
                    opcode_list = { OP_ADRP, dst_idx,
                                    static_cast<uint32_t>(imm & 0xFFFFFFFFull),
                                    static_cast<uint32_t>((imm >> 32) & 0xFFFFFFFFull) };
                }
                break;
            }
            case ARM64_INS_MRS: {
                if (op_count >= 1 && ops[0].type == ARM64_OP_REG) {
                    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[0].reg));
                    opcode_list = { OP_LOAD_IMM, dst_idx, 0 };
                }
                break;
            }
            case ARM64_INS_RET:
                opcode_list = { OP_RETURN, 1, getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ARM64_REG_X0)) };
                break;
            case ARM64_INS_BR:
                if (op_count >= 1 && ops[0].type == ARM64_OP_REG && (ops[0].reg == ARM64_REG_LR || ops[0].reg == ARM64_REG_X30)) {
                    opcode_list = { OP_RETURN, 1, getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ARM64_REG_X0)) };
                }
                break;
            case ARM64_INS_BLR: {
                if (op_count >= 1 && ops[0].type == ARM64_OP_REG) {
                    uint32_t func_reg = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[0].reg));
                    uint32_t x0 = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ARM64_REG_X0));
                    uint32_t x1 = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ARM64_REG_X1));
                    uint32_t x2 = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ARM64_REG_X2));
                    uint32_t x3 = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ARM64_REG_X3));
                    uint32_t x4 = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ARM64_REG_X4));
                    uint32_t x5 = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ARM64_REG_X5));
                    opcode_list = { OP_CALL, 0, 6, 1, x0, func_reg, x0, x1, x2, x3, x4, x5 };
                }
                break;
            }
            case ARM64_INS_B: {
                if (op_count >= 1 && ops[0].type == ARM64_OP_IMM && detail) {
                    arm64_cc cc = detail->aarch64.cc;
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
                            uint64_t target_addr = static_cast<uint64_t>(ops[0].imm);
                            uint32_t branch_id = getOrAddBranch(branch_id_list, target_addr);
                            opcode_list = { OP_BRANCH_IF_CC, static_cast<uint32_t>(cc), branch_id };
                            break;
                        }
                        case ARM64_CC_AL:
                        case ARM64_CC_INVALID: {
                            uint64_t target_addr = static_cast<uint64_t>(ops[0].imm);
                            uint32_t branch_id = getOrAddBranch(branch_id_list, target_addr);
                            opcode_list = { OP_BRANCH, branch_id };
                            break;
                        }
                        default:
                            break;
                    }
                }
                break;
            }
            case ARM64_INS_CSEL: {
                if (detail &&
                    op_count >= 3 &&
                    ops[0].type == ARM64_OP_REG &&
                    ops[1].type == ARM64_OP_REG &&
                    ops[2].type == ARM64_OP_REG) {
                    // CSEL 语义：dst = cond ? src_true : src_false
                    // 这里展开成：dst=src_true; if(cond) goto next; dst=src_false;
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
                            if (appendAssignRegOrZero(csel_ops, reg_id_list, ops[0].reg, ops[1].reg)) {
                                uint32_t branch_id = getOrAddBranch(branch_id_list, next_addr);
                                csel_ops.push_back(OP_BRANCH_IF_CC);
                                csel_ops.push_back(static_cast<uint32_t>(cc));
                                csel_ops.push_back(branch_id);
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
                            break;
                    }
                }
                break;
            }
            case ARM64_INS_TBZ:
            case ARM64_INS_TBNZ: {
                static const uint32_t BIN_UPDATE_FLAGS = 0x40u;
                if (op_count >= 3 &&
                    ops[0].type == ARM64_OP_REG &&
                    ops[1].type == ARM64_OP_IMM &&
                    ops[2].type == ARM64_OP_IMM) {
                    uint32_t src_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[0].reg));
                    uint32_t tmp_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ARM64_REG_X16));
                    uint32_t type_idx = getOrAddTypeTag(type_id_list, TYPE_TAG_INT64_SIGNED);
                    uint32_t bit = static_cast<uint32_t>(ops[1].imm) & 63u;
                    uint64_t target_addr = static_cast<uint64_t>(ops[2].imm);
                    uint32_t branch_id = getOrAddBranch(branch_id_list, target_addr);
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
            case ARM64_INS_SUBS: {
                static const uint32_t BIN_UPDATE_FLAGS = 0x40u;
                if (op_count >= 3 && ops[0].type == ARM64_OP_REG && ops[1].type == ARM64_OP_REG) {
                    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[0].reg));
                    uint32_t lhs_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[1].reg));
                    if (ops[2].type == ARM64_OP_IMM) {
                        uint32_t imm = static_cast<uint32_t>(ops[2].imm);
                        opcode_list = { OP_BINARY_IMM, BIN_SUB | BIN_UPDATE_FLAGS, getOrAddTypeTag(type_id_list, TYPE_TAG_INT64_SIGNED), lhs_idx, imm, dst_idx };
                    } else if (ops[2].type == ARM64_OP_REG) {
                        uint32_t rhs_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[2].reg));
                        opcode_list = { OP_BINARY, BIN_SUB | BIN_UPDATE_FLAGS, getOrAddTypeTag(type_id_list, TYPE_TAG_INT64_SIGNED), lhs_idx, rhs_idx, dst_idx };
                    }
                }
                break;
            }
            case ARM64_INS_STP: {
                if (op_count >= 3 && ops[0].type == ARM64_OP_REG && ops[1].type == ARM64_OP_REG && ops[2].type == ARM64_OP_MEM) {
                    int32_t offset = static_cast<int32_t>(ops[2].mem.disp);
                    uint32_t base_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[2].mem.base));
                    uint32_t pair_size = (ops[0].reg >= ARM64_REG_W0 && ops[0].reg <= ARM64_REG_W30) ? 4u : 8u;
                    uint32_t type_tag = (pair_size == 4)
                                        ? getOrAddTypeTag(type_id_list, TYPE_TAG_INT32_SIGNED_2)
                                        : getOrAddTypeTag(type_id_list, TYPE_TAG_INT64_SIGNED);
                    uint32_t val1 = (ops[0].reg == ARM64_REG_WZR || ops[0].reg == ARM64_REG_XZR)
                                    ? static_cast<uint32_t>(-1)
                                    : getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[0].reg));
                    uint32_t val2 = (ops[1].reg == ARM64_REG_WZR || ops[1].reg == ARM64_REG_XZR)
                                    ? static_cast<uint32_t>(-1)
                                    : getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[1].reg));
                    opcode_list = {
                        OP_SET_FIELD, type_tag, base_idx, static_cast<uint32_t>(offset), val1,
                        OP_SET_FIELD, type_tag, base_idx, static_cast<uint32_t>(offset + static_cast<int32_t>(pair_size)), val2
                    };
                }
                break;
            }
            case ARM64_INS_STUR: {
                if (op_count >= 2 && ops[0].type == ARM64_OP_REG && ops[1].type == ARM64_OP_MEM) {
                    int32_t offset = static_cast<int32_t>(ops[1].mem.disp);
                    uint32_t value_reg_idx = (ops[0].reg == ARM64_REG_WZR || ops[0].reg == ARM64_REG_XZR)
                                             ? static_cast<uint32_t>(-1)
                                             : getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[0].reg));
                    opcode_list = {
                        OP_SET_FIELD,
                        getOrAddTypeTagForRegWidth(type_id_list, ops[0].reg),
                        getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[1].mem.base)),
                        static_cast<uint32_t>(offset),
                        value_reg_idx
                    };
                }
                break;
            }
            case ARM64_INS_LDUR: {
                if (op_count >= 2 && ops[0].type == ARM64_OP_REG && ops[1].type == ARM64_OP_MEM) {
                    int32_t offset = static_cast<int32_t>(ops[1].mem.disp);
                    opcode_list = {
                        OP_GET_FIELD,
                        getOrAddTypeTagForRegWidth(type_id_list, ops[0].reg),
                        getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[1].mem.base)),
                        static_cast<uint32_t>(offset),
                        getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[0].reg))
                    };
                }
                break;
            }
            case ARM64_INS_LDURB: {
                if (op_count >= 2 && ops[0].type == ARM64_OP_REG && ops[1].type == ARM64_OP_MEM) {
                    int32_t offset = static_cast<int32_t>(ops[1].mem.disp);
                    opcode_list = {
                        OP_GET_FIELD,
                        getOrAddTypeTag(type_id_list, TYPE_TAG_INT8_UNSIGNED),
                        getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[1].mem.base)),
                        static_cast<uint32_t>(offset),
                        getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[0].reg))
                    };
                }
                break;
            }
            case ARM64_INS_BL: {
                if (op_count >= 1 && ops[0].type == ARM64_OP_IMM) {
                    uint64_t target_addr = static_cast<uint64_t>(ops[0].imm);
                    uint32_t branch_id = getOrAddBranch(call_target_list, target_addr);
                    opcode_list = { OP_BL, branch_id };
                }
                break;
            }
            case ARM64_INS_LDP: {
                if (op_count >= 3 && ops[0].type == ARM64_OP_REG && ops[1].type == ARM64_OP_REG && ops[2].type == ARM64_OP_MEM) {
                    int32_t offset = static_cast<int32_t>(ops[2].mem.disp);
                    uint32_t base_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[2].mem.base));
                    uint32_t pair_size = (ops[0].reg >= ARM64_REG_W0 && ops[0].reg <= ARM64_REG_W30) ? 4u : 8u;
                    uint32_t type_tag = (pair_size == 4)
                                        ? getOrAddTypeTag(type_id_list, TYPE_TAG_INT32_SIGNED_2)
                                        : getOrAddTypeTag(type_id_list, TYPE_TAG_INT64_SIGNED);
                    uint32_t dst1 = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[0].reg));
                    uint32_t dst2 = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[1].reg));
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
                    if (op_count >= 2 && ops[0].type == ARM64_OP_REG && ops[1].type == ARM64_OP_REG) {
                        uint32_t dst_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[0].reg));
                        uint32_t lhs_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[1].reg));
                        uint32_t type_idx = getOrAddTypeTag(type_id_list, TYPE_TAG_INT64_SIGNED);
                        if (op_count >= 3) {
                            if (ops[2].type == ARM64_OP_IMM) {
                                opcode_list = {
                                    OP_BINARY_IMM,
                                    BIN_SHL,
                                    type_idx,
                                    lhs_idx,
                                    static_cast<uint32_t>(ops[2].imm),
                                    dst_idx
                                };
                            } else if (ops[2].type == ARM64_OP_REG) {
                                uint32_t rhs_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[2].reg));
                                opcode_list = { OP_BINARY, BIN_SHL, type_idx, lhs_idx, rhs_idx, dst_idx };
                            }
                        } else if (ops[1].shift.type == ARM64_SFT_LSL) {
                            opcode_list = {
                                OP_BINARY_IMM,
                                BIN_SHL,
                                type_idx,
                                lhs_idx,
                                static_cast<uint32_t>(ops[1].shift.value),
                                dst_idx
                            };
                        }
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
            ops[0].type == ARM64_OP_REG) {
            (void)tryEmitMovLike(opcode_list, reg_id_list, ops[0].reg, ops[1]);
        }

        // 兼容 Capstone 把 mul/and/ldrsw 归类到其它指令 ID 或 alias 的情况。
        if (opcode_list.empty() &&
            op_count >= 3 && ops &&
            insn[j].mnemonic &&
            std::strcmp(insn[j].mnemonic, "mul") == 0 &&
            ops[0].type == ARM64_OP_REG &&
            ops[1].type == ARM64_OP_REG &&
            ops[2].type == ARM64_OP_REG) {
            uint32_t dst_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[0].reg));
            uint32_t lhs_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[1].reg));
            uint32_t rhs_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[2].reg));
            uint32_t type_idx = getOrAddTypeTagForRegWidth(type_id_list, ops[0].reg);
            opcode_list = { OP_BINARY, BIN_MUL, type_idx, lhs_idx, rhs_idx, dst_idx };
        }

        if (opcode_list.empty() &&
            op_count >= 3 && ops &&
            insn[j].mnemonic &&
            std::strcmp(insn[j].mnemonic, "and") == 0 &&
            ops[0].type == ARM64_OP_REG &&
            ops[1].type == ARM64_OP_REG) {
            uint32_t dst_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[0].reg));
            uint32_t lhs_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[1].reg));
            uint32_t type_idx = getOrAddTypeTagForRegWidth(type_id_list, ops[0].reg);
            if (ops[2].type == ARM64_OP_REG) {
                uint32_t rhs_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[2].reg));
                opcode_list = { OP_BINARY, BIN_AND, type_idx, lhs_idx, rhs_idx, dst_idx };
            } else if (ops[2].type == ARM64_OP_IMM) {
                uint32_t imm = static_cast<uint32_t>(ops[2].imm);
                opcode_list = { OP_BINARY_IMM, BIN_AND, type_idx, lhs_idx, imm, dst_idx };
            }
        }

        if (opcode_list.empty() &&
            op_count >= 2 && ops &&
            insn[j].mnemonic &&
            std::strcmp(insn[j].mnemonic, "ldrsw") == 0 &&
            ops[0].type == ARM64_OP_REG &&
            ops[1].type == ARM64_OP_MEM) {
            int32_t offset = static_cast<int32_t>(ops[1].mem.disp);
            opcode_list = {
                OP_GET_FIELD,
                getOrAddTypeTag(type_id_list, TYPE_TAG_INT32_SIGNED_2),
                getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[1].mem.base)),
                static_cast<uint32_t>(offset),
                getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[0].reg))
            };
        }

        if (opcode_list.empty() &&
            op_count >= 2 && ops &&
            insn[j].mnemonic &&
            std::strcmp(insn[j].mnemonic, "ldursw") == 0 &&
            ops[0].type == ARM64_OP_REG &&
            ops[1].type == ARM64_OP_MEM) {
            int32_t offset = static_cast<int32_t>(ops[1].mem.disp);
            opcode_list = {
                OP_GET_FIELD,
                getOrAddTypeTag(type_id_list, TYPE_TAG_INT32_SIGNED_2),
                getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[1].mem.base)),
                static_cast<uint32_t>(offset),
                getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[0].reg))
            };
        }

        if (opcode_list.empty() &&
            detail &&
            op_count >= 3 && ops &&
            insn[j].mnemonic &&
            std::strcmp(insn[j].mnemonic, "csel") == 0 &&
            ops[0].type == ARM64_OP_REG &&
            ops[1].type == ARM64_OP_REG &&
            ops[2].type == ARM64_OP_REG) {
            // 兼容某些 Capstone 版本把 csel 归到其它 instruction id 的情况。
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
                    if (appendAssignRegOrZero(csel_ops, reg_id_list, ops[0].reg, ops[1].reg)) {
                        uint32_t branch_id = getOrAddBranch(branch_id_list, next_addr);
                        csel_ops.push_back(OP_BRANCH_IF_CC);
                        csel_ops.push_back(static_cast<uint32_t>(cc));
                        csel_ops.push_back(branch_id);
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
                    break;
            }
        }

        if (opcode_list.empty()) {
            const char* reason = instruction_id_handled
                                 ? "recognized instruction but operand pattern is not translated"
                                 : "unsupported instruction id";
            unencoded.translationOk = false;
            unencoded.translationError = str_format(
                "translate failed at 0x%" PRIx64 ": %s %s (%s, op_count=%u)",
                addr,
                insn[j].mnemonic ? insn[j].mnemonic : "",
                insn[j].op_str ? insn[j].op_str : "",
                reason,
                static_cast<unsigned>(op_count)
            );
            LOGE("%s", unencoded.translationError.c_str());
            translation_aborted = true;
            break;
        }

        unencoded.instByAddress[addr] = std::move(opcode_list);
        std::string asm_line(insn[j].mnemonic ? insn[j].mnemonic : "");
        if (insn[j].op_str && insn[j].op_str[0] != '\0') {
            asm_line += ' ';
            asm_line += insn[j].op_str;
        }
        unencoded.asmByAddress[addr] = std::move(asm_line);
    }

    if (translation_aborted) {
        cs_free(insn, count);
        return unencoded;
    }

    std::map<uint64_t, uint32_t> addr_to_pc;
    uint32_t pc = 0;
    for (const auto& kv : unencoded.instByAddress) {
        addr_to_pc[kv.first] = pc;
        pc += static_cast<uint32_t>(kv.second.size());
    }

    unencoded.branchAddrWords = call_target_list;
    unencoded.branchWords.clear();
    for (uint64_t arm_addr : branch_id_list) {
        auto it = addr_to_pc.find(arm_addr);
        unencoded.branchWords.push_back(it != addr_to_pc.end() ? it->second : 0u);
    }
    unencoded.branchCount = static_cast<uint32_t>(unencoded.branchWords.size());

    cs_free(insn, count);

    unencoded.regList = std::move(reg_id_list);
    unencoded.registerCount = static_cast<uint32_t>(unencoded.regList.size());
    if (unencoded.registerCount < 4) unencoded.registerCount = 4;

    unencoded.typeTags = std::move(type_id_list);
    unencoded.typeCount = static_cast<uint32_t>(unencoded.typeTags.size());

    unencoded.instCount = 0;
    for (const auto& kv : unencoded.instByAddress) {
        unencoded.instCount += static_cast<uint32_t>(kv.second.size());
    }

    return unencoded;
}

static std::vector<uint32_t> flattenInstByAddress(const std::map<uint64_t, std::vector<uint32_t>>& instByAddress) {
    // 按地址有序展开，确保输出顺序稳定。
    std::vector<uint32_t> flat;
    for (const auto& kv : instByAddress) {
        for (uint32_t word : kv.second) {
            flat.push_back(word);
        }
    }
    return flat;
}

static void write_u32_bin(std::ostream& out, uint32_t value) {
    out.write(reinterpret_cast<const char*>(&value), sizeof(value));
}

static bool read_u32_bin(const std::vector<uint8_t>& data, size_t& cursor, uint32_t& out) {
    if (cursor + sizeof(uint32_t) > data.size()) return false;
    std::memcpy(&out, data.data() + cursor, sizeof(uint32_t));
    cursor += sizeof(uint32_t);
    return true;
}

static void write_u64_bin(std::ostream& out, uint64_t value) {
    out.write(reinterpret_cast<const char*>(&value), sizeof(value));
}

static bool read_u64_bin(const std::vector<uint8_t>& data, size_t& cursor, uint64_t& out) {
    if (cursor + sizeof(uint64_t) > data.size()) return false;
    std::memcpy(&out, data.data() + cursor, sizeof(uint64_t));
    cursor += sizeof(uint64_t);
    return true;
}

static void write_string_bin(std::ostream& out, const std::string& value) {
    write_u32_bin(out, static_cast<uint32_t>(value.size()));
    if (!value.empty()) {
        out.write(value.data(), static_cast<std::streamsize>(value.size()));
    }
}

static bool read_string_bin(const std::vector<uint8_t>& data, size_t& cursor, std::string& out) {
    uint32_t size = 0;
    if (!read_u32_bin(data, cursor, size)) return false;
    if (cursor + size > data.size()) return false;
    out.assign(reinterpret_cast<const char*>(data.data() + cursor), size);
    cursor += size;
    return true;
}

static bool writeUnencodedToBinaryStream(std::ostream& out, const zUnencodedBytecode& unencoded) {
    // 先写 header，再写各区段，读取端按同顺序恢复。
    zUnencodedBinHeader header;
    header.magic = Z_UNENCODED_BIN_MAGIC;
    header.version = Z_UNENCODED_BIN_VERSION;
    header.registerCount = unencoded.registerCount;
    header.regCount = static_cast<uint32_t>(unencoded.regList.size());
    header.typeCount = unencoded.typeCount;
    header.initValueCount = unencoded.initValueCount;
    header.instLineCount = static_cast<uint32_t>(unencoded.instByAddress.size());
    header.instCount = unencoded.instCount;
    header.branchCount = unencoded.branchCount;
    header.branchAddrCount = static_cast<uint32_t>(unencoded.branchAddrWords.size());

    write_u32_bin(out, header.magic);
    write_u32_bin(out, header.version);
    write_u32_bin(out, header.registerCount);
    write_u32_bin(out, header.regCount);
    write_u32_bin(out, header.typeCount);
    write_u32_bin(out, header.initValueCount);
    write_u32_bin(out, header.instLineCount);
    write_u32_bin(out, header.instCount);
    write_u32_bin(out, header.branchCount);
    write_u32_bin(out, header.branchAddrCount);

    for (uint32_t value : unencoded.regList) {
        write_u32_bin(out, value);
    }
    for (uint32_t value : unencoded.typeTags) {
        write_u32_bin(out, value);
    }
    for (uint32_t value : unencoded.branchWords) {
        write_u32_bin(out, value);
    }
    for (uint64_t value : unencoded.branchAddrWords) {
        write_u64_bin(out, value);
    }

    for (const auto& kv : unencoded.instByAddress) {
        write_u64_bin(out, kv.first);
        write_u32_bin(out, static_cast<uint32_t>(kv.second.size()));
        for (uint32_t word : kv.second) {
            write_u32_bin(out, word);
        }
        auto asm_it = unencoded.asmByAddress.find(kv.first);
        const std::string asm_text = (asm_it != unencoded.asmByAddress.end()) ? asm_it->second : std::string();
        write_string_bin(out, asm_text);
    }

    return static_cast<bool>(out);
}

static bool readUnencodedFromBinaryBytes(const std::vector<uint8_t>& data, zUnencodedBytecode& out) {
    size_t cursor = 0;
    zUnencodedBinHeader header;
    if (!read_u32_bin(data, cursor, header.magic)) return false;
    if (!read_u32_bin(data, cursor, header.version)) return false;
    if (!read_u32_bin(data, cursor, header.registerCount)) return false;
    if (!read_u32_bin(data, cursor, header.regCount)) return false;
    if (!read_u32_bin(data, cursor, header.typeCount)) return false;
    if (!read_u32_bin(data, cursor, header.initValueCount)) return false;
    if (!read_u32_bin(data, cursor, header.instLineCount)) return false;
    if (!read_u32_bin(data, cursor, header.instCount)) return false;
    if (!read_u32_bin(data, cursor, header.branchCount)) return false;

    if (!read_u32_bin(data, cursor, header.branchAddrCount)) return false;

    if (header.magic != Z_UNENCODED_BIN_MAGIC || header.version != Z_UNENCODED_BIN_VERSION) {
        return false;
    }

    // 先恢复元信息，再按段顺序恢复具体内容。
    out = zUnencodedBytecode();
    out.registerCount = header.registerCount;
    out.typeCount = header.typeCount;
    out.initValueCount = header.initValueCount;
    out.instCount = header.instCount;
    out.branchCount = header.branchCount;

    out.regList.resize(header.regCount);
    for (uint32_t i = 0; i < header.regCount; i++) {
        if (!read_u32_bin(data, cursor, out.regList[i])) return false;
    }

    out.typeTags.resize(header.typeCount);
    for (uint32_t i = 0; i < header.typeCount; i++) {
        if (!read_u32_bin(data, cursor, out.typeTags[i])) return false;
    }

    out.branchWords.resize(header.branchCount);
    for (uint32_t i = 0; i < header.branchCount; i++) {
        if (!read_u32_bin(data, cursor, out.branchWords[i])) return false;
    }

    out.branchAddrWords.resize(header.branchAddrCount);
    for (uint32_t i = 0; i < header.branchAddrCount; i++) {
        if (!read_u64_bin(data, cursor, out.branchAddrWords[i])) return false;
    }

    for (uint32_t i = 0; i < header.instLineCount; i++) {
        uint64_t addr = 0;
        uint32_t words_count = 0;
        if (!read_u64_bin(data, cursor, addr)) return false;
        if (!read_u32_bin(data, cursor, words_count)) return false;

        std::vector<uint32_t> words(words_count);
        for (uint32_t j = 0; j < words_count; j++) {
            if (!read_u32_bin(data, cursor, words[j])) return false;
        }

        std::string asm_text;
        if (!read_string_bin(data, cursor, asm_text)) return false;

        out.instByAddress.emplace(addr, std::move(words));
        if (!asm_text.empty()) {
            out.asmByAddress.emplace(addr, std::move(asm_text));
        }
    }

    if (cursor != data.size()) {
        return false;
    }

    return true;
}

static std::string trim_copy(std::string value) {
    auto is_space = [](unsigned char c) { return std::isspace(c) != 0; };
    auto begin_it = std::find_if_not(value.begin(), value.end(), is_space);
    auto end_it = std::find_if_not(value.rbegin(), value.rend(), is_space).base();
    if (begin_it >= end_it) return std::string();
    return std::string(begin_it, end_it);
}

static bool parseArrayValuesFromLine(const std::string& line, std::vector<uint32_t>& values) {
    size_t l = line.find('{');
    size_t r = line.find('}');
    if (l == std::string::npos || r == std::string::npos || r <= l) return false;
    std::string body = line.substr(l + 1, r - l - 1);
    std::stringstream ss(body);
    std::string token;
    values.clear();
    while (std::getline(ss, token, ',')) {
        std::string trimmed = trim_copy(token);
        if (trimmed.empty()) continue;
        unsigned long long value = std::strtoull(trimmed.c_str(), nullptr, 0);
        values.push_back(static_cast<uint32_t>(value));
    }
    return true;
}

static bool parseArrayValuesFromLine64(const std::string& line, std::vector<uint64_t>& values) {
    size_t l = line.find('{');
    size_t r = line.find('}');
    if (l == std::string::npos || r == std::string::npos || r <= l) return false;
    std::string body = line.substr(l + 1, r - l - 1);
    std::stringstream ss(body);
    std::string token;
    values.clear();
    while (std::getline(ss, token, ',')) {
        std::string trimmed = trim_copy(token);
        if (trimmed.empty()) continue;
        unsigned long long value = std::strtoull(trimmed.c_str(), nullptr, 0);
        values.push_back(static_cast<uint64_t>(value));
    }
    return true;
}

static bool parseUnencodedFromTextContent(const std::string& content, zUnencodedBytecode& out) {
    std::istringstream in(content);
    std::string line;

    out = zUnencodedBytecode();

    bool got_reg_list = false;
    bool got_type_count = false;
    bool got_type_list = false;
    bool got_branch_count = false;
    bool got_branch_list = false;
    bool got_branch_addr_count = false;
    bool got_branch_addr_list = false;
    bool got_inst_count = false;
    uint64_t parsed_branch_addr_count = 0;

    bool in_inst_list = false;
    uint32_t auto_addr = 0;

    // 第一阶段：提取 reg/type/branch/inst 等静态定义。
    while (std::getline(in, line)) {
        std::string trimmed = trim_copy(line);
        if (trimmed.empty()) continue;

        if (!in_inst_list) {
            if (trimmed.find("static const uint32_t reg_id_list[]") != std::string::npos) {
                got_reg_list = parseArrayValuesFromLine(trimmed, out.regList);
                continue;
            }
            if (trimmed.find("static const uint32_t reg_id_count") != std::string::npos) {
                continue;
            }
            if (trimmed.find("static const uint32_t type_id_count") != std::string::npos) {
                size_t eq = trimmed.find('=');
                size_t sc = trimmed.find(';', eq);
                if (eq == std::string::npos || sc == std::string::npos) return false;
                out.typeCount = static_cast<uint32_t>(std::strtoul(trimmed.substr(eq + 1, sc - eq - 1).c_str(), nullptr, 10));
                got_type_count = true;
                continue;
            }
            if (trimmed.find("static const uint32_t type_id_list[]") != std::string::npos) {
                got_type_list = parseArrayValuesFromLine(trimmed, out.typeTags);
                continue;
            }
            if (trimmed.find("static const uint32_t branch_id_count") != std::string::npos) {
                size_t eq = trimmed.find('=');
                size_t sc = trimmed.find(';', eq);
                if (eq == std::string::npos || sc == std::string::npos) return false;
                out.branchCount = static_cast<uint32_t>(std::strtoul(trimmed.substr(eq + 1, sc - eq - 1).c_str(), nullptr, 10));
                got_branch_count = true;
                continue;
            }
            if (trimmed.find("static const uint64_t branch_addr_count") != std::string::npos) {
                size_t eq = trimmed.find('=');
                size_t sc = trimmed.find(';', eq);
                if (eq == std::string::npos || sc == std::string::npos) return false;
                parsed_branch_addr_count = std::strtoull(trimmed.substr(eq + 1, sc - eq - 1).c_str(), nullptr, 10);
                got_branch_addr_count = true;
                continue;
            }
            if (trimmed.find("uint64_t branch_addr_list") != std::string::npos && trimmed.find('{') != std::string::npos) {
                std::vector<uint64_t> branch_addr_values;
                if (!parseArrayValuesFromLine64(trimmed, branch_addr_values)) return false;
                out.branchAddrWords = std::move(branch_addr_values);
                got_branch_addr_list = true;
                continue;
            }
            if (trimmed.find("branch_id_list") != std::string::npos && trimmed.find('{') != std::string::npos) {
                std::vector<uint32_t> branch_values;
                if (!parseArrayValuesFromLine(trimmed, branch_values)) return false;
                out.branchWords = std::move(branch_values);
                got_branch_list = true;
                continue;
            }
            if (trimmed.find("static const uint32_t inst_id_count") != std::string::npos) {
                size_t eq = trimmed.find('=');
                size_t sc = trimmed.find(';', eq);
                if (eq == std::string::npos || sc == std::string::npos) return false;
                out.instCount = static_cast<uint32_t>(std::strtoul(trimmed.substr(eq + 1, sc - eq - 1).c_str(), nullptr, 10));
                got_inst_count = true;
                continue;
            }
            if (trimmed.find("uint32_t inst_id_list[]") != std::string::npos) {
                in_inst_list = true;
                continue;
            }
        } else {
            if (trimmed == "};") {
                in_inst_list = false;
                continue;
            }

            size_t comment_pos = trimmed.find("//");
            std::string value_part = (comment_pos == std::string::npos) ? trimmed : trim_copy(trimmed.substr(0, comment_pos));
            if (!value_part.empty() && value_part.back() == ',') {
                value_part.pop_back();
                value_part = trim_copy(value_part);
            }

            std::vector<uint32_t> words;
            std::stringstream ss(value_part);
            std::string token;
            while (std::getline(ss, token, ',')) {
                std::string token_trimmed = trim_copy(token);
                if (token_trimmed.empty()) continue;
                unsigned long long value = std::strtoull(token_trimmed.c_str(), nullptr, 10);
                words.push_back(static_cast<uint32_t>(value));
            }
            if (words.empty()) continue;

            uint64_t addr = static_cast<uint64_t>(auto_addr++);
            std::string asm_text;
            if (comment_pos != std::string::npos) {
                std::string comment = trim_copy(trimmed.substr(comment_pos + 2));
                size_t addr_pos = comment.find("0x");
                if (addr_pos != std::string::npos) {
                    size_t colon_pos = comment.find(':', addr_pos);
                    if (colon_pos != std::string::npos) {
                        std::string addr_str = comment.substr(addr_pos, colon_pos - addr_pos);
                        addr = std::strtoull(addr_str.c_str(), nullptr, 16);
                        asm_text = trim_copy(comment.substr(colon_pos + 1));
                    }
                }
            }

            out.instByAddress[addr] = std::move(words);
            if (!asm_text.empty()) {
                out.asmByAddress[addr] = std::move(asm_text);
            }
        }
    }

    if (!got_reg_list || !got_type_count || !got_type_list || !got_branch_count || !got_branch_list ||
        !got_branch_addr_count || !got_branch_addr_list || !got_inst_count) {
        return false;
    }

    if (out.typeTags.size() != out.typeCount) {
        out.typeCount = static_cast<uint32_t>(out.typeTags.size());
    }
    if (out.branchWords.size() != out.branchCount) {
        return false;
    }
    if (parsed_branch_addr_count != out.branchAddrWords.size()) {
        return false;
    }

    uint32_t computed_inst_count = 0;
    for (const auto& kv : out.instByAddress) {
        computed_inst_count += static_cast<uint32_t>(kv.second.size());
    }
    if (computed_inst_count != out.instCount) {
        out.instCount = computed_inst_count;
    }

    out.registerCount = static_cast<uint32_t>(out.regList.size());
    if (out.registerCount < 4) out.registerCount = 4;
    out.initValueCount = 0;

    return true;
}

static std::vector<uint8_t> parseFunctionBytesFromDisasm(const std::map<uint64_t, std::string>& asm_by_address) {
    // 这里是轻量近似恢复，仅用于调试展示，不作为真实机器码回放。
    std::vector<uint8_t> bytes;
    for (const auto& kv : asm_by_address) {
        const std::string& asm_text = kv.second;
        std::string mnemonic;
        std::istringstream ss(asm_text);
        ss >> mnemonic;
        if (mnemonic.empty()) continue;
        if (mnemonic == "ret") {
            bytes.insert(bytes.end(), {0xC0, 0x03, 0x5F, 0xD6});
        } else if (mnemonic == "b" || mnemonic == "bl" || mnemonic.rfind("b.", 0) == 0) {
            bytes.insert(bytes.end(), {0x00, 0x00, 0x00, 0x14});
        } else {
            bytes.insert(bytes.end(), {0x1F, 0x20, 0x03, 0xD5});
        }
    }
    return bytes;
}

static uint64_t inferFunctionAddress(const zUnencodedBytecode& unencoded) {
    for (const auto& kv : unencoded.instByAddress) {
        auto asm_it = unencoded.asmByAddress.find(kv.first);
        if (asm_it != unencoded.asmByAddress.end() && !asm_it->second.empty()) {
            return kv.first;
        }
    }

    if (!unencoded.asmByAddress.empty()) {
        return unencoded.asmByAddress.begin()->first;
    }
    return 0;
}

static bool writeUnencodedToStream(std::ostream& out, const zUnencodedBytecode& unencoded) {
    // 输出结构保持与历史 fun_xxx.txt 格式一致，便于双向回归。
    out << "static const uint32_t reg_id_list[] = { ";
    for (size_t i = 0; i < unencoded.regList.size(); i++) {
        if (i > 0) out << ", ";
        out << unencoded.regList[i];
    }
    out << " };\n";
    out << "static const uint32_t reg_id_count = sizeof(reg_id_list)/sizeof(uint32_t);\n";

    out << "static const uint32_t type_id_count = " << unencoded.typeCount << ";\n";
    out << "static const uint32_t type_id_list[] = { ";
    for (size_t i = 0; i < unencoded.typeTags.size(); i++) {
        if (i > 0) out << ", ";
        out << unencoded.typeTags[i];
    }
    out << " };\n";

    out << "static const uint32_t branch_id_count = " << unencoded.branchCount << ";\n";
    if (unencoded.branchCount > 0) {
        out << "uint32_t branch_id_list[] = { ";
        for (size_t i = 0; i < unencoded.branchWords.size(); i++) {
            if (i > 0) out << ", ";
            out << unencoded.branchWords[i];
        }
        out << " };\n";
    } else {
        out << "uint32_t branch_id_list[1] = {};\n";
    }

    out << "static const uint64_t branch_addr_count = " << unencoded.branchAddrWords.size() << ";\n";
    if (!unencoded.branchAddrWords.empty()) {
        out << "uint64_t branch_addr_list[] = { ";
        for (size_t i = 0; i < unencoded.branchAddrWords.size(); i++) {
            if (i > 0) out << ", ";
            out << str_format("0x%" PRIx64, unencoded.branchAddrWords[i]);
        }
        out << " };\n";
    } else {
        out << "uint64_t branch_addr_list[1] = {};\n";
    }

    out << "static const uint32_t inst_id_count = " << unencoded.instCount << ";\n";
    out << "static const uint64_t fun_addr = "
        << str_format("0x%" PRIx64, inferFunctionAddress(unencoded)) << ";\n";
    out << "uint32_t inst_id_list[] = {\n";

    const size_t comment_column = 54;
    const size_t op_name_width = 20;
    for (auto it = unencoded.instByAddress.begin(); it != unencoded.instByAddress.end(); ++it) {
        const auto& opcode_list = it->second;
        const char* op_name = opcode_list.empty() ? "OP_UNKNOWN" : getOpcodeName(opcode_list[0]);

        auto asm_it = unencoded.asmByAddress.find(it->first);
        const char* asm_str = (asm_it != unencoded.asmByAddress.end()) ? asm_it->second.c_str() : "";
        std::string asm_with_addr = (asm_str[0] != '\0')
            ? str_format("0x%" PRIx64 ": %s", it->first, asm_str)
            : std::string();
        const char* asm_display = (asm_str[0] != '\0') ? asm_with_addr.c_str() : asm_str;

        std::string line = formatInstructionLine(opcode_list, op_name, asm_display, comment_column, op_name_width);
        out << line << "\n";
    }

    out << "};\n";
    return static_cast<bool>(out);
}

}

// 用既有 zFunctionData 初始化函数对象。
zFunction::zFunction(const zFunctionData& data)
    : zFunctionData(data) {
}

const std::string& zFunction::name() const {
    return function_name;
}

Elf64_Addr zFunction::offset() const {
    return function_offset;
}

size_t zFunction::size() const {
    return function_bytes.size();
}

const uint8_t* zFunction::data() const {
    return function_bytes.empty() ? nullptr : function_bytes.data();
}

bool zFunction::empty() const {
    return function_bytes.empty();
}

void zFunction::set_unencoded_cache(
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

void zFunction::rebuild_asm_list_from_unencoded() const {
    asm_list_.clear();
    // 把按地址缓存的 opcode 行重建成展示用的 zInst 列表。
    for (const auto& kv : inst_words_by_addr_cache_) {
        uint64_t addr = kv.first;
        std::vector<uint8_t> raw(4, 0);
        std::string asm_text;
        std::string asm_type = "vm";

        auto it = asm_text_by_addr_cache_.find(addr);
        if (it != asm_text_by_addr_cache_.end()) {
            asm_text = it->second;
            std::istringstream ss(asm_text);
            ss >> asm_type;
            if (asm_type.empty()) asm_type = "vm";
        }

        asm_list_.emplace_back(addr, std::move(raw), 4u, std::move(asm_type), std::move(asm_text));
    }
    asm_ready_ = true;
}

// 确保未编码缓存可用：优先复用缓存，缺失时再由机器码反推。
void zFunction::ensure_unencoded_ready() const {
    if (unencoded_ready_) return;

    // 没有原始机器码时，写入空缓存，避免后续重复判空分支。
    if (!data() || size() == 0) {
        set_unencoded_cache(0, {}, 0, {}, 0, {}, {}, 0, 0, {}, {});
        unencoded_translate_ok_ = false;
        unencoded_translate_error_ = "function bytes are empty";
        return;
    }

    csh handle = 0;
    if (cs_open(CS_ARCH_AARCH64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        set_unencoded_cache(0, {}, 0, {}, 0, {}, {}, 0, 0, {}, {});
        unencoded_translate_ok_ = false;
        unencoded_translate_error_ = "capstone cs_open failed";
        return;
    }

    zUnencodedBytecode unencoded = buildUnencodedByCapstone(handle, data(), size(), offset());
    cs_close(&handle);

    if (!unencoded.translationOk) {
        set_unencoded_cache(0, {}, 0, {}, 0, {}, {}, 0, 0, {}, {});
        unencoded_translate_ok_ = false;
        unencoded_translate_error_ = unencoded.translationError.empty()
                                     ? "capstone translation failed"
                                     : unencoded.translationError;
        LOGE("ensure_unencoded_ready failed for %s: %s",
             function_name.c_str(),
             unencoded_translate_error_.c_str());
        return;
    }

    // 解析完成后一次性更新缓存。
    set_unencoded_cache(
            unencoded.registerCount,
            std::move(unencoded.regList),
            unencoded.typeCount,
            std::move(unencoded.typeTags),
            unencoded.initValueCount,
            std::move(unencoded.instByAddress),
            std::move(unencoded.asmByAddress),
            unencoded.instCount,
            unencoded.branchCount,
            std::move(unencoded.branchWords),
            std::move(unencoded.branchAddrWords)
    );
}

// 确保反汇编展示列表可用：优先复用未编码缓存，其次走 Capstone。
void zFunction::ensure_asm_ready() const {
    if (asm_ready_) {
        return;
    }

    // 未编码缓存已就绪时，直接重建展示列表，避免重复反汇编。
    if (unencoded_ready_) {
        rebuild_asm_list_from_unencoded();
        return;
    }

    asm_list_.clear();
    if (!data() || size() == 0) {
        asm_ready_ = true;
        return;
    }

    csh handle = 0;
    if (cs_open(CS_ARCH_AARCH64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        asm_ready_ = true;
        return;
    }

    cs_insn* insn = nullptr;
    size_t count = cs_disasm(handle, data(), size(), offset(), 0, &insn);
    // 逐条指令转成 zInst 结构，统一供 assemblyInfo() 输出。
    for (size_t i = 0; i < count; i++) {
        const cs_insn& item = insn[i];
        std::vector<uint8_t> raw(item.bytes, item.bytes + item.size);

        std::string asm_type = item.mnemonic ? item.mnemonic : "";
        std::string disasm_text = asm_type;
        if (item.op_str && item.op_str[0] != '\0') {
            disasm_text += " ";
            disasm_text += item.op_str;
        }

        asm_list_.emplace_back(
            item.address,
            std::move(raw),
            static_cast<uint32_t>(item.size),
            std::move(asm_type),
            std::move(disasm_text)
        );
    }

    if (insn) {
        cs_free(insn, count);
    }
    cs_close(&handle);
    asm_ready_ = true;
}

zFunction& zFunction::analyzeAssembly() {
    ensure_asm_ready();
    return *this;
}

const std::vector<zInst>& zFunction::assemblyList() const {
    ensure_asm_ready();
    return asm_list_;
}

std::string zFunction::assemblyInfo() const {
    ensure_asm_ready();

    std::ostringstream oss;
    for (size_t i = 0; i < asm_list_.size(); i++) {
        if (i > 0) {
            oss << "\n";
        }
        oss << asm_list_[i].getInfo();
    }
    return oss.str();
}

const std::vector<uint64_t>& zFunction::sharedBranchAddrs() const {
    ensure_unencoded_ready();
    if (!unencoded_translate_ok_) {
        static const std::vector<uint64_t> kEmpty;
        LOGE("sharedBranchAddrs unavailable for %s: %s",
             function_name.c_str(),
             unencoded_translate_error_.c_str());
        return kEmpty;
    }
    return branch_addrs_cache_;
}

bool zFunction::remapBlToSharedBranchAddrs(const std::vector<uint64_t>& shared_branch_addrs) {
    ensure_unencoded_ready();
    if (!unencoded_translate_ok_) {
        LOGE("remapBlToSharedBranchAddrs failed for %s: %s",
             function_name.c_str(),
             unencoded_translate_error_.c_str());
        return false;
    }
    if (shared_branch_addrs.empty()) {
        for (const auto& kv : inst_words_by_addr_cache_) {
            const std::vector<uint32_t>& words = kv.second;
            if (!words.empty() && words[0] == OP_BL) {
                return false;
            }
        }
        branch_addrs_cache_.clear();
        return true;
    }

    std::unordered_map<uint64_t, uint32_t> global_index_map;
    global_index_map.reserve(shared_branch_addrs.size());
    for (uint32_t i = 0; i < static_cast<uint32_t>(shared_branch_addrs.size()); ++i) {
        global_index_map.emplace(shared_branch_addrs[i], i);
    }

    for (auto& kv : inst_words_by_addr_cache_) {
        std::vector<uint32_t>& words = kv.second;
        if (words.empty() || words[0] != OP_BL) {
            continue;
        }
        if (words.size() < 2) {
            return false;
        }

        const uint32_t local_index = words[1];
        if (local_index >= branch_addrs_cache_.size()) {
            return false;
        }

        const uint64_t target_addr = branch_addrs_cache_[local_index];
        auto it = global_index_map.find(target_addr);
        if (it == global_index_map.end()) {
            return false;
        }
        words[1] = it->second;
    }

    // 所有函数统一写入同一份全局 branch_addr_list，保证索引语义一致。
    branch_addrs_cache_ = shared_branch_addrs;
    return true;
}

// 按导出模式输出函数数据。
bool zFunction::dump(const char* file_path, DumpMode mode) const {
    if (!file_path || file_path[0] == '\0') return false;

    // 从缓存恢复统一中间结构，避免不同导出模式重复拼装。
    auto build_unencoded_from_cache = [this]() {
        zUnencodedBytecode unencoded;
        unencoded.registerCount = register_count_cache_;
        unencoded.regList = register_ids_cache_;
        unencoded.typeCount = type_count_cache_;
        unencoded.typeTags = type_tags_cache_;
        unencoded.initValueCount = init_value_count_cache_;
        unencoded.instByAddress = inst_words_by_addr_cache_;
        unencoded.asmByAddress = asm_text_by_addr_cache_;
        unencoded.instCount = inst_count_cache_;
        unencoded.branchCount = branch_count_cache_;
        unencoded.branchWords = branch_words_cache_;
        unencoded.branchAddrWords = branch_addrs_cache_;
        return unencoded;
    };

    if (mode == DumpMode::UNENCODED_BIN) {
        ensure_unencoded_ready();
        if (!unencoded_translate_ok_) {
            LOGE("dump failed for %s: %s",
                 function_name.c_str(),
                 unencoded_translate_error_.c_str());
            return false;
        }
        zUnencodedBytecode unencoded = build_unencoded_from_cache();
        std::ofstream out(file_path, std::ios::binary);
        if (!out) return false;
        return writeUnencodedToBinaryStream(out, unencoded);
    }

    ensure_unencoded_ready();
    if (!unencoded_translate_ok_) {
        LOGE("dump failed for %s: %s",
             function_name.c_str(),
             unencoded_translate_error_.c_str());
        return false;
    }
    zUnencodedBytecode unencoded = build_unencoded_from_cache();

    if (mode == DumpMode::ENCODED) {
        // 编码导出时做“往返一致性”校验，保证序列化协议稳定。
        zFunctionData source_data;
        std::string error;
        if (!buildEncodedDataFromUnencoded(unencoded, source_data, &error)) {
            LOGE("dump encoded failed: build source data error: %s", error.c_str());
            return false;
        }

        std::vector<uint8_t> encoded;
        if (!source_data.serializeEncoded(encoded, &error)) {
            LOGE("dump encoded failed: serialize error: %s", error.c_str());
            return false;
        }

        zFunctionData decoded_data;
        if (!zFunctionData::deserializeEncoded(encoded.data(), encoded.size(), decoded_data, &error)) {
            LOGE("dump encoded failed: deserialize error: %s", error.c_str());
            return false;
        }
        if (!source_data.encodedEquals(decoded_data, &error)) {
            LOGE("dump encoded failed: round-trip mismatch: %s", error.c_str());
            return false;
        }

        std::ofstream out(file_path, std::ios::binary);
        if (!out) return false;
        if (!encoded.empty()) {
            out.write(reinterpret_cast<const char*>(encoded.data()), static_cast<std::streamsize>(encoded.size()));
        }
        return static_cast<bool>(out);
    }

    std::ofstream out(file_path);
    if (!out) return false;
    return writeUnencodedToStream(out, unencoded);
}

