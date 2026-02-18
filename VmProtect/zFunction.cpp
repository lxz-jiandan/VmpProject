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

class zBytecodeEncoder {
public:
    void write6bits(uint32_t value) {
        value &= 0x3Fu;
        bit_buf_ |= (value << bit_count_);
        bit_count_ += 6;
        while (bit_count_ >= 8) {
            out_.push_back(static_cast<uint8_t>(bit_buf_ & 0xFFu));
            bit_buf_ >>= 8;
            bit_count_ -= 8;
        }
    }

    void write6bitExt(uint32_t value) {
        if (value < 32u) {
            write6bits(value);
            return;
        }
        while (value >= 32u) {
            write6bits(0x20u | (value & 0x1Fu));
            value >>= 5;
        }
        write6bits(value & 0x1Fu);
    }

    std::vector<uint8_t> finish() {
        if (bit_count_ > 0) {
            out_.push_back(static_cast<uint8_t>(bit_buf_ & 0xFFu));
        }
        bit_buf_ = 0;
        bit_count_ = 0;
        return std::move(out_);
    }

private:
    std::vector<uint8_t> out_;
    uint32_t bit_buf_ = 0;
    int bit_count_ = 0;
};

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
    int size_buf = std::snprintf(nullptr, 0, format.c_str(), args...) + 1;
    if (size_buf <= 0) return std::string();
    std::unique_ptr<char[]> buf(new(std::nothrow) char[size_buf]);
    if (!buf) return std::string();
    std::snprintf(buf.get(), static_cast<size_t>(size_buf), format.c_str(), args...);
    return std::string(buf.get(), buf.get() + size_buf - 1);
}

static std::string formatOpcodeList(const std::vector<uint32_t>& opcode_list, bool trailing_comma = true) {
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

static void emitLoadImm(std::vector<uint32_t>& opcode_list, uint32_t dst_idx, uint64_t imm) {
    if (imm <= 0xFFFFFFFFull) {
        opcode_list = { OP_LOAD_IMM, dst_idx, static_cast<uint32_t>(imm) };
    } else {
        opcode_list = { OP_LOAD_CONST64, dst_idx,
                        static_cast<uint32_t>(imm & 0xFFFFFFFFull),
                        static_cast<uint32_t>((imm >> 32) & 0xFFFFFFFFull) };
    }
}

static uint32_t getOrAddTypeTag(std::vector<uint32_t>& type_id_list, uint32_t type_tag) {
    for (size_t k = 0; k < type_id_list.size(); k++) {
        if (type_id_list[k] == type_tag) return static_cast<uint32_t>(k);
    }
    type_id_list.push_back(type_tag);
    return static_cast<uint32_t>(type_id_list.size() - 1);
}

static uint32_t getOrAddBranch(std::vector<uint64_t>& branch_id_list, uint64_t target_arm_addr) {
    for (size_t k = 0; k < branch_id_list.size(); k++) {
        if (branch_id_list[k] == target_arm_addr) return static_cast<uint32_t>(k);
    }
    branch_id_list.push_back(target_arm_addr);
    return static_cast<uint32_t>(branch_id_list.size() - 1);
}

static std::vector<uint8_t> buildBytecode(
    uint32_t registerCount,
    uint32_t typeCount,
    const uint32_t* typeTags,
    uint32_t initValueCount,
    uint32_t instCount,
    const uint32_t* instWords,
    uint32_t branchCount,
    const uint32_t* branchWords
) {
    zBytecodeEncoder encoder;
    encoder.write6bits(0);
    encoder.write6bitExt(registerCount);
    encoder.write6bitExt(0);
    for (uint32_t i = 0; i < typeCount; i++) {
        encoder.write6bitExt(typeTags[i]);
    }
    encoder.write6bitExt(initValueCount);
    encoder.write6bitExt(instCount);
    for (uint32_t i = 0; i < instCount; i++) {
        encoder.write6bitExt(instWords[i]);
    }
    encoder.write6bitExt(branchCount);
    if (branchWords) {
        for (uint32_t i = 0; i < branchCount; i++) {
            encoder.write6bitExt(branchWords[i]);
        }
    }
    return encoder.finish();
}

static zUnencodedBytecode buildUnencodedByCapstone(csh handle, const uint8_t* code, size_t size, uint64_t base_addr) {
    zUnencodedBytecode unencoded;
    unencoded.initValueCount = 0;
    unencoded.branchCount = 0;
    unencoded.branchWords.clear();

    std::vector<uint32_t> reg_id_list;
    std::vector<uint32_t> type_id_list;

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_insn* insn = nullptr;
    size_t count = cs_disasm(handle, code, size, base_addr, 0, &insn);
    if (count == 0 || !insn) {
        return unencoded;
    }

    for (int i = 0; i < 31; i++) {
        reg_id_list.push_back(static_cast<uint32_t>(i));
    }

    (void)getOrAddReg(reg_id_list, 0);
    unencoded.instByAddress[0] = { OP_ALLOC_RETURN, 0, 0, 0, 0 };

    uint32_t vfp_idx = getOrAddReg(reg_id_list, 29);
    uint32_t vsp_idx = getOrAddReg(reg_id_list, 31);
    unencoded.instByAddress[1] = { OP_ALLOC_VSP, 0, 0, 0, vfp_idx, vsp_idx };

    std::vector<uint64_t> branch_id_list;

    for (size_t j = 0; j < count; j++) {
        uint64_t addr = insn[j].address;
        unsigned int id = insn[j].id;
        cs_detail* detail = insn[j].detail;
        uint8_t op_count = detail ? detail->aarch64.op_count : 0;
        cs_arm64_op* ops = detail ? reinterpret_cast<cs_arm64_op*>(detail->aarch64.operands) : nullptr;
        std::vector<uint32_t> opcode_list;

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
                        getOrAddTypeTag(type_id_list, TYPE_TAG_INT32_SIGNED_2),
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
                        getOrAddTypeTag(type_id_list, TYPE_TAG_INT32_SIGNED_2),
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
            case ARM64_INS_MOV: {
                if (op_count >= 2 && ops[0].type == ARM64_OP_REG) {
                    uint32_t dst_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[0].reg));
                    if (ops[1].type == ARM64_OP_REG) {
                        if (ops[1].reg == ARM64_REG_WZR || ops[1].reg == ARM64_REG_XZR) {
                            opcode_list = { OP_LOAD_IMM, dst_idx, 0 };
                        } else if (ops[0].reg != ARM64_REG_WZR && ops[0].reg != ARM64_REG_XZR) {
                            uint32_t src_idx = getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ops[1].reg));
                            opcode_list = { OP_MOV, src_idx, dst_idx };
                        }
                    } else if (ops[1].type == ARM64_OP_IMM) {
                        uint64_t imm = static_cast<uint64_t>(ops[1].imm);
                        if (ops[1].shift.type == ARM64_SFT_LSL && ops[1].shift.value != 0) {
                            imm <<= ops[1].shift.value;
                        }
                        if (is_arm64_w_reg(ops[0].reg)) {
                            imm &= 0xFFFFFFFFull;
                        }
                        emitLoadImm(opcode_list, dst_idx, imm);
                    }
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
            case ARM64_INS_RET:
                opcode_list = { OP_RETURN, 1, getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ARM64_REG_X0)) };
                break;
            case ARM64_INS_BR:
                if (op_count >= 1 && ops[0].type == ARM64_OP_REG && (ops[0].reg == ARM64_REG_LR || ops[0].reg == ARM64_REG_X30)) {
                    opcode_list = { OP_RETURN, 1, getOrAddReg(reg_id_list, arm64_capstone_to_arch_index(ARM64_REG_X0)) };
                }
                break;
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
                        getOrAddTypeTag(type_id_list, TYPE_TAG_INT32_SIGNED_2),
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
                        getOrAddTypeTag(type_id_list, TYPE_TAG_INT32_SIGNED_2),
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
                    uint32_t branch_id = getOrAddBranch(branch_id_list, target_addr);
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
                LOGE("Unsupported instruction: %d %s", insn[j].id, insn[j].mnemonic);
                break;
        }

        if (!opcode_list.empty()) {
            unencoded.instByAddress[addr] = std::move(opcode_list);
            std::string asm_line(insn[j].mnemonic ? insn[j].mnemonic : "");
            if (insn[j].op_str && insn[j].op_str[0] != '\0') {
                asm_line += ' ';
                asm_line += insn[j].op_str;
            }
            unencoded.asmByAddress[addr] = std::move(asm_line);
        }
    }

    std::map<uint64_t, uint32_t> addr_to_pc;
    uint32_t pc = 0;
    for (const auto& kv : unencoded.instByAddress) {
        addr_to_pc[kv.first] = pc;
        pc += static_cast<uint32_t>(kv.second.size());
    }

    unencoded.branchAddrWords = branch_id_list;
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
    std::vector<uint32_t> flat;
    for (const auto& kv : instByAddress) {
        for (uint32_t word : kv.second) {
            flat.push_back(word);
        }
    }
    return flat;
}

static std::vector<uint8_t> encodeBytecode(const zUnencodedBytecode& unencoded) {
    std::vector<uint32_t> inst_words = flattenInstByAddress(unencoded.instByAddress);
    return buildBytecode(
        unencoded.registerCount,
        unencoded.typeCount,
        unencoded.typeTags.empty() ? nullptr : unencoded.typeTags.data(),
        unencoded.initValueCount,
        unencoded.instCount,
        inst_words.empty() ? nullptr : inst_words.data(),
        unencoded.branchCount,
        unencoded.branchWords.empty() ? nullptr : unencoded.branchWords.data()
    );
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
    if (out.branchAddrWords.size() != out.branchCount) {
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

static bool writeUnencodedToStream(std::ostream& out, const zUnencodedBytecode& unencoded) {
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

zFunction::zFunction(std::string function_name, Elf64_Addr function_offset, std::vector<uint8_t> function_bytes)
    : function_name_(std::move(function_name)),
      function_offset_(function_offset),
      function_bytes_(std::move(function_bytes)) {
}

const std::string& zFunction::name() const {
    return function_name_;
}

Elf64_Addr zFunction::offset() const {
    return function_offset_;
}

size_t zFunction::size() const {
    return function_bytes_.size();
}

const uint8_t* zFunction::data() const {
    return function_bytes_.empty() ? nullptr : function_bytes_.data();
}

bool zFunction::empty() const {
    return function_bytes_.empty();
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
    unencoded_register_count_ = register_count;
    unencoded_reg_list_ = std::move(reg_id_list);
    unencoded_type_count_ = type_count;
    unencoded_type_tags_ = std::move(type_tags);
    unencoded_init_value_count_ = init_value_count;
    unencoded_inst_by_address_ = std::move(inst_by_address);
    unencoded_asm_by_address_ = std::move(asm_by_address);
    unencoded_inst_count_ = inst_count;
    unencoded_branch_count_ = branch_count;
    unencoded_branch_words_ = std::move(branch_words);
    unencoded_branch_addr_words_ = std::move(branch_addr_words);
    unencoded_ready_ = true;
}

void zFunction::rebuild_asm_list_from_unencoded() const {
    asm_list_.clear();
    for (const auto& kv : unencoded_inst_by_address_) {
        uint64_t addr = kv.first;
        std::vector<uint8_t> raw(4, 0);
        std::string asm_text;
        std::string asm_type = "vm";

        auto it = unencoded_asm_by_address_.find(addr);
        if (it != unencoded_asm_by_address_.end()) {
            asm_text = it->second;
            std::istringstream ss(asm_text);
            ss >> asm_type;
            if (asm_type.empty()) asm_type = "vm";
        }

        asm_list_.emplace_back(addr, std::move(raw), 4u, std::move(asm_type), std::move(asm_text));
    }
    asm_ready_ = true;
}

void zFunction::ensure_unencoded_ready() const {
    if (unencoded_ready_) return;

    if (!data() || size() == 0) {
        set_unencoded_cache(0, {}, 0, {}, 0, {}, {}, 0, 0, {}, {});
        return;
    }

    csh handle = 0;
    if (cs_open(CS_ARCH_AARCH64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        set_unencoded_cache(0, {}, 0, {}, 0, {}, {}, 0, 0, {}, {});
        return;
    }

    zUnencodedBytecode unencoded = buildUnencodedByCapstone(handle, data(), size(), offset());
    cs_close(&handle);

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

void zFunction::ensure_asm_ready() const {
    if (asm_ready_) {
        return;
    }

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

zFunction& zFunction::analyzeAsm() {
    ensure_asm_ready();
    return *this;
}

zFunction& zFunction::analyzeasm() {
    return analyzeAsm();
}

const std::vector<zInst>& zFunction::asmList() const {
    ensure_asm_ready();
    return asm_list_;
}

const std::vector<zInst>& zFunction::asmlist() const {
    return asmList();
}

std::string zFunction::getAsmInfo() const {
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

std::string zFunction::getasminfo() const {
    return getAsmInfo();
}

zFunction zFunction::fromUnencodedTxt(const char* file_path, const std::string& function_name, Elf64_Addr function_offset) {
    zFunction function(function_name, function_offset, {});
    function.loadUnencodedTxt(file_path);
    return function;
}

zFunction zFunction::fromUnencodedBin(const char* file_path, const std::string& function_name, Elf64_Addr function_offset) {
    zFunction function(function_name, function_offset, {});
    function.loadUnencodedBin(file_path);
    return function;
}

bool zFunction::loadUnencodedTxt(const char* file_path) {
    if (!file_path || file_path[0] == '\0') return false;
    std::ifstream in(file_path, std::ios::binary);
    if (!in) return false;

    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    zUnencodedBytecode parsed;
    if (!parseUnencodedFromTextContent(content, parsed)) return false;

    set_unencoded_cache(
        parsed.registerCount,
        std::move(parsed.regList),
        parsed.typeCount,
        std::move(parsed.typeTags),
        parsed.initValueCount,
        std::move(parsed.instByAddress),
        std::move(parsed.asmByAddress),
        parsed.instCount,
        parsed.branchCount,
        std::move(parsed.branchWords),
        std::move(parsed.branchAddrWords)
    );

    function_bytes_ = parseFunctionBytesFromDisasm(unencoded_asm_by_address_);
    rebuild_asm_list_from_unencoded();
    return true;
}

bool zFunction::loadUnencodedBin(const char* file_path) {
    if (!file_path || file_path[0] == '\0') return false;
    std::ifstream in(file_path, std::ios::binary);
    if (!in) return false;

    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    zUnencodedBytecode parsed;
    if (!readUnencodedFromBinaryBytes(bytes, parsed)) return false;

    set_unencoded_cache(
        parsed.registerCount,
        std::move(parsed.regList),
        parsed.typeCount,
        std::move(parsed.typeTags),
        parsed.initValueCount,
        std::move(parsed.instByAddress),
        std::move(parsed.asmByAddress),
        parsed.instCount,
        parsed.branchCount,
        std::move(parsed.branchWords),
        std::move(parsed.branchAddrWords)
    );

    function_bytes_ = parseFunctionBytesFromDisasm(unencoded_asm_by_address_);
    rebuild_asm_list_from_unencoded();
    return true;
}

bool zFunction::dump(const char* file_path, DumpMode mode) const {
    if (!file_path || file_path[0] == '\0') return false;

    auto build_unencoded_from_cache = [this]() {
        zUnencodedBytecode unencoded;
        unencoded.registerCount = unencoded_register_count_;
        unencoded.regList = unencoded_reg_list_;
        unencoded.typeCount = unencoded_type_count_;
        unencoded.typeTags = unencoded_type_tags_;
        unencoded.initValueCount = unencoded_init_value_count_;
        unencoded.instByAddress = unencoded_inst_by_address_;
        unencoded.asmByAddress = unencoded_asm_by_address_;
        unencoded.instCount = unencoded_inst_count_;
        unencoded.branchCount = unencoded_branch_count_;
        unencoded.branchWords = unencoded_branch_words_;
        unencoded.branchAddrWords = unencoded_branch_addr_words_;
        return unencoded;
    };

    if (mode == DumpMode::UNENCODED_BIN) {
        ensure_unencoded_ready();
        zUnencodedBytecode unencoded = build_unencoded_from_cache();
        std::ofstream out(file_path, std::ios::binary);
        if (!out) return false;
        return writeUnencodedToBinaryStream(out, unencoded);
    }

    ensure_unencoded_ready();
    zUnencodedBytecode unencoded = build_unencoded_from_cache();

    if (mode == DumpMode::ENCODED) {
        std::vector<uint8_t> encoded = encodeBytecode(unencoded);
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
