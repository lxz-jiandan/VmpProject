/*
 * [VMP_FLOW_NOTE] ARM64 translator dispatch contract.
 * - Shared opcode/type constants for split asm dispatch modules.
 * - Shared helper declarations implemented in zInstAsmTranslate.cpp.
 */
#ifndef VMPROTECT_ZINSTDISPATCH_H
#define VMPROTECT_ZINSTDISPATCH_H

#include "zInstAsm.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

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
    OP_ATOMIC_LOAD = 57, OP_ATOMIC_STORE = 58, OP_BRANCH_REG = 59,
};

enum : uint32_t {
    BIN_XOR = 0, BIN_SUB = 1, BIN_ASR = 2, BIN_DIV = 3, BIN_ADD = 4, BIN_OR = 5,
    BIN_MOD = 6, BIN_IDIV = 7, BIN_FMOD = 8, BIN_MUL = 9, BIN_LSR = 0xA, BIN_SHL = 0xB, BIN_AND = 0xC,
};

enum : uint32_t {
    UNARY_NEG = 0,
    UNARY_NOT = 1,
    UNARY_LNOT = 2,
    UNARY_ABS = 3,
    UNARY_SQRT = 4,
    UNARY_CEIL = 5,
    UNARY_FLOOR = 6,
    UNARY_ROUND = 7,
    UNARY_CLZ = 8,
};

enum : uint32_t {
    CMP_EQ = 0x20,
};

enum : uint32_t {
    VM_MEM_ORDER_RELAXED = 0,
    VM_MEM_ORDER_ACQUIRE = 1,
    VM_MEM_ORDER_RELEASE = 2,
    VM_MEM_ORDER_ACQ_REL = 3,
    VM_MEM_ORDER_SEQ_CST = 4,
};

enum : uint32_t {
    TYPE_TAG_INT8_SIGNED = 0,
    TYPE_TAG_INT16_SIGNED = 1,
    TYPE_TAG_INT64_UNSIGNED = 2,
    TYPE_TAG_INT32_SIGNED_2 = 4,
    TYPE_TAG_INT16_UNSIGNED = 0xB,
    TYPE_TAG_INT32_UNSIGNED = 0xD,
    TYPE_TAG_INT8_UNSIGNED = 0x15,
    TYPE_TAG_INT64_SIGNED = 0xE,
};

uint32_t arm64CapstoneToArchIndex(unsigned int reg);
uint32_t getOrAddReg(std::vector<uint32_t>& regIdList, uint32_t reg);
bool isArm64WReg(unsigned int reg);
bool isArm64GpReg(unsigned int reg);
bool isArm64ZeroReg(unsigned int reg);
void emitLoadImm(std::vector<uint32_t>& opcodeList, uint32_t dstIndex, uint64_t imm);

bool tryEmitMovLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    unsigned int dstReg,
    const cs_arm64_op& srcOp
);

bool appendAssignRegOrZero(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    unsigned int dstReg,
    unsigned int srcReg
);

uint32_t getOrAddTypeTag(std::vector<uint32_t>& typeIdList, uint32_t typeTag);
uint32_t getOrAddTypeTagForRegWidth(std::vector<uint32_t>& typeIdList, unsigned int reg);

bool appendAddImmSelf(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    unsigned int dstReg,
    uint32_t imm
);

bool tryEmitCmpLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    uint8_t opCount,
    cs_arm64_op* ops
);

bool tryEmitLslLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    const cs_insn& instruction,
    uint8_t opCount,
    cs_arm64_op* ops
);

bool tryEmitLsrLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    const cs_insn& instruction,
    uint8_t opCount,
    cs_arm64_op* ops
);

bool tryEmitAsrLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    const cs_insn& instruction,
    uint8_t opCount,
    cs_arm64_op* ops
);

bool tryEmitNegLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    unsigned int dstReg,
    unsigned int srcReg
);

bool tryEmitBitwiseNotLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    unsigned int dstReg,
    unsigned int srcReg
);

bool tryEmitWideningMulAddLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    unsigned int dstReg,
    unsigned int lhsReg,
    unsigned int rhsReg,
    unsigned int addReg,
    bool hasAdd,
    bool signedMode
);

bool tryEmitMulHighLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    unsigned int dstReg,
    unsigned int lhsReg,
    unsigned int rhsReg,
    bool signedMode
);

bool tryEmitRorLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    const cs_insn& instruction,
    uint8_t opCount,
    cs_arm64_op* ops
);

bool tryEmitExtendLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    unsigned int dstReg,
    unsigned int srcReg,
    bool signExtend,
    uint32_t srcTypeTag
);

void appendAndByMask(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    uint32_t srcIndex,
    uint32_t dstIndex,
    uint64_t mask,
    uint32_t typeIndex,
    unsigned int tmpMaskReg
);

bool tryEmitReverseBytesLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    unsigned int dstReg,
    unsigned int srcReg,
    bool onlySwapBytesInsideHalfword
);

bool tryEmitAtomicLoadExclusiveLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    unsigned int dstReg,
    unsigned int baseReg,
    int32_t offset,
    uint32_t memOrder
);

bool tryEmitAtomicStoreExclusiveLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    unsigned int statusReg,
    unsigned int valueReg,
    unsigned int baseReg,
    int32_t offset,
    uint32_t memOrder
);

bool appendSignExtendFromWidth(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    unsigned int dstReg,
    uint32_t dstIndex,
    uint32_t width
);

bool tryEmitBitExtractLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    unsigned int dstReg,
    unsigned int srcReg,
    uint32_t lsb,
    uint32_t width,
    bool signExtract
);

bool tryEmitBitfieldInsertLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    unsigned int dstReg,
    unsigned int srcReg,
    uint32_t lsb,
    uint32_t width,
    bool signExtract
);

bool tryEmitBitfieldInsertIntoDstLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    unsigned int dstReg,
    unsigned int srcReg,
    uint32_t lsb,
    uint32_t width
);

bool tryEmitBitfieldMoveLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    unsigned int dstReg,
    unsigned int srcReg,
    uint32_t immr,
    uint32_t imms,
    bool signExtract
);

uint32_t getOrAddBranch(std::vector<uint64_t>& branchIdList, uint64_t targetArmAddr);

// 分发调用上下文：把长参数列表收敛为单一对象，便于编排层与模块层解耦。
struct zInstDispatchContext {
    uint8_t opCount;
    cs_arm64_op* ops;
    cs_detail* detail;
    const cs_insn* insn;
    size_t instructionIndex;
    uint64_t address;
    std::vector<uint32_t>& opcodeList;
    std::vector<uint32_t>& regIdList;
    std::vector<uint32_t>& typeIdList;
    std::vector<uint64_t>& branchIdList;
    std::vector<uint64_t>& callTargetList;
};

bool dispatchArm64ArithCase(
    unsigned int id,
    uint8_t opCount,
    cs_arm64_op* ops,
    cs_detail* detail,
    const cs_insn* insn,
    size_t instructionIndex,
    uint64_t address,
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    std::vector<uint64_t>& branchIdList,
    std::vector<uint64_t>& callTargetList
);

inline bool dispatchArm64ArithCase(unsigned int id, zInstDispatchContext& context) {
    return dispatchArm64ArithCase(
        id,
        context.opCount,
        context.ops,
        context.detail,
        context.insn,
        context.instructionIndex,
        context.address,
        context.opcodeList,
        context.regIdList,
        context.typeIdList,
        context.branchIdList,
        context.callTargetList
    );
}

bool dispatchArm64LogicCase(
    unsigned int id,
    uint8_t opCount,
    cs_arm64_op* ops,
    cs_detail* detail,
    const cs_insn* insn,
    size_t instructionIndex,
    uint64_t address,
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    std::vector<uint64_t>& branchIdList,
    std::vector<uint64_t>& callTargetList
);

inline bool dispatchArm64LogicCase(unsigned int id, zInstDispatchContext& context) {
    return dispatchArm64LogicCase(
        id,
        context.opCount,
        context.ops,
        context.detail,
        context.insn,
        context.instructionIndex,
        context.address,
        context.opcodeList,
        context.regIdList,
        context.typeIdList,
        context.branchIdList,
        context.callTargetList
    );
}

bool dispatchArm64MemoryCase(
    unsigned int id,
    uint8_t opCount,
    cs_arm64_op* ops,
    cs_detail* detail,
    const cs_insn* insn,
    size_t instructionIndex,
    uint64_t address,
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    std::vector<uint64_t>& branchIdList,
    std::vector<uint64_t>& callTargetList
);

inline bool dispatchArm64MemoryCase(unsigned int id, zInstDispatchContext& context) {
    return dispatchArm64MemoryCase(
        id,
        context.opCount,
        context.ops,
        context.detail,
        context.insn,
        context.instructionIndex,
        context.address,
        context.opcodeList,
        context.regIdList,
        context.typeIdList,
        context.branchIdList,
        context.callTargetList
    );
}

bool dispatchArm64BranchCase(
    unsigned int id,
    uint8_t opCount,
    cs_arm64_op* ops,
    cs_detail* detail,
    const cs_insn* insn,
    size_t instructionIndex,
    uint64_t address,
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    std::vector<uint64_t>& branchIdList,
    std::vector<uint64_t>& callTargetList
);

inline bool dispatchArm64BranchCase(unsigned int id, zInstDispatchContext& context) {
    return dispatchArm64BranchCase(
        id,
        context.opCount,
        context.ops,
        context.detail,
        context.insn,
        context.instructionIndex,
        context.address,
        context.opcodeList,
        context.regIdList,
        context.typeIdList,
        context.branchIdList,
        context.callTargetList
    );
}

#endif
