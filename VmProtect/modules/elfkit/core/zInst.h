/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - VM 指令结构声明。
 * - 加固链路位置：翻译表示层。
 * - 输入：指令字段（opcode/operand）。
 * - 输出：统一的 VM 指令模型。
 */
#ifndef VMPROTECT_ZINST_H
#define VMPROTECT_ZINST_H

#include <cstddef>  // size_t。
#include <cstdint>  // uint64_t/uint32_t。
#include <map>      // std::map（地址到指令/文本映射）。
#include <string>   // std::string（文本字段）。
#include <vector>   // std::vector（机器码字节容器）。

#include <capstone/arm64.h>  // AArch64 指令/寄存器常量定义。
#include <capstone/capstone.h>

/*
 * [VMP_FLOW_NOTE] merged from zInstAsm.h
 * - 统一把 ARM64 反汇编辅助声明并入 zInst.h，减少头文件分散。
 * - 本段只放“翻译接口契约”，具体实现位于 zInst.cpp。
 */

// AArch64 -> VM 未编码中间结果。
// 该结构被 zFunction 的缓存路径与 dump 导出路径复用，属于翻译层与导出层之间的稳定接口。
struct zInstAsmUnencodedBytecode {  // 数据结构声明：承载跨阶段传递的中间状态。
    // 函数前缀指令（与真实 ARM 地址解耦）：
    // 当前用于承载 OP_ALLOC_RETURN / OP_ALLOC_VSP 等运行时预置指令。
    // 注意：该容器中的指令不参与“地址->PC”映射，只在最终扁平指令流中位于最前面。
    std::vector<uint32_t> preludeWords;  // 状态更新：记录本步骤的中间结果或配置。
    uint32_t registerCount = 0;  // 状态更新：记录本步骤的中间结果或配置。
    std::vector<uint32_t> regList;  // 状态更新：记录本步骤的中间结果或配置。
    uint32_t typeCount = 0;  // 状态更新：记录本步骤的中间结果或配置。
    std::vector<uint32_t> typeTags;  // 状态更新：记录本步骤的中间结果或配置。
    uint32_t initValueCount = 0;  // 状态更新：记录本步骤的中间结果或配置。
    std::map<uint64_t, std::vector<uint32_t>> instByAddress;  // 状态更新：记录本步骤的中间结果或配置。
    std::map<uint64_t, std::string> asmByAddress;  // 状态更新：记录本步骤的中间结果或配置。
    uint32_t instCount = 0;  // 状态更新：记录本步骤的中间结果或配置。
    uint32_t branchCount = 0;  // 状态更新：记录本步骤的中间结果或配置。
    std::vector<uint32_t> branchWords;  // 状态更新：记录本步骤的中间结果或配置。
    std::vector<uint32_t> branchLookupWords;  // 状态更新：记录本步骤的中间结果或配置。
    std::vector<uint64_t> branchLookupAddrs;  // 状态更新：记录本步骤的中间结果或配置。
    std::vector<uint64_t> branchAddrWords;  // 状态更新：记录本步骤的中间结果或配置。
    bool translationOk = true;  // 状态更新：记录本步骤的中间结果或配置。
    std::string translationError;  // 状态更新：记录本步骤的中间结果或配置。
};  // 状态更新：记录本步骤的中间结果或配置。

class zInstAsm {  // 类型声明：定义该组件的职责边界与可见接口。
public:  // 可见性分区：限定调用方可访问的接口范围。
    // 打开 AArch64 Capstone 句柄。
    // 仅负责 cs_open；若失败会把 handle 置 0 并返回 false。
    static bool open(csh& handle);  // 状态更新：记录本步骤的中间结果或配置。
    // 一步完成“打开句柄 + 开启 detail 模式”。
    // detail 模式是解析操作数(op_count/operands)所必需的前置条件。
    static bool openWithDetail(csh& handle);  // 状态更新：记录本步骤的中间结果或配置。
    // 在已打开句柄上启用 CS_OPT_DETAIL。
    static bool enableDetail(csh handle);  // 状态更新：记录本步骤的中间结果或配置。
    // 关闭句柄并清零，防止上层误用悬空句柄。
    static void close(csh& handle);  // 状态更新：记录本步骤的中间结果或配置。

    // 反汇编 [code, code + size) 区间的全部指令。
    // baseAddr 作为反汇编地址基准写入 cs_insn.address。
    static size_t disasm(csh handle,  // 参数声明：该参数参与当前语义分发或结果组装。
                         const uint8_t* code,  // 参数声明：该参数参与当前语义分发或结果组装。
                         size_t size,  // 参数声明：该参数参与当前语义分发或结果组装。
                         uint64_t baseAddr,  // 参数声明：该参数参与当前语义分发或结果组装。
                         cs_insn*& outInsn);  // 状态更新：记录本步骤的中间结果或配置。
    // 释放 disasm() 返回的指令缓存。
    static void freeInsn(cs_insn* insn, size_t count);  // 状态更新：记录本步骤的中间结果或配置。

    // mnemonic / 文本辅助方法。
    // getMnemonic: 返回助记符字符串（空安全）。
    static std::string getMnemonic(const cs_insn& insn);  // 状态更新：记录本步骤的中间结果或配置。
    // buildAsmText: 组装 "mnemonic op_str" 可读文本（dump/日志共用）。
    static std::string buildAsmText(const cs_insn& insn);  // 状态更新：记录本步骤的中间结果或配置。

    // 端到端翻译入口：
    // 原始 ARM64 机器码 -> VM 未编码中间字节码结构。
    static zInstAsmUnencodedBytecode buildUnencodedBytecode(const uint8_t* code, size_t size, uint64_t baseAddr);  // 状态更新：记录本步骤的中间结果或配置。
};

class zInst {
public:
    // ARM64 指令在翻译阶段的职责分域。
    // 作用：让解析层先完成一次“类别分发”，减少后续模块重复判定。
    enum class zAsmDomain {
        Unknown = 0,
        Arith,
        Logic,
        Memory,
        Branch,
    };

    // 空指令对象：
    // 使用类内默认成员初始值，不做额外初始化动作。
    zInst() = default;

    // 构造一条反汇编指令快照。
    // 参数语义：
    // 1) address：指令地址；
    // 2) rawBytes：机器码字节；
    // 3) instructionLength：指令长度；
    // 4) asmType：指令类别；
    // 5) disasmText：反汇编文本。
    zInst(uint64_t address,
          std::vector<uint8_t> rawBytes,
          uint32_t instructionLength,
          std::string asmType,
          std::string disasmText);

    // 基础访问器：返回指令地址、机器码、长度和反汇编信息。
    // 设计要点：
    // 1) 所有接口均为 const，保证调用不改变对象状态；
    // 2) `getRawBytes()` 返回 const 引用，避免不必要复制。
    uint64_t getAddress() const;
    const std::vector<uint8_t>& getRawBytes() const;
    uint32_t getInstructionLength() const;
    const std::string& getAsmType() const;
    const std::string& getDisasmText() const;

    // 拼接可读字符串，便于日志打印和回归比对。
    // 格式在 cpp 中固定为：
    // addr=0x..., len=..., type=..., bytes=..., text=...
    std::string getInfo() const;

    // 根据 ARM64 指令 id 进行一级类别分发。
    // 说明：
    // 1) instructionId 通常来自 Capstone `cs_insn::id`；
    // 2) 返回 Unknown 表示当前 id 未覆盖，翻译层会按严格模式直接失败。
    static zAsmDomain classifyArm64Domain(unsigned int instructionId);
    // 把分域枚举转成稳定文本，便于日志排查。
    static const char* getAsmDomainName(zAsmDomain domain);

private:
    // 指令起始地址。
    uint64_t addressValue = 0;
    // 原始机器码字节。
    std::vector<uint8_t> rawBytesValue;
    // 指令长度（字节数）。
    uint32_t instructionLengthValue = 0;
    // 指令类型标签（通常对应 mnemonic）。
    std::string asmTypeValue;
    // 可读反汇编文本（通常是 mnemonic + operands）。
    std::string disasmTextValue;
};


/*
 * [VMP_FLOW_NOTE] merged from zInstDispatch.h
 * - 统一收拢 ARM64->VM 分发契约，避免多头头文件。
 */
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
