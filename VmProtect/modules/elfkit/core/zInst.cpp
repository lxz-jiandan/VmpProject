/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - VM 指令对象与序列化辅助实现。
 * - 加固链路位置：翻译结果落盘前处理。
 * - 输入：翻译后的 VM 指令流。
 * - 输出：可写入 txt/bin 的标准化表示。
 */
#include "zInst.h"
#include "zInstAsm.h"
#include "zLog.h"
#include "zInstDispatch.h"
#include <sstream>  // std::ostringstream。
#include <iomanip>  // std::hex/std::setw/std::setfill。
#include <utility>  // std::move。
#include <cstdio>
#include <cinttypes>
#include <cstring>
#include <memory>
#include <algorithm>
#include <iterator>
#include <cctype>
#include <cstdlib>

#include <capstone/arm64.h>

// 通过移动构造接管机器码与反汇编文本，避免不必要拷贝。
zInst::zInst(uint64_t address,
             std::vector<uint8_t> rawBytes,
             uint32_t instructionLength,
             std::string asmType,
             std::string disasmText)
    // 保存地址。
    : addressValue(address),
      // 移动接管机器码字节数组（避免复制成本）。
      rawBytesValue(std::move(rawBytes)),
      // 保存指令长度。
      instructionLengthValue(instructionLength),
      // 移动接管类型文本（例如 "add"/"bl"/"ret"）。
      asmTypeValue(std::move(asmType)),
      // 移动接管反汇编文本（例如 "add x0, x0, #1"）。
      disasmTextValue(std::move(disasmText)) {
    // 构造体主体无需额外逻辑。
}

uint64_t zInst::getAddress() const {
    // 返回地址快照。
    return addressValue;
}

const std::vector<uint8_t>& zInst::getRawBytes() const {
    // 返回机器码只读引用，避免额外拷贝。
    return rawBytesValue;
}

uint32_t zInst::getInstructionLength() const {
    // 返回指令长度。
    return instructionLengthValue;
}

const std::string& zInst::getAsmType() const {
    // 返回类型标签。
    return asmTypeValue;
}

const std::string& zInst::getDisasmText() const {
    // 返回反汇编文本。
    return disasmTextValue;
}

std::string zInst::getInfo() const {
    // 使用字符串流拼接统一输出格式，便于日志与回归脚本稳定匹配。
    std::ostringstream oss;

    // 统一输出地址、长度和指令类型。
    // 地址按十六进制显示，便于与反汇编工具对齐。
    oss << "addr=0x" << std::hex << addressValue << std::dec;
    // 输出长度。
    oss << ", len=" << instructionLengthValue;
    // 输出类型。
    oss << ", type=" << asmTypeValue;
    // 输出机器码前缀。
    oss << ", bytes=";

    // 机器码按两位十六进制拼接，格式与常见反汇编工具一致。
    for (size_t byteIndex = 0; byteIndex < rawBytesValue.size(); ++byteIndex) {
        // 字节之间用空格分隔。
        if (byteIndex > 0) oss << ' ';
        // 每字节补齐两位十六进制（00~ff）。
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<unsigned>(rawBytesValue[byteIndex]);
    }
    // 恢复十进制流状态，避免影响后续数字输出。
    oss << std::dec;
    // 追加反汇编文本尾段。
    oss << ", text=" << disasmTextValue;
    // 返回完整信息字符串。
    return oss.str();
}

zInst::zAsmDomain zInst::classifyArm64Domain(unsigned int instructionId) {
    // 先按 instruction id 分发；这是主路径，速度更快且语义稳定。
    switch (instructionId) {
        // branch
        case ARM64_INS_RET:
        case ARM64_INS_BR:
        case ARM64_INS_BLR:
        case ARM64_INS_B:
        case ARM64_INS_CSEL:
        case ARM64_INS_CBZ:
        case ARM64_INS_CBNZ:
        case ARM64_INS_TBZ:
        case ARM64_INS_TBNZ:
        case ARM64_INS_BL:
        case ARM64_INS_CSINC:
        case ARM64_INS_CSINV:
        case ARM64_INS_ALIAS_CSET:
            return zAsmDomain::Branch;

        // memory
        case ARM64_INS_STR:
        case ARM64_INS_LDR:
        case ARM64_INS_STP:
        case ARM64_INS_LDP:
        case ARM64_INS_STRB:
        case ARM64_INS_STRH:
        case ARM64_INS_LDRB:
        case ARM64_INS_LDRH:
        case ARM64_INS_STUR:
        case ARM64_INS_STURB:
        case ARM64_INS_STURH:
        case ARM64_INS_STLRB:
        case ARM64_INS_STLRH:
        case ARM64_INS_STLR:
        case ARM64_INS_STLXR:
        case ARM64_INS_STXR:
        case ARM64_INS_LDUR:
        case ARM64_INS_LDAXR:
        case ARM64_INS_LDXR:
        case ARM64_INS_LDARB:
        case ARM64_INS_LDARH:
        case ARM64_INS_LDAR:
        case ARM64_INS_LDURB:
        case ARM64_INS_LDURH:
        case ARM64_INS_LDURSW:
        case ARM64_INS_ALIAS_LDURSW:
        case ARM64_INS_LDRSB:
        case ARM64_INS_LDRSH:
        case ARM64_INS_LDRSW:
            return zAsmDomain::Memory;

        // logic
        case ARM64_INS_SXTB:
        case ARM64_INS_SXTH:
        case ARM64_INS_SXTW:
        case ARM64_INS_UXTB:
        case ARM64_INS_UXTH:
        case ARM64_INS_UXTW:
        case ARM64_INS_ALIAS_UBFX:
        case ARM64_INS_ALIAS_SBFX:
        case ARM64_INS_ALIAS_UBFIZ:
        case ARM64_INS_ALIAS_SBFIZ:
        case ARM64_INS_UBFM:
        case ARM64_INS_SBFM:
        case ARM64_INS_MOV:
        case ARM64_INS_MOVI:
        case ARM64_INS_MOVZ:
        case ARM64_INS_MOVN:
        case ARM64_INS_EXTR:
        case ARM64_INS_AND:
        case ARM64_INS_ANDS:
        case ARM64_INS_ORR:
        case ARM64_INS_ORN:
        case ARM64_INS_BIC:
        case ARM64_INS_BICS:
        case ARM64_INS_EON:
        case ARM64_INS_EOR:
        case ARM64_INS_REV:
        case ARM64_INS_REV16:
            return zAsmDomain::Logic;

        // arith
        case ARM64_INS_SUB:
        case ARM64_INS_ADD:
        case ARM64_INS_ADDS:
        case ARM64_INS_MOVK:
        case ARM64_INS_LSL:
        case ARM64_INS_LSLR:
        case ARM64_INS_ALIAS_LSL:
        case ARM64_INS_LSR:
        case ARM64_INS_ASR:
        case ARM64_INS_ROR:
        case ARM64_INS_CLZ:
        case ARM64_INS_MUL:
        case ARM64_INS_MADD:
        case ARM64_INS_MSUB:
        case ARM64_INS_UMULL:
        case ARM64_INS_SMULL:
        case ARM64_INS_UMADDL:
        case ARM64_INS_SMADDL:
        case ARM64_INS_UMULH:
        case ARM64_INS_SMULH:
        case ARM64_INS_UDIV:
        case ARM64_INS_SDIV:
        case ARM64_INS_ADR:
        case ARM64_INS_ADRP:
        case ARM64_INS_MRS:
        case ARM64_INS_HINT:
        case ARM64_INS_CLREX:
        case ARM64_INS_BRK:
        case ARM64_INS_SVC:
        case ARM64_INS_SUBS:
            return zAsmDomain::Arith;

        default:
            break;
    }
    // 未命中则保持 Unknown，翻译阶段将按严格模式直接判定为 unsupported instruction id。
    return zAsmDomain::Unknown;
}

const char* zInst::getAsmDomainName(zAsmDomain domain) {
    switch (domain) {
        case zAsmDomain::Arith:
            return "arith";
        case zAsmDomain::Logic:
            return "logic";
        case zAsmDomain::Memory:
            return "memory";
        case zAsmDomain::Branch:
            return "branch";
        case zAsmDomain::Unknown:
        default:
            return "unknown";
    }
}

/*
 * [VMP_FLOW_NOTE] merged from zInstAsmCore.cpp
 * - 合并原因：按当前工程调整，将反汇编辅助实现并入 zInst.cpp。
 */
bool zInstAsm::open(csh& handle) {
    handle = 0;
    // 显式指定小端模式，避免平台默认值差异导致行为不一致。
    if (cs_open(CS_ARCH_AARCH64, CS_MODE_LITTLE_ENDIAN, &handle) != CS_ERR_OK) {
        handle = 0;
        return false;
    }
    return true;
}

bool zInstAsm::openWithDetail(csh& handle) {
    if (!open(handle)) {
        return false;
    }
    if (!enableDetail(handle)) {
        close(handle);
        return false;
    }
    return true;
}

bool zInstAsm::enableDetail(csh handle) {
    return cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK;
}

void zInstAsm::close(csh& handle) {
    if (handle == 0) {
        return;
    }
    cs_close(&handle);
    handle = 0;
}

size_t zInstAsm::disasm(csh handle,
                         const uint8_t* code,
                         size_t size,
                         uint64_t baseAddr,
                         cs_insn*& outInsn) {
    outInsn = nullptr;
    if (handle == 0 || code == nullptr || size == 0) {
        return 0;
    }
    return cs_disasm(handle, code, size, baseAddr, 0, &outInsn);
}

void zInstAsm::freeInsn(cs_insn* insn, size_t count) {
    if (insn == nullptr || count == 0) {
        return;
    }
    cs_free(insn, count);
}

std::string zInstAsm::getMnemonic(const cs_insn& insn) {
    return insn.mnemonic ? insn.mnemonic : "";
}

std::string zInstAsm::buildAsmText(const cs_insn& insn) {
    std::string text = getMnemonic(insn);
    if (insn.op_str != nullptr && insn.op_str[0] != '\0') {
        if (!text.empty()) {
            text.push_back(' ');
        }
        text += insn.op_str;
    }
    return text;
}

/*
 * [VMP_FLOW_NOTE] merged from zInstAsmTranslate.cpp
 * - 合并原因：按当前工程调整，将 ARM64->VM 翻译编排实现并入 zInst.cpp。
 */
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

static std::string buildCodePreview(const uint8_t* code, size_t size, size_t maxBytes = 24) {
    if (code == nullptr || size == 0) {
        return "empty";
    }
    const size_t count = std::min(size, maxBytes);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < count; ++i) {
        if (i != 0) {
            oss << ' ';
        }
        oss << std::setw(2) << static_cast<unsigned>(code[i]);
    }
    if (size > count) {
        oss << " ...";
    }
    return oss.str();
}

static std::string buildOperandDetail(uint8_t op_count, cs_arm64_op* ops) {
    if (ops == nullptr || op_count == 0) {
        return "none";
    }
    std::ostringstream oss;
    for (uint8_t i = 0; i < op_count; ++i) {
        if (i != 0) {
            oss << "; ";
        }
        const cs_arm64_op& op = ops[i];
        oss << "#" << static_cast<unsigned>(i) << "{type=" << static_cast<unsigned>(op.type);
        if (op.type == AARCH64_OP_REG) {
            oss << ",reg=" << static_cast<unsigned>(op.reg);
        } else if (op.type == AARCH64_OP_IMM) {
            oss << ",imm=0x" << std::hex << static_cast<unsigned long long>(op.imm) << std::dec;
        } else if (op.type == AARCH64_OP_MEM) {
            oss << ",mem.base=" << static_cast<unsigned>(op.mem.base)
                << ",mem.index=" << static_cast<unsigned>(op.mem.index)
                << ",mem.disp=" << op.mem.disp;
        }
        oss << ",shift=(" << static_cast<unsigned>(op.shift.type)
            << "," << static_cast<unsigned>(op.shift.value) << ")";
        oss << ",ext=" << static_cast<unsigned>(op.ext);
        oss << "}";
    }
    return oss.str();
}

static std::string buildInsnBytePreview(const cs_insn& insn) {
    return buildCodePreview(insn.bytes, static_cast<size_t>(insn.size), 8);
}

uint32_t arm64CapstoneToArchIndex(unsigned int reg) {
    // 把 Capstone 寄存器枚举映射到 VM 侧统一索引。
    if (reg == AARCH64_REG_SP || reg == AARCH64_REG_WSP) return 31;
    if (reg == AARCH64_REG_FP || reg == AARCH64_REG_X29) return 29;
    if (reg == AARCH64_REG_LR || reg == AARCH64_REG_X30) return 30;
    if (reg >= AARCH64_REG_W0 && reg <= AARCH64_REG_W30) return static_cast<uint32_t>(reg - AARCH64_REG_W0);
    if (reg >= AARCH64_REG_X0 && reg <= AARCH64_REG_X28) return static_cast<uint32_t>(reg - AARCH64_REG_X0);
    return 0;
}

uint32_t getOrAddReg(std::vector<uint32_t>& regIdList, uint32_t reg) {
    // 返回寄存器在 regIdList 中的索引，不存在则追加。
    for (size_t registerIndex = 0; registerIndex < regIdList.size(); ++registerIndex) {
        if (regIdList[registerIndex] == reg) return static_cast<uint32_t>(registerIndex);
    }
    regIdList.push_back(reg);
    return static_cast<uint32_t>(regIdList.size() - 1);
}

bool isArm64WReg(unsigned int reg) {
    // 判断是否 32 位通用寄存器（w0-w30/wsp/wzr）。
    return (reg >= AARCH64_REG_W0 && reg <= AARCH64_REG_W30) ||
           reg == AARCH64_REG_WSP || reg == AARCH64_REG_WZR;
}

bool isArm64GpReg(unsigned int reg) {
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
bool isArm64ZeroReg(unsigned int reg) {
    return reg == AARCH64_REG_WZR || reg == AARCH64_REG_XZR;
}

// 根据立即数宽度生成 OP_LOAD_IMM / OP_LOAD_CONST64。
void emitLoadImm(std::vector<uint32_t>& opcodeList, uint32_t dstIndex, uint64_t imm) {
    if (imm <= 0xFFFFFFFFull) {
        // 32 位可表达：直接走 OP_LOAD_IMM，字数更短。
        opcodeList = { OP_LOAD_IMM, dstIndex, static_cast<uint32_t>(imm) };
    } else {
        // 超过 32 位：拆成低/高 32 位写入 OP_LOAD_CONST64。
        opcodeList = { OP_LOAD_CONST64, dstIndex,
                       static_cast<uint32_t>(imm & 0xFFFFFFFFull),
                       static_cast<uint32_t>((imm >> 32) & 0xFFFFFFFFull) };
    }
}

bool tryEmitMovLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    unsigned int dstReg,
    const cs_arm64_op& srcOp
) {
    // 统一处理 mov/orr alias 等“搬运”语义指令。
    if (!isArm64GpReg(dstReg) || dstReg == AARCH64_REG_WZR || dstReg == AARCH64_REG_XZR) {
        // 目标不是可写通用寄存器时直接拒绝翻译。
        return false;
    }

    // 先拿到目标寄存器在 VM 寄存器表中的索引。
    uint32_t dstIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(dstReg));
    if (srcOp.type == AARCH64_OP_REG) {
        if (!isArm64GpReg(srcOp.reg)) {
            // 源寄存器不是通用寄存器，当前不处理。
            return false;
        }
        if (srcOp.reg == AARCH64_REG_WZR || srcOp.reg == AARCH64_REG_XZR) {
            // mov dst, wzr/xzr -> dst = 0。
            opcodeList = { OP_LOAD_IMM, dstIndex, 0 };
            return true;
        }
        // 普通寄存器搬运。
        uint32_t srcIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(srcOp.reg));
        opcodeList = { OP_MOV, srcIndex, dstIndex };
        return true;
    }
    if (srcOp.type == AARCH64_OP_IMM) {
        // 立即数路径：支持 LSL 移位并按目标寄存器宽度截断。
        uint64_t imm = static_cast<uint64_t>(srcOp.imm);
        if (srcOp.shift.type == AARCH64_SFT_LSL && srcOp.shift.value != 0) {
            // 立即数带 LSL 时在离线翻译阶段预先折叠。
            imm <<= srcOp.shift.value;
        }
        if (isArm64WReg(dstReg)) {
            // 写入 w 寄存器时截断到低 32 位。
            imm &= 0xFFFFFFFFull;
        }
        emitLoadImm(opcodeList, dstIndex, imm);
        return !opcodeList.empty();
    }
    return false;
}

// 追加“dst = src”语义，兼容 src 为 wzr/xzr 的零值写入。
bool appendAssignRegOrZero(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    unsigned int dstReg,
    unsigned int srcReg
) {
    if (!isArm64GpReg(dstReg) || isArm64ZeroReg(dstReg)) {
        // 目标必须是可写通用寄存器，不能是零寄存器。
        return false;
    }
    if (!isArm64GpReg(srcReg)) {
        // 源必须是通用寄存器。
        return false;
    }

    uint32_t dstIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(dstReg));
    if (isArm64ZeroReg(srcReg)) {
        // src 为 wzr/xzr 时，降级为显式加载 0。
        opcodeList.push_back(OP_LOAD_IMM);
        opcodeList.push_back(dstIndex);
        opcodeList.push_back(0);
        return true;
    }

    uint32_t srcIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(srcReg));
    // 常规寄存器赋值走 OP_MOV。
    opcodeList.push_back(OP_MOV);
    opcodeList.push_back(srcIndex);
    opcodeList.push_back(dstIndex);
    return true;
}

uint32_t getOrAddTypeTag(std::vector<uint32_t>& typeIdList, uint32_t typeTag);
uint32_t getOrAddTypeTagForRegWidth(std::vector<uint32_t>& typeIdList, unsigned int reg);

// 在已有寄存器值上执行“dst += imm”。
bool appendAddImmSelf(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    unsigned int dstReg,
    uint32_t imm
) {
    if (!isArm64GpReg(dstReg) || isArm64ZeroReg(dstReg)) {
        // 目标必须是可写通用寄存器，不能是零寄存器。
        return false;
    }
    uint32_t dstIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(dstReg));
    uint32_t typeIndex = getOrAddTypeTag(
        typeIdList,
        isArm64WReg(dstReg) ? TYPE_TAG_INT32_SIGNED_2 : TYPE_TAG_INT64_SIGNED
    );
    opcodeList.push_back(OP_BINARY_IMM);
    opcodeList.push_back(BIN_ADD);
    opcodeList.push_back(typeIndex);
    opcodeList.push_back(dstIndex);
    opcodeList.push_back(imm);
    opcodeList.push_back(dstIndex);
    return true;
}

// cmp/cmn 这类“只更新 NZCV、结果丢弃”的语义，统一转成 SUBS 到临时寄存器。
bool tryEmitCmpLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    uint8_t opCount,
    cs_arm64_op* ops
) {
    if (ops == nullptr || opCount < 2 || ops[0].type != AARCH64_OP_REG) {
        return false;
    }
    if (!isArm64GpReg(ops[0].reg)) {
        return false;
    }

    static const uint32_t BIN_UPDATE_FLAGS = 0x40u;
    std::vector<uint32_t> out;
    uint32_t typeIndex = getOrAddTypeTag(
        typeIdList,
        isArm64WReg(ops[0].reg) ? TYPE_TAG_INT32_SIGNED_2 : TYPE_TAG_INT64_SIGNED
    );
    uint32_t dstIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X16));

    auto appendRegValueOrZero = [&](unsigned int reg, unsigned int zeroTmpReg, uint32_t& outIndex) -> bool {
        if (!isArm64GpReg(reg)) {
            return false;
        }
        if (isArm64ZeroReg(reg)) {
            outIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(zeroTmpReg));
            out.push_back(OP_LOAD_IMM);
            out.push_back(outIndex);
            out.push_back(0);
            return true;
        }
        outIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(reg));
        return true;
    };

    uint32_t lhsIndex = 0;
    if (!appendRegValueOrZero(ops[0].reg, AARCH64_REG_X17, lhsIndex)) {
        return false;
    }

    if (ops[1].type == AARCH64_OP_REG) {
        uint32_t rhsIndex = 0;
        if (!appendRegValueOrZero(ops[1].reg, AARCH64_REG_X15, rhsIndex)) {
            return false;
        }
        if (ops[1].shift.type == AARCH64_SFT_LSL && ops[1].shift.value != 0) {
            uint32_t shiftIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X14));
            out.push_back(OP_BINARY_IMM);
            out.push_back(BIN_SHL);
            out.push_back(typeIndex);
            out.push_back(rhsIndex);
            out.push_back(static_cast<uint32_t>(ops[1].shift.value));
            out.push_back(shiftIndex);
            rhsIndex = shiftIndex;
        }
        out.push_back(OP_BINARY);
        out.push_back(BIN_SUB | BIN_UPDATE_FLAGS);
        out.push_back(typeIndex);
        out.push_back(lhsIndex);
        out.push_back(rhsIndex);
        out.push_back(dstIndex);
        opcodeList = std::move(out);
        return true;
    }

    if (ops[1].type == AARCH64_OP_IMM) {
        uint64_t imm64 = static_cast<uint64_t>(ops[1].imm);
        if (ops[1].shift.type == AARCH64_SFT_LSL && ops[1].shift.value != 0) {
            imm64 <<= static_cast<uint32_t>(ops[1].shift.value);
        }
        if (isArm64WReg(ops[0].reg)) {
            imm64 &= 0xFFFFFFFFull;
        }
        out.push_back(OP_BINARY_IMM);
        out.push_back(BIN_SUB | BIN_UPDATE_FLAGS);
        out.push_back(typeIndex);
        out.push_back(lhsIndex);
        out.push_back(static_cast<uint32_t>(imm64 & 0xFFFFFFFFull));
        out.push_back(dstIndex);
        opcodeList = std::move(out);
        return true;
    }

    return false;
}

bool tryEmitLslLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    const cs_insn& instruction,
    uint8_t opCount,
    cs_arm64_op* ops
) {
    // 统一处理 lsl 的多种 Capstone 操作数形态。
    // 严格模式：仅依据结构化 operands 翻译，不再回退解析 op_str 文本。
    (void)instruction;
    if (ops == nullptr || opCount < 1 || ops[0].type != AARCH64_OP_REG) {
        return false;
    }

    uint32_t dstIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(ops[0].reg));
    uint32_t typeIndex = getOrAddTypeTag(typeIdList, TYPE_TAG_INT64_SIGNED);

    // 常规三操作数形态：lsl dst, src, #imm / lsl dst, src, shiftReg
    if (opCount >= 3 && ops[1].type == AARCH64_OP_REG) {
        uint32_t lhsIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(ops[1].reg));
        if (ops[2].type == AARCH64_OP_IMM) {
            opcodeList = {
                OP_BINARY_IMM,
                BIN_SHL,
                typeIndex,
                lhsIndex,
                static_cast<uint32_t>(ops[2].imm),
                dstIndex
            };
            return true;
        }
        if (ops[2].type == AARCH64_OP_REG) {
            uint32_t rhsIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(ops[2].reg));
            opcodeList = { OP_BINARY, BIN_SHL, typeIndex, lhsIndex, rhsIndex, dstIndex };
            return true;
        }
    }

    // 二操作数 + shift 元信息形态：lsl dst, src, #imm。
    if (opCount >= 2 && ops[1].type == AARCH64_OP_REG) {
        uint32_t lhsIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(ops[1].reg));
        if (ops[1].shift.type == AARCH64_SFT_LSL && ops[1].shift.value != 0) {
            opcodeList = {
                OP_BINARY_IMM,
                BIN_SHL,
                typeIndex,
                lhsIndex,
                static_cast<uint32_t>(ops[1].shift.value),
                dstIndex
            };
            return true;
        }
        if (ops[1].shift.type == AARCH64_SFT_LSL_REG) {
            uint32_t rhsIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(ops[1].shift.value));
            opcodeList = { OP_BINARY, BIN_SHL, typeIndex, lhsIndex, rhsIndex, dstIndex };
            return true;
        }
        if (ops[0].shift.type == AARCH64_SFT_LSL && ops[0].shift.value != 0) {
            opcodeList = {
                OP_BINARY_IMM,
                BIN_SHL,
                typeIndex,
                lhsIndex,
                static_cast<uint32_t>(ops[0].shift.value),
                dstIndex
            };
            return true;
        }
        if (ops[0].shift.type == AARCH64_SFT_LSL_REG) {
            uint32_t rhsIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(ops[0].shift.value));
            opcodeList = { OP_BINARY, BIN_SHL, typeIndex, lhsIndex, rhsIndex, dstIndex };
            return true;
        }
    }

    // 极端形态：lsl dst, #imm（隐式 src=dst）。
    if (opCount >= 2 && ops[1].type == AARCH64_OP_IMM) {
        opcodeList = {
            OP_BINARY_IMM,
            BIN_SHL,
            typeIndex,
            dstIndex,
            static_cast<uint32_t>(ops[1].imm),
            dstIndex
        };
        return true;
    }

    return false;
}

bool tryEmitLsrLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    const cs_insn& instruction,
    uint8_t opCount,
    cs_arm64_op* ops
) {
    // 统一处理 lsr 的多种 Capstone 操作数形态（含 *_REG shift 退化为 op_count=2 的场景）。
    // 严格模式：仅依据结构化 operands 翻译，不再回退解析 op_str 文本。
    (void)instruction;
    if (ops == nullptr || opCount < 1 || ops[0].type != AARCH64_OP_REG || !isArm64GpReg(ops[0].reg)) {
        return false;
    }

    uint32_t dstIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(ops[0].reg));
    uint32_t typeIndex = getOrAddTypeTagForRegWidth(typeIdList, ops[0].reg);

    auto appendWMaskIfNeeded = [&]() {
        if (isArm64WReg(ops[0].reg)) {
            opcodeList.push_back(OP_BINARY_IMM);
            opcodeList.push_back(BIN_AND);
            opcodeList.push_back(getOrAddTypeTag(typeIdList, TYPE_TAG_INT32_UNSIGNED));
            opcodeList.push_back(dstIndex);
            opcodeList.push_back(0xFFFFFFFFu);
            opcodeList.push_back(dstIndex);
        }
    };

    // 常规三操作数形态：lsr dst, src, #imm / lsr dst, src, shiftReg
    if (opCount >= 3 && ops[1].type == AARCH64_OP_REG) {
        uint32_t lhsIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(ops[1].reg));
        if (ops[2].type == AARCH64_OP_IMM) {
            opcodeList = {
                OP_BINARY_IMM,
                BIN_LSR,
                typeIndex,
                lhsIndex,
                static_cast<uint32_t>(ops[2].imm),
                dstIndex
            };
            appendWMaskIfNeeded();
            return true;
        }
        if (ops[2].type == AARCH64_OP_REG) {
            uint32_t rhsIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(ops[2].reg));
            opcodeList = { OP_BINARY, BIN_LSR, typeIndex, lhsIndex, rhsIndex, dstIndex };
            appendWMaskIfNeeded();
            return true;
        }
    }

    // 二操作数 + shift 元信息形态：lsr dst, src, #imm / lsr dst, src, shiftReg。
    if (opCount >= 2 && ops[1].type == AARCH64_OP_REG) {
        uint32_t lhsIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(ops[1].reg));
        if (ops[1].shift.type == AARCH64_SFT_LSR && ops[1].shift.value != 0) {
            opcodeList = {
                OP_BINARY_IMM,
                BIN_LSR,
                typeIndex,
                lhsIndex,
                static_cast<uint32_t>(ops[1].shift.value),
                dstIndex
            };
            appendWMaskIfNeeded();
            return true;
        }
        if (ops[1].shift.type == AARCH64_SFT_LSR_REG) {
            uint32_t rhsIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(ops[1].shift.value));
            opcodeList = { OP_BINARY, BIN_LSR, typeIndex, lhsIndex, rhsIndex, dstIndex };
            appendWMaskIfNeeded();
            return true;
        }
        if (ops[0].shift.type == AARCH64_SFT_LSR && ops[0].shift.value != 0) {
            opcodeList = {
                OP_BINARY_IMM,
                BIN_LSR,
                typeIndex,
                lhsIndex,
                static_cast<uint32_t>(ops[0].shift.value),
                dstIndex
            };
            appendWMaskIfNeeded();
            return true;
        }
        if (ops[0].shift.type == AARCH64_SFT_LSR_REG) {
            uint32_t rhsIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(ops[0].shift.value));
            opcodeList = { OP_BINARY, BIN_LSR, typeIndex, lhsIndex, rhsIndex, dstIndex };
            appendWMaskIfNeeded();
            return true;
        }
    }

    // 极端形态：lsr dst, #imm（隐式 src=dst）。
    if (opCount >= 2 && ops[1].type == AARCH64_OP_IMM) {
        opcodeList = {
            OP_BINARY_IMM,
            BIN_LSR,
            typeIndex,
            dstIndex,
            static_cast<uint32_t>(ops[1].imm),
            dstIndex
        };
        appendWMaskIfNeeded();
        return true;
    }

    return false;
}

bool tryEmitAsrLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    const cs_insn& instruction,
    uint8_t opCount,
    cs_arm64_op* ops
) {
    // 统一处理 asr 的多种 Capstone 操作数形态（含 *_REG shift 退化为 op_count=2 的场景）。
    // 严格模式：仅依据结构化 operands 翻译，不再回退解析 op_str 文本。
    (void)instruction;
    if (ops == nullptr || opCount < 1 || ops[0].type != AARCH64_OP_REG || !isArm64GpReg(ops[0].reg)) {
        return false;
    }

    uint32_t dstIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(ops[0].reg));
    uint32_t typeIndex = getOrAddTypeTagForRegWidth(typeIdList, ops[0].reg);

    auto appendWMaskIfNeeded = [&]() {
        if (isArm64WReg(ops[0].reg)) {
            opcodeList.push_back(OP_BINARY_IMM);
            opcodeList.push_back(BIN_AND);
            opcodeList.push_back(getOrAddTypeTag(typeIdList, TYPE_TAG_INT32_UNSIGNED));
            opcodeList.push_back(dstIndex);
            opcodeList.push_back(0xFFFFFFFFu);
            opcodeList.push_back(dstIndex);
        }
    };

    // 常规三操作数形态：asr dst, src, #imm / asr dst, src, shiftReg
    if (opCount >= 3 && ops[1].type == AARCH64_OP_REG) {
        uint32_t lhsIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(ops[1].reg));
        if (ops[2].type == AARCH64_OP_IMM) {
            opcodeList = {
                OP_BINARY_IMM,
                BIN_ASR,
                typeIndex,
                lhsIndex,
                static_cast<uint32_t>(ops[2].imm),
                dstIndex
            };
            appendWMaskIfNeeded();
            return true;
        }
        if (ops[2].type == AARCH64_OP_REG) {
            uint32_t rhsIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(ops[2].reg));
            opcodeList = { OP_BINARY, BIN_ASR, typeIndex, lhsIndex, rhsIndex, dstIndex };
            appendWMaskIfNeeded();
            return true;
        }
    }

    // 二操作数 + shift 元信息形态：asr dst, src, #imm / asr dst, src, shiftReg。
    if (opCount >= 2 && ops[1].type == AARCH64_OP_REG) {
        uint32_t lhsIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(ops[1].reg));
        if (ops[1].shift.type == AARCH64_SFT_ASR && ops[1].shift.value != 0) {
            opcodeList = {
                OP_BINARY_IMM,
                BIN_ASR,
                typeIndex,
                lhsIndex,
                static_cast<uint32_t>(ops[1].shift.value),
                dstIndex
            };
            appendWMaskIfNeeded();
            return true;
        }
        if (ops[1].shift.type == AARCH64_SFT_ASR_REG) {
            uint32_t rhsIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(ops[1].shift.value));
            opcodeList = { OP_BINARY, BIN_ASR, typeIndex, lhsIndex, rhsIndex, dstIndex };
            appendWMaskIfNeeded();
            return true;
        }
        if (ops[0].shift.type == AARCH64_SFT_ASR && ops[0].shift.value != 0) {
            opcodeList = {
                OP_BINARY_IMM,
                BIN_ASR,
                typeIndex,
                lhsIndex,
                static_cast<uint32_t>(ops[0].shift.value),
                dstIndex
            };
            appendWMaskIfNeeded();
            return true;
        }
        if (ops[0].shift.type == AARCH64_SFT_ASR_REG) {
            uint32_t rhsIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(ops[0].shift.value));
            opcodeList = { OP_BINARY, BIN_ASR, typeIndex, lhsIndex, rhsIndex, dstIndex };
            appendWMaskIfNeeded();
            return true;
        }
    }

    // 极端形态：asr dst, #imm（隐式 src=dst）。
    if (opCount >= 2 && ops[1].type == AARCH64_OP_IMM) {
        opcodeList = {
            OP_BINARY_IMM,
            BIN_ASR,
            typeIndex,
            dstIndex,
            static_cast<uint32_t>(ops[1].imm),
            dstIndex
        };
        appendWMaskIfNeeded();
        return true;
    }

    return false;
}

// 统一处理 neg 语义：dst = 0 - src。
bool tryEmitNegLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    unsigned int dstReg,
    unsigned int srcReg
) {
    if (!isArm64GpReg(dstReg) || !isArm64GpReg(srcReg) || isArm64ZeroReg(dstReg)) {
        return false;
    }

    uint32_t dstIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(dstReg));
    if (isArm64ZeroReg(srcReg)) {
        opcodeList = { OP_LOAD_IMM, dstIndex, 0u };
        return true;
    }

    uint32_t srcIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(srcReg));
    uint32_t typeIndex = getOrAddTypeTagForRegWidth(typeIdList, dstReg);
    uint32_t zeroIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X16));
    opcodeList = {
        OP_LOAD_IMM,
        zeroIndex,
        0u,
        OP_BINARY,
        BIN_SUB,
        typeIndex,
        zeroIndex,
        srcIndex,
        dstIndex
    };
    if (isArm64WReg(dstReg)) {
        opcodeList.push_back(OP_BINARY_IMM);
        opcodeList.push_back(BIN_AND);
        opcodeList.push_back(getOrAddTypeTag(typeIdList, TYPE_TAG_INT32_UNSIGNED));
        opcodeList.push_back(dstIndex);
        opcodeList.push_back(0xFFFFFFFFu);
        opcodeList.push_back(dstIndex);
    }
    return true;
}

// 统一处理按位取反：dst = ~src（按 dst 位宽收口）。
bool tryEmitBitwiseNotLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    unsigned int dstReg,
    unsigned int srcReg
) {
    if (!isArm64GpReg(dstReg) || !isArm64GpReg(srcReg) || isArm64ZeroReg(dstReg)) {
        return false;
    }

    const bool isWidth32 = isArm64WReg(dstReg);
    const uint64_t allOnes = isWidth32 ? 0xFFFFFFFFull : 0xFFFFFFFFFFFFFFFFull;
    const uint32_t typeIndex = isWidth32
                               ? getOrAddTypeTag(typeIdList, TYPE_TAG_INT32_UNSIGNED)
                               : getOrAddTypeTag(typeIdList, TYPE_TAG_INT64_UNSIGNED);
    const uint32_t dstIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(dstReg));

    if (isArm64ZeroReg(srcReg)) {
        emitLoadImm(opcodeList, dstIndex, allOnes);
        return true;
    }

    const uint32_t srcIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(srcReg));
    const uint32_t maskIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X16));
    std::vector<uint32_t> loadMaskOps;
    emitLoadImm(loadMaskOps, maskIndex, allOnes);
    opcodeList.insert(opcodeList.end(), loadMaskOps.begin(), loadMaskOps.end());
    opcodeList.push_back(OP_BINARY);
    opcodeList.push_back(BIN_XOR);
    opcodeList.push_back(typeIndex);
    opcodeList.push_back(srcIndex);
    opcodeList.push_back(maskIndex);
    opcodeList.push_back(dstIndex);
    if (isWidth32) {
        opcodeList.push_back(OP_BINARY_IMM);
        opcodeList.push_back(BIN_AND);
        opcodeList.push_back(typeIndex);
        opcodeList.push_back(dstIndex);
        opcodeList.push_back(0xFFFFFFFFu);
        opcodeList.push_back(dstIndex);
    }
    return true;
}

// 统一处理 {u,s}mull / {u,s}maddl（32bit 源扩展到 64bit 后做乘/加）。
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
) {
    if (!isArm64GpReg(dstReg) || isArm64ZeroReg(dstReg) || !isArm64GpReg(lhsReg) || !isArm64GpReg(rhsReg)) {
        return false;
    }
    if (hasAdd && !isArm64GpReg(addReg)) {
        return false;
    }

    const uint32_t dstIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(dstReg));
    const uint32_t lhsWideIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X16));
    const uint32_t rhsWideIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X17));
    const uint32_t mulIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X14));
    const uint32_t typeIndex = getOrAddTypeTag(typeIdList, signedMode ? TYPE_TAG_INT64_SIGNED : TYPE_TAG_INT64_UNSIGNED);
    const uint32_t srcTypeIndex = getOrAddTypeTag(typeIdList, signedMode ? TYPE_TAG_INT32_SIGNED_2 : TYPE_TAG_INT32_UNSIGNED);
    const uint32_t dstTypeIndex = getOrAddTypeTag(typeIdList, signedMode ? TYPE_TAG_INT64_SIGNED : TYPE_TAG_INT64_UNSIGNED);

    auto appendExtend32To64 = [&](unsigned int srcReg, uint32_t outIndex) -> bool {
        if (!isArm64GpReg(srcReg)) {
            return false;
        }
        if (isArm64ZeroReg(srcReg)) {
            opcodeList.push_back(OP_LOAD_IMM);
            opcodeList.push_back(outIndex);
            opcodeList.push_back(0u);
            return true;
        }
        uint32_t srcIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(srcReg));
        opcodeList.push_back(signedMode ? OP_SIGN_EXTEND : OP_ZERO_EXTEND);
        opcodeList.push_back(srcTypeIndex);
        opcodeList.push_back(dstTypeIndex);
        opcodeList.push_back(srcIndex);
        opcodeList.push_back(outIndex);
        return true;
    };

    if (!appendExtend32To64(lhsReg, lhsWideIndex) || !appendExtend32To64(rhsReg, rhsWideIndex)) {
        return false;
    }

    opcodeList.push_back(OP_BINARY);
    opcodeList.push_back(BIN_MUL);
    opcodeList.push_back(typeIndex);
    opcodeList.push_back(lhsWideIndex);
    opcodeList.push_back(rhsWideIndex);
    opcodeList.push_back(mulIndex);

    if (hasAdd) {
        uint32_t addIndex = 0;
        if (isArm64ZeroReg(addReg)) {
            addIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X13));
            opcodeList.push_back(OP_LOAD_IMM);
            opcodeList.push_back(addIndex);
            opcodeList.push_back(0u);
        } else {
            addIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(addReg));
        }
        opcodeList.push_back(OP_BINARY);
        opcodeList.push_back(BIN_ADD);
        opcodeList.push_back(typeIndex);
        opcodeList.push_back(mulIndex);
        opcodeList.push_back(addIndex);
        opcodeList.push_back(dstIndex);
    } else if (mulIndex != dstIndex) {
        opcodeList.push_back(OP_MOV);
        opcodeList.push_back(mulIndex);
        opcodeList.push_back(dstIndex);
    }

    if (isArm64WReg(dstReg)) {
        opcodeList.push_back(OP_BINARY_IMM);
        opcodeList.push_back(BIN_AND);
        opcodeList.push_back(getOrAddTypeTag(typeIdList, TYPE_TAG_INT32_UNSIGNED));
        opcodeList.push_back(dstIndex);
        opcodeList.push_back(0xFFFFFFFFu);
        opcodeList.push_back(dstIndex);
    }
    return true;
}

// 统一处理 {u,s}mulh：返回 64x64 乘法结果的高 64 位。
bool tryEmitMulHighLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    unsigned int dstReg,
    unsigned int lhsReg,
    unsigned int rhsReg,
    bool signedMode
) {
    if (!isArm64GpReg(dstReg) || !isArm64GpReg(lhsReg) || !isArm64GpReg(rhsReg) || isArm64ZeroReg(dstReg)) {
        return false;
    }

    const uint32_t typeU64 = getOrAddTypeTag(typeIdList, TYPE_TAG_INT64_UNSIGNED);
    const uint32_t typeS64 = getOrAddTypeTag(typeIdList, TYPE_TAG_INT64_SIGNED);
    const uint32_t dstIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(dstReg));

    auto getRegValueOrZero = [&](unsigned int reg, unsigned int zeroTmpReg) -> uint32_t {
        if (isArm64ZeroReg(reg)) {
            uint32_t zeroIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(zeroTmpReg));
            opcodeList.push_back(OP_LOAD_IMM);
            opcodeList.push_back(zeroIndex);
            opcodeList.push_back(0u);
            return zeroIndex;
        }
        return getOrAddReg(regIdList, arm64CapstoneToArchIndex(reg));
    };

    const uint32_t lhsIndex = getRegValueOrZero(lhsReg, AARCH64_REG_X15);
    const uint32_t rhsIndex = getRegValueOrZero(rhsReg, AARCH64_REG_X14);

    // 拆分寄存器：
    // a = a_hi<<32 + a_lo
    // b = b_hi<<32 + b_lo
    const uint32_t aLo = getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X16));
    const uint32_t aHi = getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X17));
    const uint32_t bLo = getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X13));
    const uint32_t bHi = getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X12));

    // 乘积分块：
    const uint32_t p0 = getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X11)); // a_lo * b_lo
    const uint32_t p1 = getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X10)); // a_lo * b_hi
    const uint32_t p2 = getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X9));  // a_hi * b_lo
    const uint32_t p3 = getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X8));  // a_hi * b_hi

    const uint32_t mid = getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X7));
    const uint32_t tmp0 = getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X6));
    const uint32_t tmp1 = getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X5));
    const uint32_t high = getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X4));

    // a_lo / a_hi / b_lo / b_hi。
    opcodeList.push_back(OP_BINARY_IMM);
    opcodeList.push_back(BIN_AND);
    opcodeList.push_back(typeU64);
    opcodeList.push_back(lhsIndex);
    opcodeList.push_back(0xFFFFFFFFu);
    opcodeList.push_back(aLo);
    opcodeList.push_back(OP_BINARY_IMM);
    opcodeList.push_back(BIN_LSR);
    opcodeList.push_back(typeU64);
    opcodeList.push_back(lhsIndex);
    opcodeList.push_back(32u);
    opcodeList.push_back(aHi);

    opcodeList.push_back(OP_BINARY_IMM);
    opcodeList.push_back(BIN_AND);
    opcodeList.push_back(typeU64);
    opcodeList.push_back(rhsIndex);
    opcodeList.push_back(0xFFFFFFFFu);
    opcodeList.push_back(bLo);
    opcodeList.push_back(OP_BINARY_IMM);
    opcodeList.push_back(BIN_LSR);
    opcodeList.push_back(typeU64);
    opcodeList.push_back(rhsIndex);
    opcodeList.push_back(32u);
    opcodeList.push_back(bHi);

    // p0..p3。
    opcodeList.push_back(OP_BINARY);
    opcodeList.push_back(BIN_MUL);
    opcodeList.push_back(typeU64);
    opcodeList.push_back(aLo);
    opcodeList.push_back(bLo);
    opcodeList.push_back(p0);
    opcodeList.push_back(OP_BINARY);
    opcodeList.push_back(BIN_MUL);
    opcodeList.push_back(typeU64);
    opcodeList.push_back(aLo);
    opcodeList.push_back(bHi);
    opcodeList.push_back(p1);
    opcodeList.push_back(OP_BINARY);
    opcodeList.push_back(BIN_MUL);
    opcodeList.push_back(typeU64);
    opcodeList.push_back(aHi);
    opcodeList.push_back(bLo);
    opcodeList.push_back(p2);
    opcodeList.push_back(OP_BINARY);
    opcodeList.push_back(BIN_MUL);
    opcodeList.push_back(typeU64);
    opcodeList.push_back(aHi);
    opcodeList.push_back(bHi);
    opcodeList.push_back(p3);

    // mid = (p0 >> 32) + (p1 & 0xffffffff) + (p2 & 0xffffffff)
    opcodeList.push_back(OP_BINARY_IMM);
    opcodeList.push_back(BIN_LSR);
    opcodeList.push_back(typeU64);
    opcodeList.push_back(p0);
    opcodeList.push_back(32u);
    opcodeList.push_back(mid);

    opcodeList.push_back(OP_BINARY_IMM);
    opcodeList.push_back(BIN_AND);
    opcodeList.push_back(typeU64);
    opcodeList.push_back(p1);
    opcodeList.push_back(0xFFFFFFFFu);
    opcodeList.push_back(tmp0);
    opcodeList.push_back(OP_BINARY);
    opcodeList.push_back(BIN_ADD);
    opcodeList.push_back(typeU64);
    opcodeList.push_back(mid);
    opcodeList.push_back(tmp0);
    opcodeList.push_back(mid);

    opcodeList.push_back(OP_BINARY_IMM);
    opcodeList.push_back(BIN_AND);
    opcodeList.push_back(typeU64);
    opcodeList.push_back(p2);
    opcodeList.push_back(0xFFFFFFFFu);
    opcodeList.push_back(tmp1);
    opcodeList.push_back(OP_BINARY);
    opcodeList.push_back(BIN_ADD);
    opcodeList.push_back(typeU64);
    opcodeList.push_back(mid);
    opcodeList.push_back(tmp1);
    opcodeList.push_back(mid);

    // high = p3 + (p1>>32) + (p2>>32) + (mid>>32)
    opcodeList.push_back(OP_MOV);
    opcodeList.push_back(p3);
    opcodeList.push_back(high);

    opcodeList.push_back(OP_BINARY_IMM);
    opcodeList.push_back(BIN_LSR);
    opcodeList.push_back(typeU64);
    opcodeList.push_back(p1);
    opcodeList.push_back(32u);
    opcodeList.push_back(tmp0);
    opcodeList.push_back(OP_BINARY);
    opcodeList.push_back(BIN_ADD);
    opcodeList.push_back(typeU64);
    opcodeList.push_back(high);
    opcodeList.push_back(tmp0);
    opcodeList.push_back(high);

    opcodeList.push_back(OP_BINARY_IMM);
    opcodeList.push_back(BIN_LSR);
    opcodeList.push_back(typeU64);
    opcodeList.push_back(p2);
    opcodeList.push_back(32u);
    opcodeList.push_back(tmp1);
    opcodeList.push_back(OP_BINARY);
    opcodeList.push_back(BIN_ADD);
    opcodeList.push_back(typeU64);
    opcodeList.push_back(high);
    opcodeList.push_back(tmp1);
    opcodeList.push_back(high);

    opcodeList.push_back(OP_BINARY_IMM);
    opcodeList.push_back(BIN_LSR);
    opcodeList.push_back(typeU64);
    opcodeList.push_back(mid);
    opcodeList.push_back(32u);
    opcodeList.push_back(tmp0);
    opcodeList.push_back(OP_BINARY);
    opcodeList.push_back(BIN_ADD);
    opcodeList.push_back(typeU64);
    opcodeList.push_back(high);
    opcodeList.push_back(tmp0);
    opcodeList.push_back(high);

    if (!signedMode) {
        if (high != dstIndex) {
            opcodeList.push_back(OP_MOV);
            opcodeList.push_back(high);
            opcodeList.push_back(dstIndex);
        }
        if (isArm64WReg(dstReg)) {
            opcodeList.push_back(OP_BINARY_IMM);
            opcodeList.push_back(BIN_AND);
            opcodeList.push_back(getOrAddTypeTag(typeIdList, TYPE_TAG_INT32_UNSIGNED));
            opcodeList.push_back(dstIndex);
            opcodeList.push_back(0xFFFFFFFFu);
            opcodeList.push_back(dstIndex);
        }
        return true;
    }

    // smulh = umulh - ((a>>63) * b) - ((b>>63) * a)
    const uint32_t signA = getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X3));
    const uint32_t signB = getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X2));
    const uint32_t corr0 = getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X1));
    const uint32_t corr1 = getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X0));

    opcodeList.push_back(OP_BINARY_IMM);
    opcodeList.push_back(BIN_LSR);
    opcodeList.push_back(typeU64);
    opcodeList.push_back(lhsIndex);
    opcodeList.push_back(63u);
    opcodeList.push_back(signA);
    opcodeList.push_back(OP_BINARY_IMM);
    opcodeList.push_back(BIN_LSR);
    opcodeList.push_back(typeU64);
    opcodeList.push_back(rhsIndex);
    opcodeList.push_back(63u);
    opcodeList.push_back(signB);

    opcodeList.push_back(OP_BINARY);
    opcodeList.push_back(BIN_MUL);
    opcodeList.push_back(typeU64);
    opcodeList.push_back(signA);
    opcodeList.push_back(rhsIndex);
    opcodeList.push_back(corr0);
    opcodeList.push_back(OP_BINARY);
    opcodeList.push_back(BIN_MUL);
    opcodeList.push_back(typeU64);
    opcodeList.push_back(signB);
    opcodeList.push_back(lhsIndex);
    opcodeList.push_back(corr1);

    opcodeList.push_back(OP_BINARY);
    opcodeList.push_back(BIN_SUB);
    opcodeList.push_back(typeS64);
    opcodeList.push_back(high);
    opcodeList.push_back(corr0);
    opcodeList.push_back(high);
    opcodeList.push_back(OP_BINARY);
    opcodeList.push_back(BIN_SUB);
    opcodeList.push_back(typeS64);
    opcodeList.push_back(high);
    opcodeList.push_back(corr1);
    opcodeList.push_back(high);

    if (high != dstIndex) {
        opcodeList.push_back(OP_MOV);
        opcodeList.push_back(high);
        opcodeList.push_back(dstIndex);
    }
    if (isArm64WReg(dstReg)) {
        opcodeList.push_back(OP_BINARY_IMM);
        opcodeList.push_back(BIN_AND);
        opcodeList.push_back(getOrAddTypeTag(typeIdList, TYPE_TAG_INT32_UNSIGNED));
        opcodeList.push_back(dstIndex);
        opcodeList.push_back(0xFFFFFFFFu);
        opcodeList.push_back(dstIndex);
    }

    return true;
}

// 统一处理 ror 语义：dst = (src >> n) | (src << (width-n))。
bool tryEmitRorLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    const cs_insn& instruction,
    uint8_t opCount,
    cs_arm64_op* ops
) {
    // 严格模式：仅依据结构化 operands 翻译，不再回退解析 op_str 文本。
    (void)instruction;
    if (ops == nullptr || opCount < 1 || ops[0].type != AARCH64_OP_REG || !isArm64GpReg(ops[0].reg)) {
        return false;
    }

    const bool isWidth32 = isArm64WReg(ops[0].reg);
    const uint32_t bitWidth = isWidth32 ? 32u : 64u;
    uint32_t dstIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(ops[0].reg));
    uint32_t typeIndex = getOrAddTypeTagForRegWidth(typeIdList, ops[0].reg);

    auto appendWMaskIfNeeded = [&]() {
        if (isWidth32) {
            opcodeList.push_back(OP_BINARY_IMM);
            opcodeList.push_back(BIN_AND);
            opcodeList.push_back(getOrAddTypeTag(typeIdList, TYPE_TAG_INT32_UNSIGNED));
            opcodeList.push_back(dstIndex);
            opcodeList.push_back(0xFFFFFFFFu);
            opcodeList.push_back(dstIndex);
        }
    };

    auto emitByImmediate = [&](uint32_t shift, uint32_t srcIndex) -> bool {
        shift %= bitWidth;
        std::vector<uint32_t> out = opcodeList;
        if (shift == 0u) {
            out.push_back(OP_MOV);
            out.push_back(srcIndex);
            out.push_back(dstIndex);
            opcodeList = std::move(out);
            appendWMaskIfNeeded();
            return true;
        }
        uint32_t rightIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X16));
        uint32_t leftIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X17));
        out.push_back(OP_BINARY_IMM);
        out.push_back(BIN_LSR);
        out.push_back(typeIndex);
        out.push_back(srcIndex);
        out.push_back(shift);
        out.push_back(rightIndex);
        out.push_back(OP_BINARY_IMM);
        out.push_back(BIN_SHL);
        out.push_back(typeIndex);
        out.push_back(srcIndex);
        out.push_back(bitWidth - shift);
        out.push_back(leftIndex);
        out.push_back(OP_BINARY);
        out.push_back(BIN_OR);
        out.push_back(typeIndex);
        out.push_back(rightIndex);
        out.push_back(leftIndex);
        out.push_back(dstIndex);
        opcodeList = std::move(out);
        appendWMaskIfNeeded();
        return true;
    };

    auto resolveSrcIndex = [&](uint32_t& outSrcIndex) -> bool {
        if (opCount >= 2 && ops[1].type == AARCH64_OP_REG && isArm64GpReg(ops[1].reg)) {
            if (isArm64ZeroReg(ops[1].reg)) {
                outSrcIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X15));
                opcodeList = { OP_LOAD_IMM, outSrcIndex, 0u };
            } else {
                outSrcIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(ops[1].reg));
            }
            return true;
        }
        outSrcIndex = dstIndex;
        return true;
    };

    // 常规三操作数：ror dst, src, #imm / reg。
    if (opCount >= 3 && ops[1].type == AARCH64_OP_REG && isArm64GpReg(ops[1].reg)) {
        uint32_t srcIndex = isArm64ZeroReg(ops[1].reg)
                            ? getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X15))
                            : getOrAddReg(regIdList, arm64CapstoneToArchIndex(ops[1].reg));
        if (isArm64ZeroReg(ops[1].reg)) {
            opcodeList = { OP_LOAD_IMM, srcIndex, 0u };
        }
        if (ops[2].type == AARCH64_OP_IMM) {
            return emitByImmediate(static_cast<uint32_t>(ops[2].imm), srcIndex);
        }
    }

    // 二操作数 + shift 元信息：ror dst, src, #imm。
    if (opCount >= 2 && ops[1].type == AARCH64_OP_REG) {
        uint32_t srcIndex = 0;
        if (!resolveSrcIndex(srcIndex)) {
            return false;
        }
        if (ops[1].shift.type == AARCH64_SFT_ROR && ops[1].shift.value != 0) {
            return emitByImmediate(static_cast<uint32_t>(ops[1].shift.value), srcIndex);
        }
        if (ops[0].shift.type == AARCH64_SFT_ROR && ops[0].shift.value != 0) {
            return emitByImmediate(static_cast<uint32_t>(ops[0].shift.value), srcIndex);
        }
    }

    return false;
}

bool tryEmitExtendLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    unsigned int dstReg,
    unsigned int srcReg,
    bool signExtend,
    uint32_t srcTypeTag
) {
    // 统一处理 sxt*/uxt* 指令族。
    if (!isArm64GpReg(dstReg) || !isArm64GpReg(srcReg) || isArm64ZeroReg(dstReg)) {
        return false;
    }

    uint32_t dstIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(dstReg));
    if (isArm64ZeroReg(srcReg)) {
        // 源为零寄存器时直接写 0。
        opcodeList = { OP_LOAD_IMM, dstIndex, 0 };
        return true;
    }

    uint32_t srcIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(srcReg));
    uint32_t srcTypeIndex = getOrAddTypeTag(typeIdList, srcTypeTag);
    uint32_t dstTypeTag = isArm64WReg(dstReg)
                          ? (signExtend ? TYPE_TAG_INT32_SIGNED_2 : TYPE_TAG_INT32_UNSIGNED)
                          : TYPE_TAG_INT64_SIGNED;
    uint32_t dstTypeIndex = getOrAddTypeTag(typeIdList, dstTypeTag);

    opcodeList = {
        signExtend ? OP_SIGN_EXTEND : OP_ZERO_EXTEND,
        srcTypeIndex,
        dstTypeIndex,
        srcIndex,
        dstIndex
    };

    // w 寄存器写入语义：高 32 位清零。
    if (isArm64WReg(dstReg) && signExtend) {
        uint32_t typeIndex = getOrAddTypeTag(typeIdList, TYPE_TAG_INT64_SIGNED);
        opcodeList.push_back(OP_BINARY_IMM);
        opcodeList.push_back(BIN_AND);
        opcodeList.push_back(typeIndex);
        opcodeList.push_back(dstIndex);
        opcodeList.push_back(0xFFFFFFFFu);
        opcodeList.push_back(dstIndex);
    }
    return true;
}

uint32_t getOrAddTypeTag(std::vector<uint32_t>& typeIdList, uint32_t typeTag) {
    // 返回类型标签在 typeIdList 中的索引，不存在则追加。
    for (size_t typeIndex = 0; typeIndex < typeIdList.size(); ++typeIndex) {
        if (typeIdList[typeIndex] == typeTag) return static_cast<uint32_t>(typeIndex);
    }
    typeIdList.push_back(typeTag);
    return static_cast<uint32_t>(typeIdList.size() - 1);
}

uint32_t getOrAddTypeTagForRegWidth(std::vector<uint32_t>& typeIdList, unsigned int reg) {
    // 32 位寄存器映射到 int32 标签，其余走 int64 标签。
    const bool isWide32 = isArm64WReg(reg);
    return getOrAddTypeTag(typeIdList, isWide32 ? TYPE_TAG_INT32_SIGNED_2 : TYPE_TAG_INT64_SIGNED);
}

// 追加“按位与掩码”语义：优先用 imm32，超出时退化到加载常量再寄存器与。
void appendAndByMask(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    uint32_t srcIndex,
    uint32_t dstIndex,
    uint64_t mask,
    uint32_t typeIndex,
    unsigned int tmpMaskReg
) {
    if (mask <= 0xFFFFFFFFull) {
        opcodeList.push_back(OP_BINARY_IMM);
        opcodeList.push_back(BIN_AND);
        opcodeList.push_back(typeIndex);
        opcodeList.push_back(srcIndex);
        opcodeList.push_back(static_cast<uint32_t>(mask));
        opcodeList.push_back(dstIndex);
        return;
    }

    uint32_t maskIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(tmpMaskReg));
    std::vector<uint32_t> loadOps;
    emitLoadImm(loadOps, maskIndex, mask);
    opcodeList.insert(opcodeList.end(), loadOps.begin(), loadOps.end());
    opcodeList.push_back(OP_BINARY);
    opcodeList.push_back(BIN_AND);
    opcodeList.push_back(typeIndex);
    opcodeList.push_back(srcIndex);
    opcodeList.push_back(maskIndex);
    opcodeList.push_back(dstIndex);
}

// 统一处理 rev/rev16 字节重排语义（仅 GP 寄存器）。
bool tryEmitReverseBytesLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    unsigned int dstReg,
    unsigned int srcReg,
    bool onlySwapBytesInsideHalfword
) {
    if (!isArm64GpReg(dstReg) || !isArm64GpReg(srcReg) || isArm64ZeroReg(dstReg)) {
        return false;
    }

    uint32_t dstIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(dstReg));
    if (isArm64ZeroReg(srcReg)) {
        opcodeList = { OP_LOAD_IMM, dstIndex, 0 };
        return true;
    }

    uint32_t srcIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(srcReg));
    uint32_t typeIndex = getOrAddTypeTagForRegWidth(typeIdList, dstReg);
    const bool isWidth32 = isArm64WReg(dstReg);
    const uint64_t stage1Mask = isWidth32 ? 0x00FF00FFull : 0x00FF00FF00FF00FFull;
    const uint64_t stage2Mask = isWidth32 ? 0x0000FFFFull : 0x0000FFFF0000FFFFull;
    const uint64_t widthMask = isWidth32 ? 0xFFFFFFFFull : 0xFFFFFFFFFFFFFFFFull;

    uint32_t tmpA = getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X16));
    uint32_t tmpB = getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X17));
    uint32_t tmpC = getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X14));
    std::vector<uint32_t> out;

    // 第 1 步：按字节交换（ab cd -> ba dc）。
    appendAndByMask(out, regIdList, typeIdList, srcIndex, tmpA, stage1Mask, typeIndex, AARCH64_REG_X13);
    out.push_back(OP_BINARY_IMM);
    out.push_back(BIN_SHL);
    out.push_back(typeIndex);
    out.push_back(tmpA);
    out.push_back(8u);
    out.push_back(tmpA);

    out.push_back(OP_BINARY_IMM);
    out.push_back(BIN_LSR);
    out.push_back(typeIndex);
    out.push_back(srcIndex);
    out.push_back(8u);
    out.push_back(tmpB);
    appendAndByMask(out, regIdList, typeIdList, tmpB, tmpB, stage1Mask, typeIndex, AARCH64_REG_X12);
    out.push_back(OP_BINARY);
    out.push_back(BIN_OR);
    out.push_back(typeIndex);
    out.push_back(tmpA);
    out.push_back(tmpB);
    out.push_back(dstIndex);

    if (!onlySwapBytesInsideHalfword) {
        // 第 2 步：按半字交换（ba dc -> dc ba）。
        appendAndByMask(out, regIdList, typeIdList, dstIndex, tmpA, stage2Mask, typeIndex, AARCH64_REG_X11);
        out.push_back(OP_BINARY_IMM);
        out.push_back(BIN_SHL);
        out.push_back(typeIndex);
        out.push_back(tmpA);
        out.push_back(16u);
        out.push_back(tmpA);

        out.push_back(OP_BINARY_IMM);
        out.push_back(BIN_LSR);
        out.push_back(typeIndex);
        out.push_back(dstIndex);
        out.push_back(16u);
        out.push_back(tmpB);
        appendAndByMask(out, regIdList, typeIdList, tmpB, tmpB, stage2Mask, typeIndex, AARCH64_REG_X10);
        out.push_back(OP_BINARY);
        out.push_back(BIN_OR);
        out.push_back(typeIndex);
        out.push_back(tmpA);
        out.push_back(tmpB);
        out.push_back(dstIndex);

        if (!isWidth32) {
            // 第 3 步：64 位再按字交换（32-bit block swap）。
            out.push_back(OP_BINARY_IMM);
            out.push_back(BIN_SHL);
            out.push_back(typeIndex);
            out.push_back(dstIndex);
            out.push_back(32u);
            out.push_back(tmpA);
            out.push_back(OP_BINARY_IMM);
            out.push_back(BIN_LSR);
            out.push_back(typeIndex);
            out.push_back(dstIndex);
            out.push_back(32u);
            out.push_back(tmpB);
            out.push_back(OP_BINARY);
            out.push_back(BIN_OR);
            out.push_back(typeIndex);
            out.push_back(tmpA);
            out.push_back(tmpB);
            out.push_back(dstIndex);
        }
    }

    // w 写回语义：高 32 位清零。
    appendAndByMask(out, regIdList, typeIdList, dstIndex, tmpC, widthMask, typeIndex, AARCH64_REG_X9);
    if (tmpC != dstIndex) {
        out.push_back(OP_MOV);
        out.push_back(tmpC);
        out.push_back(dstIndex);
    }

    opcodeList = std::move(out);
    return true;
}

// 统一处理 LDAXR/LDXR 语义（当前不建模 exclusive monitor，仅保留原子读序语义）。
bool tryEmitAtomicLoadExclusiveLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    unsigned int dstReg,
    unsigned int baseReg,
    int32_t offset,
    uint32_t memOrder
) {
    if (!isArm64GpReg(dstReg) || !isArm64GpReg(baseReg)) {
        return false;
    }
    const uint32_t typeIndex = isArm64WReg(dstReg)
                               ? getOrAddTypeTag(typeIdList, TYPE_TAG_INT32_UNSIGNED)
                               : getOrAddTypeTag(typeIdList, TYPE_TAG_INT64_SIGNED);
    opcodeList = {
        OP_ATOMIC_LOAD,
        typeIndex,
        getOrAddReg(regIdList, arm64CapstoneToArchIndex(baseReg)),
        static_cast<uint32_t>(offset),
        memOrder,
        getOrAddReg(regIdList, arm64CapstoneToArchIndex(dstReg))
    };
    return true;
}

// 统一处理 STLXR/STXR 语义（当前默认返回成功 status=0）。
bool tryEmitAtomicStoreExclusiveLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    unsigned int statusReg,
    unsigned int valueReg,
    unsigned int baseReg,
    int32_t offset,
    uint32_t memOrder
) {
    if (!isArm64GpReg(statusReg) || !isArm64GpReg(valueReg) || !isArm64GpReg(baseReg)) {
        return false;
    }

    const uint32_t typeIndex = isArm64WReg(valueReg)
                               ? getOrAddTypeTag(typeIdList, TYPE_TAG_INT32_UNSIGNED)
                               : getOrAddTypeTag(typeIdList, TYPE_TAG_INT64_SIGNED);
    const uint32_t valueIndex = isArm64ZeroReg(valueReg)
                                ? static_cast<uint32_t>(-1)
                                : getOrAddReg(regIdList, arm64CapstoneToArchIndex(valueReg));
    opcodeList = {
        OP_ATOMIC_STORE,
        typeIndex,
        getOrAddReg(regIdList, arm64CapstoneToArchIndex(baseReg)),
        static_cast<uint32_t>(offset),
        valueIndex,
        memOrder
    };

    if (!isArm64ZeroReg(statusReg)) {
        uint32_t statusIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(statusReg));
        opcodeList.push_back(OP_LOAD_IMM);
        opcodeList.push_back(statusIndex);
        opcodeList.push_back(0u);
    }

    return true;
}

// 对 dst 低 width 位执行精确符号扩展（支持任意 width，非仅 8/16/32）。
bool appendSignExtendFromWidth(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    unsigned int dstReg,
    uint32_t dstIndex,
    uint32_t width
) {
    const uint32_t bitWidth = isArm64WReg(dstReg) ? 32u : 64u;
    if (width == 0u || width > bitWidth) {
        return false;
    }

    const uint32_t typeIndex = getOrAddTypeTagForRegWidth(typeIdList, dstReg);
    if (width < bitWidth) {
        uint64_t signMask64 = 1ull << (width - 1u);
        if (signMask64 <= 0xFFFFFFFFull) {
            uint32_t signMask = static_cast<uint32_t>(signMask64);
            // (x ^ signMask) - signMask：对任意位宽做标准补码符号扩展。
            opcodeList.push_back(OP_BINARY_IMM);
            opcodeList.push_back(BIN_XOR);
            opcodeList.push_back(typeIndex);
            opcodeList.push_back(dstIndex);
            opcodeList.push_back(signMask);
            opcodeList.push_back(dstIndex);
            opcodeList.push_back(OP_BINARY_IMM);
            opcodeList.push_back(BIN_SUB);
            opcodeList.push_back(typeIndex);
            opcodeList.push_back(dstIndex);
            opcodeList.push_back(signMask);
            opcodeList.push_back(dstIndex);
        } else {
            // 64 位大常量走“加载常量 + 寄存器算术”路径。
            uint32_t signIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X14));
            std::vector<uint32_t> loadSignOps;
            emitLoadImm(loadSignOps, signIndex, signMask64);
            opcodeList.insert(opcodeList.end(), loadSignOps.begin(), loadSignOps.end());
            opcodeList.push_back(OP_BINARY);
            opcodeList.push_back(BIN_XOR);
            opcodeList.push_back(typeIndex);
            opcodeList.push_back(dstIndex);
            opcodeList.push_back(signIndex);
            opcodeList.push_back(dstIndex);
            opcodeList.push_back(OP_BINARY);
            opcodeList.push_back(BIN_SUB);
            opcodeList.push_back(typeIndex);
            opcodeList.push_back(dstIndex);
            opcodeList.push_back(signIndex);
            opcodeList.push_back(dstIndex);
        }
    }

    if (isArm64WReg(dstReg)) {
        // w 写入语义：高 32 位归零。
        uint32_t type64Index = getOrAddTypeTag(typeIdList, TYPE_TAG_INT64_SIGNED);
        opcodeList.push_back(OP_BINARY_IMM);
        opcodeList.push_back(BIN_AND);
        opcodeList.push_back(type64Index);
        opcodeList.push_back(dstIndex);
        opcodeList.push_back(0xFFFFFFFFu);
        opcodeList.push_back(dstIndex);
    }

    return true;
}

bool tryEmitBitExtractLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    unsigned int dstReg,
    unsigned int srcReg,
    uint32_t lsb,
    uint32_t width,
    bool signExtract
) {
    // 统一处理 ubfx/sbfx（bit extract）语义。
    if (!isArm64GpReg(dstReg) || !isArm64GpReg(srcReg) || isArm64ZeroReg(dstReg)) {
        return false;
    }
    if (width == 0 || lsb >= 64 || width > 64 || (lsb + width) > 64) {
        return false;
    }

    uint32_t dstIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(dstReg));
    if (isArm64ZeroReg(srcReg)) {
        // 源为零寄存器时提取结果恒为 0。
        opcodeList = { OP_LOAD_IMM, dstIndex, 0 };
        return true;
    }

    uint32_t srcIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(srcReg));
    uint32_t typeIndex = getOrAddTypeTagForRegWidth(typeIdList, dstReg);
    std::vector<uint32_t> out;

    // 第一步：右移到 bit0。
    if (lsb != 0) {
        out.push_back(OP_BINARY_IMM);
        out.push_back(BIN_LSR);
        out.push_back(typeIndex);
        out.push_back(srcIndex);
        out.push_back(lsb);
        out.push_back(dstIndex);
    } else if (srcIndex != dstIndex) {
        out.push_back(OP_MOV);
        out.push_back(srcIndex);
        out.push_back(dstIndex);
    }

    // 第二步：按 width 截断。
    if (width < 64) {
        if (width <= 32) {
            uint32_t mask = (width == 32) ? 0xFFFFFFFFu : ((1u << width) - 1u);
            out.push_back(OP_BINARY_IMM);
            out.push_back(BIN_AND);
            out.push_back(typeIndex);
            out.push_back(dstIndex);
            out.push_back(mask);
            out.push_back(dstIndex);
        } else {
            // 64 位宽掩码无法塞进 imm32，走“加载常量 + 寄存器与”。
            uint64_t mask64 = (width == 64) ? ~0ull : ((1ull << width) - 1ull);
            uint32_t maskIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X17));
            std::vector<uint32_t> loadMaskOps;
            emitLoadImm(loadMaskOps, maskIndex, mask64);
            out.insert(out.end(), loadMaskOps.begin(), loadMaskOps.end());
            out.push_back(OP_BINARY);
            out.push_back(BIN_AND);
            out.push_back(typeIndex);
            out.push_back(dstIndex);
            out.push_back(maskIndex);
            out.push_back(dstIndex);
        }
    }

    // 第三步：sbfx 需要在提取后做符号扩展。
    if (signExtract) {
        if (!appendSignExtendFromWidth(out, regIdList, typeIdList, dstReg, dstIndex, width)) {
            return false;
        }
    }

    opcodeList = std::move(out);
    return true;
}

// 统一处理 ubfiz/sbfiz：从 src 低 width 位取值，按 lsb 左移并写入 dst。
bool tryEmitBitfieldInsertLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    unsigned int dstReg,
    unsigned int srcReg,
    uint32_t lsb,
    uint32_t width,
    bool signExtract
) {
    if (!isArm64GpReg(dstReg) || !isArm64GpReg(srcReg) || isArm64ZeroReg(dstReg)) {
        return false;
    }

    const uint32_t bitWidth = isArm64WReg(dstReg) ? 32u : 64u;
    if (width == 0u || width > bitWidth || lsb >= bitWidth || (width + lsb) > bitWidth) {
        return false;
    }

    const uint32_t dstIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(dstReg));
    if (isArm64ZeroReg(srcReg)) {
        opcodeList = { OP_LOAD_IMM, dstIndex, 0 };
        return true;
    }

    const uint32_t srcIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(srcReg));
    const uint32_t typeIndex = getOrAddTypeTagForRegWidth(typeIdList, dstReg);
    std::vector<uint32_t> out;

    // 第一步：把源值搬到目标寄存器。
    if (srcIndex != dstIndex) {
        out.push_back(OP_MOV);
        out.push_back(srcIndex);
        out.push_back(dstIndex);
    }

    // 第二步：仅保留低 width 位。
    if (width < bitWidth) {
        if (width <= 32u) {
            uint32_t mask = (width == 32u) ? 0xFFFFFFFFu : ((1u << width) - 1u);
            out.push_back(OP_BINARY_IMM);
            out.push_back(BIN_AND);
            out.push_back(typeIndex);
            out.push_back(dstIndex);
            out.push_back(mask);
            out.push_back(dstIndex);
        } else {
            uint64_t mask64 = (1ull << width) - 1ull;
            uint32_t maskIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X15));
            std::vector<uint32_t> loadMaskOps;
            emitLoadImm(loadMaskOps, maskIndex, mask64);
            out.insert(out.end(), loadMaskOps.begin(), loadMaskOps.end());
            out.push_back(OP_BINARY);
            out.push_back(BIN_AND);
            out.push_back(typeIndex);
            out.push_back(dstIndex);
            out.push_back(maskIndex);
            out.push_back(dstIndex);
        }
    }

    // 第三步：sbfiz 先按 width 做符号扩展，再左移。
    if (signExtract) {
        if (!appendSignExtendFromWidth(out, regIdList, typeIdList, dstReg, dstIndex, width)) {
            return false;
        }
    }

    // 第四步：左移到目标位段。
    if (lsb != 0u) {
        out.push_back(OP_BINARY_IMM);
        out.push_back(BIN_SHL);
        out.push_back(typeIndex);
        out.push_back(dstIndex);
        out.push_back(lsb);
        out.push_back(dstIndex);
    }

    if (isArm64WReg(dstReg)) {
        // w 写回语义：高 32 位清零。
        uint32_t type64Index = getOrAddTypeTag(typeIdList, TYPE_TAG_INT64_SIGNED);
        out.push_back(OP_BINARY_IMM);
        out.push_back(BIN_AND);
        out.push_back(type64Index);
        out.push_back(dstIndex);
        out.push_back(0xFFFFFFFFu);
        out.push_back(dstIndex);
    }

    opcodeList = std::move(out);
    return true;
}

// 统一处理 bfi：把 src 的低 width 位插入到 dst 的 [lsb, lsb+width) 位段。
bool tryEmitBitfieldInsertIntoDstLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    unsigned int dstReg,
    unsigned int srcReg,
    uint32_t lsb,
    uint32_t width
) {
    if (!isArm64GpReg(dstReg) || !isArm64GpReg(srcReg) || isArm64ZeroReg(dstReg)) {
        return false;
    }

    const uint32_t bitWidth = isArm64WReg(dstReg) ? 32u : 64u;
    if (width == 0u || width > bitWidth || lsb >= bitWidth || (lsb + width) > bitWidth) {
        return false;
    }

    const uint32_t dstIndex = getOrAddReg(regIdList, arm64CapstoneToArchIndex(dstReg));
    const uint32_t srcIndex = isArm64ZeroReg(srcReg)
                              ? static_cast<uint32_t>(-1)
                              : getOrAddReg(regIdList, arm64CapstoneToArchIndex(srcReg));
    const uint32_t typeIndex = getOrAddTypeTagForRegWidth(typeIdList, dstReg);
    const uint64_t widthMask = isArm64WReg(dstReg) ? 0xFFFFFFFFull : 0xFFFFFFFFFFFFFFFFull;
    const uint64_t srcLowMask = (width == bitWidth) ? widthMask : ((1ull << width) - 1ull);
    const uint64_t fieldMask = (srcLowMask << lsb) & widthMask;
    const uint64_t clearMask = (~fieldMask) & widthMask;

    const uint32_t tmpIns = getOrAddReg(regIdList, arm64CapstoneToArchIndex(AARCH64_REG_X16));
    std::vector<uint32_t> out;

    // 第 1 步：准备插入值 tmpIns = (src & lowMask) << lsb，再按 fieldMask 收口。
    if (srcIndex == static_cast<uint32_t>(-1)) {
        out.push_back(OP_LOAD_IMM);
        out.push_back(tmpIns);
        out.push_back(0u);
    } else if (tmpIns != srcIndex) {
        out.push_back(OP_MOV);
        out.push_back(srcIndex);
        out.push_back(tmpIns);
    }
    appendAndByMask(out, regIdList, typeIdList, tmpIns, tmpIns, srcLowMask, typeIndex, AARCH64_REG_X17);
    if (lsb != 0u) {
        out.push_back(OP_BINARY_IMM);
        out.push_back(BIN_SHL);
        out.push_back(typeIndex);
        out.push_back(tmpIns);
        out.push_back(lsb);
        out.push_back(tmpIns);
    }
    appendAndByMask(out, regIdList, typeIdList, tmpIns, tmpIns, fieldMask, typeIndex, AARCH64_REG_X14);

    // 第 2 步：清空 dst 目标位段。
    appendAndByMask(out, regIdList, typeIdList, dstIndex, dstIndex, clearMask, typeIndex, AARCH64_REG_X13);

    // 第 3 步：合并插入结果。
    out.push_back(OP_BINARY);
    out.push_back(BIN_OR);
    out.push_back(typeIndex);
    out.push_back(dstIndex);
    out.push_back(tmpIns);
    out.push_back(dstIndex);

    if (isArm64WReg(dstReg)) {
        appendAndByMask(out, regIdList, typeIdList, dstIndex, dstIndex, 0xFFFFFFFFull, typeIndex, AARCH64_REG_X12);
    }

    opcodeList = std::move(out);
    return true;
}

// 统一处理 ubfm/sbfm：同时覆盖 non-wrap 与 wrap 两种位域语义。
bool tryEmitBitfieldMoveLike(
    std::vector<uint32_t>& opcodeList,
    std::vector<uint32_t>& regIdList,
    std::vector<uint32_t>& typeIdList,
    unsigned int dstReg,
    unsigned int srcReg,
    uint32_t immr,
    uint32_t imms,
    bool signExtract
) {
    if (!isArm64GpReg(dstReg) || !isArm64GpReg(srcReg) || isArm64ZeroReg(dstReg)) {
        return false;
    }

    const uint32_t bitWidth = isArm64WReg(dstReg) ? 32u : 64u;
    immr %= bitWidth;
    imms %= bitWidth;

    // non-wrap：等价 ubfx/sbfx。
    if (imms >= immr) {
        uint32_t width = imms - immr + 1u;
        return tryEmitBitExtractLike(
            opcodeList,
            regIdList,
            typeIdList,
            dstReg,
            srcReg,
            immr,
            width,
            signExtract
        );
    }

    // wrap：等价 ubfiz/sbfiz，参数换算：
    // lsb = bitWidth - immr, width = imms + 1。
    const uint32_t insertLsb = bitWidth - immr;
    const uint32_t insertWidth = imms + 1u;
    return tryEmitBitfieldInsertLike(
        opcodeList,
        regIdList,
        typeIdList,
        dstReg,
        srcReg,
        insertLsb,
        insertWidth,
        signExtract
    );
}

uint32_t getOrAddBranch(std::vector<uint64_t>& branchIdList, uint64_t targetArmAddr) {
    // 分支目标地址去重并返回索引，供 OP_BRANCH/OP_BRANCH_IF_CC 复用。
    for (size_t branchIndex = 0; branchIndex < branchIdList.size(); ++branchIndex) {
        if (branchIdList[branchIndex] == targetArmAddr) return static_cast<uint32_t>(branchIndex);
    }
    branchIdList.push_back(targetArmAddr);
    return static_cast<uint32_t>(branchIdList.size() - 1);
}


static zInstAsmUnencodedBytecode buildUnencodedByCapstone(csh handle, const uint8_t* code, size_t size, uint64_t baseAddr) {
    // Capstone 翻译主流程：
    // ARM64 指令流 -> 未编码 VM opcode（按地址分组）。
    zInstAsmUnencodedBytecode unencoded;
    // initValueCount 当前固定为 0，保留字段以兼容旧格式。
    unencoded.initValueCount = 0;
    // 分支统计/表项初始化为 0。
    unencoded.branchCount = 0;
    unencoded.branchWords.clear();
    unencoded.branchLookupWords.clear();
    unencoded.branchLookupAddrs.clear();
    unencoded.branchAddrWords.clear();

    std::vector<uint32_t> reg_id_list;
    std::vector<uint32_t> type_id_list;

    cs_insn* insn = nullptr;
    // 第四个参数传 0 表示“尽可能反汇编到末尾”。
    size_t count = zInstAsm::disasm(handle, code, size, baseAddr, insn);
    if (count == 0 || !insn) {
        unencoded.translationOk = false;
        const cs_err err = cs_errno(handle);
        unencoded.translationError = strFormat(
            "capstone disasm failed: base=0x%" PRIx64 ", size=%zu, cs_err=%d(%s), code_preview=%s",
            baseAddr,
            size,
            static_cast<int>(err),
            cs_strerror(err),
            buildCodePreview(code, size).c_str()
        );
        LOGE("%s", unencoded.translationError.c_str());
        return unencoded;
    }

    for (int regNumber = 0; regNumber < 31; ++regNumber) {
        // 预放入 x0..x30，保证后续索引稳定。
        reg_id_list.push_back(static_cast<uint32_t>(regNumber));
    }

    // 运行时前缀指令：
    // 这里显式与 instByAddress 解耦，避免拿 0/1 这种伪地址占位导致真实地址冲突。
    // prelude_words 只用于最终扁平流前缀，不参与“ARM 地址 -> PC”映射。
    std::vector<uint32_t> prelude_words;
    prelude_words.reserve(10);
    (void)getOrAddReg(reg_id_list, 0);
    prelude_words.insert(prelude_words.end(), { OP_ALLOC_RETURN, 0, 0, 0, 0 });

    uint32_t vfp_idx = getOrAddReg(reg_id_list, 29);
    uint32_t vsp_idx = getOrAddReg(reg_id_list, 31);
    prelude_words.insert(prelude_words.end(), { OP_ALLOC_VSP, 0, 0, 0, vfp_idx, vsp_idx });

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
        zInstDispatchContext dispatch_context{
            op_count,
            ops,
            detail,
            insn,
            j,
            addr,
            opcode_list,
            reg_id_list,
            type_id_list,
            branch_id_list,
            call_target_list
        };
        // 默认认为 instruction id 可识别，若落入 default 则会改为 false。
        // 先由 zInst 做一级分域，再进入对应 asm 翻译模块。
        const zInst::zAsmDomain asmDomain = zInst::classifyArm64Domain(id);
        auto dispatchArm64ByDomain = [&](zInst::zAsmDomain domain) -> bool {
            switch (domain) {
                case zInst::zAsmDomain::Arith:
                    return dispatchArm64ArithCase(id, dispatch_context);
                case zInst::zAsmDomain::Logic:
                    return dispatchArm64LogicCase(id, dispatch_context);
                case zInst::zAsmDomain::Memory:
                    return dispatchArm64MemoryCase(id, dispatch_context);
                case zInst::zAsmDomain::Branch:
                    return dispatchArm64BranchCase(id, dispatch_context);
                case zInst::zAsmDomain::Unknown:
                default:
                    return false;
            }
        };
        bool instruction_id_handled = dispatchArm64ByDomain(asmDomain);
        // 严格模式：仅允许“分域命中后的单路径翻译”，不做跨域重试兜底。

        // 按用户要求移除“基于 mnemonic 字符串关键字”的兜底翻译逻辑。
        // 这里不再做字符串匹配补偿；未覆盖语义必须在 case 分发层显式实现。
        if (opcode_list.empty()) {
            // 空 opcode 代表本条指令无法翻译，立即失败并记录现场信息。
            // instruction_id_handled=true 表示“识别了指令，但操作数形态未覆盖”。
            const char* reason = instruction_id_handled
                                 ? "recognized instruction but operand pattern is not translated"
                                 : "unsupported instruction id";
            unencoded.translationOk = false;
            const std::string operand_detail = buildOperandDetail(op_count, ops);
            const std::string byte_preview = buildInsnBytePreview(insn[j]);
            // 错误文本增加 id/domain/bytes/operands 细节，便于一次定位失败根因。
            unencoded.translationError = strFormat(
                "translate failed at 0x%" PRIx64 ": %s %s (%s, id=%u, domain=%s, op_count=%u, size=%u, bytes=[%s], operands=[%s])",
                addr,
                insn[j].mnemonic ? insn[j].mnemonic : "",
                insn[j].op_str ? insn[j].op_str : "",
                reason,
                id,
                zInst::getAsmDomainName(asmDomain),
                static_cast<unsigned>(op_count)
                ,
                static_cast<unsigned>(insn[j].size),
                byte_preview.c_str(),
                operand_detail.c_str()
            );
            LOGE("%s", unencoded.translationError.c_str());
            // 出错即中止整段翻译，避免生成半有效字节码。
            translation_aborted = true;
            break;
        }

        // 保存翻译结果。
        unencoded.instByAddress[addr] = std::move(opcode_list);
        // 同步保存可读反汇编文本，便于后续 dump/诊断。
        std::string asm_line = zInstAsm::buildAsmText(insn[j]);
        // 与 instByAddress 使用同一地址键，确保可一一对照。
        unencoded.asmByAddress[addr] = std::move(asm_line);
    }

    if (translation_aborted) {
        // 失败路径也要释放 Capstone 指令缓存。
        zInstAsm::freeInsn(insn, count);
        return unencoded;
    }

    std::map<uint64_t, uint32_t> addr_to_pc;
    // 注意：真实指令 PC 需要从 prelude 之后开始计数。
    uint32_t pc = static_cast<uint32_t>(prelude_words.size());
    // 把“地址 -> 扁平 PC(word 下标)”预先建表。
    for (const auto& instEntry : unencoded.instByAddress) {
        // 当前地址对应的第一条 opcode word 下标。
        addr_to_pc[instEntry.first] = pc;
        // pc 累加本地址下 opcode 总字数。
        pc += static_cast<uint32_t>(instEntry.second.size());
    }

    // BL 目标地址列表直接落入 branchAddrWords（后续可 remap 为全局表）。
    unencoded.branchAddrWords = call_target_list;
    unencoded.branchWords.clear();
    // 本地 branch 目标地址转换为 VM PC。
    // 安全策略：
    // 一旦分支目标找不到对应 PC，立即失败；禁止静默写 0 继续执行。
    for (size_t branchIndex = 0; branchIndex < branch_id_list.size(); ++branchIndex) {
        const uint64_t arm_addr = branch_id_list[branchIndex];
        const auto targetPcIt = addr_to_pc.find(arm_addr);
        if (targetPcIt == addr_to_pc.end()) {
            uint64_t min_inst_addr = 0;
            uint64_t max_inst_addr = 0;
            if (!unencoded.instByAddress.empty()) {
                min_inst_addr = unencoded.instByAddress.begin()->first;
                max_inst_addr = unencoded.instByAddress.rbegin()->first;
            }
            std::vector<uint64_t> branch_preview(
                branch_id_list.begin(),
                branch_id_list.begin() + std::min<size_t>(branch_id_list.size(), 8)
            );
            std::string branch_preview_text;
            if (!branch_preview.empty()) {
                std::ostringstream oss;
                oss << std::hex;
                for (size_t idx = 0; idx < branch_preview.size(); ++idx) {
                    if (idx != 0) {
                        oss << ",";
                    }
                    oss << "0x" << branch_preview[idx];
                }
                if (branch_id_list.size() > branch_preview.size()) {
                    oss << ",...";
                }
                branch_preview_text = oss.str();
            } else {
                branch_preview_text = "none";
            }
            unencoded.translationOk = false;
            unencoded.translationError = strFormat(
                "translate failed: unresolved local branch target at index=%u addr=0x%" PRIx64
                " (branch_total=%u, inst_addr_range=[0x%" PRIx64 ",0x%" PRIx64 "], branch_preview=%s)",
                static_cast<unsigned>(branchIndex),
                arm_addr,
                static_cast<unsigned>(branch_id_list.size()),
                min_inst_addr,
                max_inst_addr,
                branch_preview_text.c_str()
            );
            LOGE("%s", unencoded.translationError.c_str());
            translation_aborted = true;
            break;
        }
        unencoded.branchWords.push_back(targetPcIt->second);
    }
    if (translation_aborted) {
        zInstAsm::freeInsn(insn, count);
        return unencoded;
    }
    unencoded.branchCount = static_cast<uint32_t>(unencoded.branchWords.size());

    // 间接跳转查找表：把每条真实 ARM 指令地址映射到对应 VM PC。
    // prelude 指令不在 instByAddress 中，因此这里天然只处理真实 ARM 地址。
    unencoded.branchLookupWords.clear();
    unencoded.branchLookupAddrs.clear();
    unencoded.branchLookupWords.reserve(count);
    unencoded.branchLookupAddrs.reserve(count);
    for (size_t insnIndex = 0; insnIndex < count; ++insnIndex) {
        const uint64_t armAddr = insn[insnIndex].address;
        const auto pcIt = addr_to_pc.find(armAddr);
        if (pcIt == addr_to_pc.end()) {
            continue;
        }
        unencoded.branchLookupAddrs.push_back(armAddr);
        unencoded.branchLookupWords.push_back(pcIt->second);
    }

    zInstAsm::freeInsn(insn, count);

    unencoded.regList = std::move(reg_id_list);
    unencoded.registerCount = static_cast<uint32_t>(unencoded.regList.size());
    // 运行时执行器至少期望前四个参数寄存器槽存在。
    if (unencoded.registerCount < 4) unencoded.registerCount = 4;

    unencoded.typeTags = std::move(type_id_list);
    // typeCount 是运行时 type 表长度。
    unencoded.typeCount = static_cast<uint32_t>(unencoded.typeTags.size());

    // prelude 指令单独存储，但在最终执行流中位于最前面。
    unencoded.preludeWords = std::move(prelude_words);
    unencoded.instCount = static_cast<uint32_t>(unencoded.preludeWords.size());
    for (const auto& instEntry : unencoded.instByAddress) {
        // instCount 统计的是“opcode word 数”，不是 ARM 指令条数。
        unencoded.instCount += static_cast<uint32_t>(instEntry.second.size());
    }

    return unencoded;
}



zInstAsmUnencodedBytecode zInstAsm::buildUnencodedBytecode(const uint8_t* code, size_t size, uint64_t baseAddr) {
    if (code == nullptr || size == 0) {
        zInstAsmUnencodedBytecode empty;
        empty.translationOk = false;
        empty.translationError = "function bytes are empty";
        return empty;
    }

    csh handle = 0;
    if (!zInstAsm::openWithDetail(handle)) {
        zInstAsmUnencodedBytecode failed;
        failed.translationOk = false;
        failed.translationError = "capstone open/detail failed";
        return failed;
    }

    zInstAsmUnencodedBytecode out = buildUnencodedByCapstone(handle, code, size, baseAddr);
    zInstAsm::close(handle);
    return out;
}
