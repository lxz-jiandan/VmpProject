#include "zPipelineCoverage.h"

// 流程说明：该注释位置用于解释当前统计链路的关键步骤。
#include <algorithm>
// 助记符兜底路径：当指令 ID 不稳定时，按 mnemonic 做保守判定。
#include <cstring>
// Markdown 输出步骤：把统计结果格式化为可读报告文本。
#include <fstream>
// 映射步骤：把原始键值折叠为稳定可比较的数据结构。
#include <map>
// 流程说明：该注释位置用于解释当前统计链路的关键步骤。
#include <sstream>
// 流程说明：该注释位置用于解释当前统计链路的关键步骤。
#include <unordered_set>
// 流程说明：该注释位置用于解释当前统计链路的关键步骤。
#include <utility>
// 流程说明：该注释位置用于解释当前统计链路的关键步骤。
#include <vector>

// ARM64 指令集合维护：用于定义当前翻译器的已支持范围。
#include <capstone/arm64.h>
// Capstone 相关步骤：用于获取指令 ID、助记符与操作数字段。
#include <capstone/capstone.h>

// 流程说明：该注释位置用于解释当前统计链路的关键步骤。
#include "zLog.h"
// ARM64 disasm utility facade.
#include "zInst.h"
// 流程说明：该注释位置用于解释当前统计链路的关键步骤。
#include "zPipelineCli.h"

// 进入 vmp 命名空间，实现覆盖率统计主流程。
namespace vmp {  // 流程注记：该语句参与当前阶段的语义实现。

// 流程说明：该注释位置用于解释当前统计链路的关键步骤。
namespace {  // 流程注记：该语句参与当前阶段的语义实现。

// ARM64 处理步骤：围绕指令分类与支持度统计展开。
std::unordered_set<unsigned int> buildSupportedInsnIdSet() {  // 处理阶段入口：进入该函数或代码块的主流程。
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    std::unordered_set<unsigned int> ids = {  // 流程注记：该语句参与当前阶段的语义实现。
        ARM64_INS_ADD,  // 流程注记：该语句参与当前阶段的语义实现。
        ARM64_INS_ADDS,  // 流程注记：该语句参与当前阶段的语义实现。
        ARM64_INS_ASR,  // 流程注记：该语句参与当前阶段的语义实现。
        ARM64_INS_ADRP,  // 流程注记：该语句参与当前阶段的语义实现。
        ARM64_INS_ALIAS_LSL,  // 流程注记：该语句参与当前阶段的语义实现。
        ARM64_INS_AND,
        ARM64_INS_ANDS,
        ARM64_INS_B,
        ARM64_INS_BL,
        ARM64_INS_BLR,
        ARM64_INS_BR,
        ARM64_INS_CBNZ,
        ARM64_INS_CBZ,
        ARM64_INS_CSEL,
        ARM64_INS_CSINC,
        ARM64_INS_EOR,
        ARM64_INS_LDP,
        ARM64_INS_LDR,
        ARM64_INS_LDRB,
        ARM64_INS_LDRH,
        ARM64_INS_LDUR,
        ARM64_INS_LDURB,
        ARM64_INS_LSL,
        ARM64_INS_LSLR,
        ARM64_INS_LSR,
        ARM64_INS_MOV,
        ARM64_INS_MOVI,
        ARM64_INS_MOVK,
        ARM64_INS_MOVN,
        ARM64_INS_MOVZ,
        ARM64_INS_MRS,
        ARM64_INS_MUL,
        ARM64_INS_MADD,
        ARM64_INS_MSUB,
        ARM64_INS_UMULL,
        ARM64_INS_SMULL,
        ARM64_INS_UMADDL,
        ARM64_INS_SMADDL,
        ARM64_INS_UMULH,
        ARM64_INS_SMULH,
        ARM64_INS_UDIV,
        ARM64_INS_SDIV,
        ARM64_INS_ORR,
        ARM64_INS_ADR,
        ARM64_INS_ORN,
        ARM64_INS_BIC,
        ARM64_INS_BFM,
        ARM64_INS_CCMP,
        ARM64_INS_CSINV,
        ARM64_INS_NEG,
        ARM64_INS_REV,
        ARM64_INS_REV16,
        ARM64_INS_ROR,
        ARM64_INS_RET,
        ARM64_INS_STP,
        ARM64_INS_STR,
        ARM64_INS_STRB,
        ARM64_INS_STRH,
        ARM64_INS_STUR,
        ARM64_INS_SUB,
        ARM64_INS_SUBS,
        ARM64_INS_SBFM,
        ARM64_INS_TBNZ,
        ARM64_INS_TBZ,
        ARM64_INS_UBFM,
        ARM64_INS_LDAXR,
        ARM64_INS_LDXR,
        ARM64_INS_STLXR,
        ARM64_INS_STXR,
        ARM64_INS_HINT,
        ARM64_INS_CLREX,
        ARM64_INS_SVC,
        ARM64_INS_BRK,
    };
// Capstone 相关步骤：用于获取指令 ID、助记符与操作数字段。
    ids.insert(ARM64_INS_CLZ);
    ids.insert(ARM64_INS_FCVTAS);
    ids.insert(ARM64_INS_FCVTZS);
    ids.insert(ARM64_INS_FDIV);
    ids.insert(ARM64_INS_FMUL);
    ids.insert(ARM64_INS_SCVTF);
    ids.insert(ARM64_INS_SHRN);
// Capstone 相关步骤：用于获取指令 ID、助记符与操作数字段。
    ids.insert(ARM64_INS_LDRSW);
// Capstone 相关步骤：用于获取指令 ID、助记符与操作数字段。
    ids.insert(ARM64_INS_LDURSW);
    ids.insert(ARM64_INS_EXTR);
    ids.insert(ARM64_INS_STURB);
    ids.insert(ARM64_INS_STURH);
    ids.insert(ARM64_INS_LDURH);
    ids.insert(ARM64_INS_LDRSB);
    ids.insert(ARM64_INS_LDRSH);
    ids.insert(ARM64_INS_LDARB);
    ids.insert(ARM64_INS_STLRB);
    ids.insert(ARM64_INS_STLRH);
    ids.insert(ARM64_INS_STLR);
    ids.insert(ARM64_INS_LDARH);
    ids.insert(ARM64_INS_LDAR);
    ids.insert(ARM64_INS_BICS);
    ids.insert(ARM64_INS_EON);
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    return ids;
}

// 助记符兜底路径：当指令 ID 不稳定时，按 mnemonic 做保守判定。
bool isSupportedByFallbackMnemonic(const char* mnemonic) {
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    if (mnemonic == nullptr) {
        return false;
    }
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    return std::strcmp(mnemonic, "mov") == 0 ||
           std::strcmp(mnemonic, "mul") == 0 ||
           std::strcmp(mnemonic, "and") == 0 ||
           std::strcmp(mnemonic, "eor") == 0 ||
           std::strcmp(mnemonic, "adds") == 0 ||
           std::strcmp(mnemonic, "cbz") == 0 ||
           std::strcmp(mnemonic, "cbnz") == 0 ||
           std::strcmp(mnemonic, "cmp") == 0 ||
           std::strcmp(mnemonic, "ldrsw") == 0 ||
            std::strcmp(mnemonic, "ldrh") == 0 ||
            std::strcmp(mnemonic, "ldursw") == 0 ||
            std::strcmp(mnemonic, "sturb") == 0 ||
            std::strcmp(mnemonic, "strh") == 0 ||
            std::strcmp(mnemonic, "sturh") == 0 ||
            std::strcmp(mnemonic, "ldurh") == 0 ||
            std::strcmp(mnemonic, "ldrsb") == 0 ||
            std::strcmp(mnemonic, "ldrsh") == 0 ||
            std::strcmp(mnemonic, "ldarb") == 0 ||
            std::strcmp(mnemonic, "stlrb") == 0 ||
            std::strcmp(mnemonic, "stlrh") == 0 ||
            std::strcmp(mnemonic, "stlr") == 0 ||
            std::strcmp(mnemonic, "ldarh") == 0 ||
            std::strcmp(mnemonic, "ldar") == 0 ||
            std::strcmp(mnemonic, "madd") == 0 ||
            std::strcmp(mnemonic, "msub") == 0 ||
            std::strcmp(mnemonic, "udiv") == 0 ||
            std::strcmp(mnemonic, "sdiv") == 0 ||
            std::strcmp(mnemonic, "extr") == 0 ||
            std::strcmp(mnemonic, "orn") == 0 ||
            std::strcmp(mnemonic, "bic") == 0 ||
            std::strcmp(mnemonic, "csel") == 0 ||
            std::strcmp(mnemonic, "csinc") == 0 ||
           std::strcmp(mnemonic, "sxtb") == 0 ||
           std::strcmp(mnemonic, "sxth") == 0 ||
           std::strcmp(mnemonic, "sxtw") == 0 ||
           std::strcmp(mnemonic, "uxtb") == 0 ||
           std::strcmp(mnemonic, "uxth") == 0 ||
           std::strcmp(mnemonic, "uxtw") == 0 ||
           std::strcmp(mnemonic, "ubfx") == 0 ||
           std::strcmp(mnemonic, "sbfx") == 0 ||
           std::strcmp(mnemonic, "ubfm") == 0 ||
           std::strcmp(mnemonic, "sbfm") == 0 ||
           std::strcmp(mnemonic, "lsl") == 0 ||
           std::strcmp(mnemonic, "lsr") == 0 ||
           std::strcmp(mnemonic, "asr") == 0 ||
           std::strcmp(mnemonic, "ror") == 0 ||
           std::strcmp(mnemonic, "clz") == 0 ||
           std::strcmp(mnemonic, "movi") == 0 ||
           std::strcmp(mnemonic, "mov") == 0 ||
           std::strcmp(mnemonic, "adr") == 0 ||
           std::strcmp(mnemonic, "rev") == 0 ||
           std::strcmp(mnemonic, "rev16") == 0 ||
           std::strcmp(mnemonic, "cmn") == 0 ||
           std::strcmp(mnemonic, "tst") == 0 ||
           std::strcmp(mnemonic, "neg") == 0 ||
           std::strcmp(mnemonic, "mvn") == 0 ||
           std::strcmp(mnemonic, "not") == 0 ||
           std::strcmp(mnemonic, "ccmp") == 0 ||
           std::strcmp(mnemonic, "cneg") == 0 ||
           std::strcmp(mnemonic, "cinc") == 0 ||
           std::strcmp(mnemonic, "csetm") == 0 ||
           std::strcmp(mnemonic, "csinv") == 0 ||
           std::strcmp(mnemonic, "bfi") == 0 ||
           std::strcmp(mnemonic, "bfxil") == 0 ||
           std::strcmp(mnemonic, "bics") == 0 ||
           std::strcmp(mnemonic, "eon") == 0 ||
           std::strcmp(mnemonic, "mneg") == 0 ||
           std::strcmp(mnemonic, "umull") == 0 ||
           std::strcmp(mnemonic, "smull") == 0 ||
           std::strcmp(mnemonic, "umaddl") == 0 ||
           std::strcmp(mnemonic, "smaddl") == 0 ||
           std::strcmp(mnemonic, "umulh") == 0 ||
           std::strcmp(mnemonic, "smulh") == 0 ||
            std::strcmp(mnemonic, "fmov") == 0 ||
            std::strcmp(mnemonic, "fcvt") == 0 ||
            std::strcmp(mnemonic, "fcvtas") == 0 ||
            std::strcmp(mnemonic, "fcvtzs") == 0 ||
            std::strcmp(mnemonic, "scvtf") == 0 ||
            std::strcmp(mnemonic, "fcmp") == 0 ||
            std::strcmp(mnemonic, "fadd") == 0 ||
            std::strcmp(mnemonic, "fdiv") == 0 ||
            std::strcmp(mnemonic, "fmul") == 0 ||
            std::strcmp(mnemonic, "fneg") == 0 ||
            std::strcmp(mnemonic, "ucvtf") == 0 ||
            std::strcmp(mnemonic, "dup") == 0 ||
           std::strcmp(mnemonic, "ld4") == 0 ||
           std::strcmp(mnemonic, "ushll") == 0 ||
           std::strcmp(mnemonic, "ushll2") == 0 ||
           std::strcmp(mnemonic, "shll") == 0 ||
            std::strcmp(mnemonic, "shll2") == 0 ||
            std::strcmp(mnemonic, "ushr") == 0 ||
            std::strcmp(mnemonic, "shl") == 0 ||
            std::strcmp(mnemonic, "shrn") == 0 ||
            std::strcmp(mnemonic, "xtn") == 0 ||
            std::strcmp(mnemonic, "bit") == 0 ||
            std::strcmp(mnemonic, "bsl") == 0 ||
           std::strcmp(mnemonic, "umov") == 0 ||
           std::strcmp(mnemonic, "cmeq") == 0 ||
           std::strcmp(mnemonic, "cmhi") == 0 ||
           std::strcmp(mnemonic, "cmlt") == 0 ||
           std::strcmp(mnemonic, "cmgt") == 0 ||
           std::strcmp(mnemonic, "cmhs") == 0 ||
           std::strcmp(mnemonic, "ldaxr") == 0 ||
           std::strcmp(mnemonic, "ldxr") == 0 ||
           std::strcmp(mnemonic, "stlxr") == 0 ||
           std::strcmp(mnemonic, "stxr") == 0 ||
            std::strcmp(mnemonic, "nop") == 0 ||
            std::strcmp(mnemonic, "hint") == 0 ||
            std::strcmp(mnemonic, "yield") == 0 ||
            std::strcmp(mnemonic, "clrex") == 0 ||
            std::strcmp(mnemonic, "svc") == 0 ||
            std::strcmp(mnemonic, "brk") == 0;
}

// 流程说明：该注释位置用于解释当前统计链路的关键步骤。
bool isInstructionSupported(const std::unordered_set<unsigned int>& supportedIds,
                            unsigned int insnId,
                            const char* mnemonic) {
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    if (supportedIds.find(insnId) != supportedIds.end()) {
        return true;
    }
    // 助记符兜底路径：当指令 ID 不稳定时，按 mnemonic 做保守判定。
    return isSupportedByFallbackMnemonic(mnemonic);
}

// 流程说明：该注释位置用于解释当前统计链路的关键步骤。
std::string buildInstructionLabel(csh handle, unsigned int insnId, const char* mnemonic) {
    // Capstone 相关步骤：用于获取指令 ID、助记符与操作数字段。
    const char* capName = cs_insn_name(handle, insnId);
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    std::string name;
    // Capstone 相关步骤：用于获取指令 ID、助记符与操作数字段。
    if (capName != nullptr && capName[0] != '\0') {
        name = capName;
    // 助记符兜底路径：当指令 ID 不稳定时，按 mnemonic 做保守判定。
    } else if (mnemonic != nullptr && mnemonic[0] != '\0') {
        name = mnemonic;
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    } else {
        name = "unknown";
    }
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    std::ostringstream oss;
    oss << name << "(" << insnId << ")";
    return oss.str();
}

// Markdown 输出步骤：把统计结果格式化为可读报告文本。
std::string markdownSafe(std::string value) {
    // Markdown 输出步骤：把统计结果格式化为可读报告文本。
    for (char& ch : value) {
        if (ch == '|') {
            ch = '/';
        }
    }
    return value;
}

// 流程说明：该注释位置用于解释当前统计链路的关键步骤。
void analyzeCoverageForFunction(csh handle,
                                const std::unordered_set<unsigned int>& supportedIds,
                                const vmp::elfkit::FunctionView& function,
                                FunctionCoverageRow& row,
                                CoverageBoard& board) {
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    if (function.getData() == nullptr || function.getSize() == 0) {
        return;
    }

    // Capstone 相关步骤：用于获取指令 ID、助记符与操作数字段。
    cs_insn* insn = nullptr;
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    const size_t instructionCount = zInstAsm::disasm(handle,
                                                      function.getData(),
                                                      function.getSize(),
                                                      function.getOffset(),
                                                      insn);
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    for (size_t instructionIndex = 0; instructionIndex < instructionCount; ++instructionIndex) {
        const cs_insn& currentInsn = insn[instructionIndex];
        // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
        const bool supported = isInstructionSupported(supportedIds,
                                                      currentInsn.id,
                                                      currentInsn.mnemonic);
        // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
        const std::string label = buildInstructionLabel(handle,
                                                        currentInsn.id,
                                                        currentInsn.mnemonic);
        // 计数步骤：命中当前分支时更新对应计数器。
        ++row.totalInstructions;
        // 计数步骤：命中当前分支时更新对应计数器。
        ++board.totalInstructions;
        // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
        if (supported) {
            ++row.supportedInstructions;
            ++board.supportedInstructions;
            ++board.supportedHistogram[label];
        } else {
            ++row.unsupportedInstructions;
            ++board.unsupportedInstructions;
            ++board.unsupportedHistogram[label];
        }
    }
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    if (insn != nullptr) {
        zInstAsm::freeInsn(insn, instructionCount);
    }
}

// 流程说明：该注释位置用于解释当前统计链路的关键步骤。
}  // namespace

// 流程说明：该注释位置用于解释当前统计链路的关键步骤。
bool buildCoverageBoard(const std::vector<std::string>& functionNames,
                        const std::vector<elfkit::FunctionView>& functions,
                        CoverageBoard& board) {
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    if (functionNames.size() != functions.size()) {
        LOGE("coverage failed: functionNames/functions size mismatch nameCount=%llu functionCount=%llu",
             static_cast<unsigned long long>(functionNames.size()),
             static_cast<unsigned long long>(functions.size()));
        return false;
    }
    // Capstone 相关步骤：用于获取指令 ID、助记符与操作数字段。
    csh handle = 0;
    // ARM64 处理步骤：围绕指令分类与支持度统计展开。
    if (!zInstAsm::open(handle)) {
        LOGE("coverage failed: capstone cs_open failed");
        return false;
    }

    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    const std::unordered_set<unsigned int> supportedIds = buildSupportedInsnIdSet();
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    board.functionRows.reserve(functions.size());
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    for (size_t functionIndex = 0; functionIndex < functions.size(); ++functionIndex) {
        FunctionCoverageRow row;
        row.functionName = functionNames[functionIndex];
        analyzeCoverageForFunction(handle,
                                   supportedIds,
                                   functions[functionIndex],
                                   row,
                                   board);
        board.functionRows.push_back(std::move(row));
    }

    // Capstone 相关步骤：用于获取指令 ID、助记符与操作数字段。
    zInstAsm::close(handle);
    return true;
}

// 与 prepareTranslation 对齐：保持口径一致，避免统计偏差。
bool fillTranslationStatus(const std::vector<elfkit::FunctionView>& functions,
                           CoverageBoard& board) {
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    if (board.functionRows.size() != functions.size()) {
        LOGE("fillTranslationStatus failed: rowCount/functionCount mismatch rowCount=%llu functionCount=%llu",
             static_cast<unsigned long long>(board.functionRows.size()),
             static_cast<unsigned long long>(functions.size()));
        return false;
    }
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    for (size_t functionIndex = 0; functionIndex < functions.size(); ++functionIndex) {
        FunctionCoverageRow& row = board.functionRows[functionIndex];
        row.translateOk = functions[functionIndex].prepareTranslation(&row.translateError);
        row.translateError = markdownSafe(row.translateError);
    }
    return true;
}

// 流程说明：该注释位置用于解释当前统计链路的关键步骤。
bool runCoverageAnalyzeFlow(const std::vector<std::string>& functionNames,
                            const std::vector<elfkit::FunctionView>& functions,
                            CoverageBoard& board) {
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    if (!buildCoverageBoard(functionNames, functions, board)) {
        return false;
    }
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    if (!fillTranslationStatus(functions, board)) {
        return false;
    }
    return true;
}

// 流程说明：该注释位置用于解释当前统计链路的关键步骤。
bool runCoverageReportFlow(const VmProtectConfig& config, const CoverageBoard& board) {
    // 覆盖率统计步骤：聚合已支持与未支持指令并输出摘要。
    const std::string coverageReportPath = joinOutputPath(config, config.coverageReport);
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    if (!writeCoverageReport(coverageReportPath, board)) {
        LOGE("failed to write coverage report: %s", coverageReportPath.c_str());
        return false;
    }
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    LOGI("coverage report written: %s", coverageReportPath.c_str());
    return true;
}

// 流程说明：该注释位置用于解释当前统计链路的关键步骤。
bool runCoverageFlow(const VmProtectConfig& config,
                     const std::vector<std::string>& functionNames,
                     const std::vector<elfkit::FunctionView>& functions,
                     CoverageBoard* outBoard) {
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    CoverageBoard board;
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    if (!runCoverageAnalyzeFlow(functionNames, functions, board)) {
        return false;
    }
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    if (!runCoverageReportFlow(config, board)) {
        return false;
    }
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    if (outBoard != nullptr) {
        *outBoard = board;
    }
    return true;
}

// Markdown 输出步骤：把统计结果格式化为可读报告文本。
bool writeCoverageReport(const std::string& reportPath, const CoverageBoard& board) {
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    std::ofstream out(reportPath, std::ios::trunc);
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    if (!out) {
        return false;
    }

    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    out << "# ARM64 Translation Coverage Board\n\n";
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    out << "| Metric | Value |\n";
    out << "| --- | ---: |\n";
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    out << "| Total instructions | " << board.totalInstructions << " |\n";
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    out << "| Supported instructions | " << board.supportedInstructions << " |\n";
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    out << "| Unsupported instructions | " << board.unsupportedInstructions << " |\n\n";

    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    out << "## Per Function\n\n";
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    out << "| Function | Total | Supported | Unsupported | Translation OK | Translation Error |\n";
    out << "| --- | ---: | ---: | ---: | --- | --- |\n";
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    for (const FunctionCoverageRow& row : board.functionRows) {
        out << "| " << row.functionName
            << " | " << row.totalInstructions
            << " | " << row.supportedInstructions
            << " | " << row.unsupportedInstructions
            << " | " << (row.translateOk ? "yes" : "no")
            << " | " << (row.translateError.empty() ? "-" : row.translateError)
            << " |\n";
    }
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    out << "\n";

    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    auto dumpHistogram = [&out](const std::string& title,
                                const std::map<std::string, uint64_t>& hist) {
        // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
        out << "## " << title << "\n\n";
        // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
        out << "| Instruction | Count |\n";
        out << "| --- | ---: |\n";
        // 映射步骤：把原始键值折叠为稳定可比较的数据结构。
        std::vector<std::pair<std::string, uint64_t>> sorted(hist.begin(), hist.end());
        // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
        std::sort(sorted.begin(), sorted.end(),
                  [](const auto& lhs, const auto& rhs) {
                      if (lhs.second != rhs.second) {
                          return lhs.second > rhs.second;
                      }
                      return lhs.first < rhs.first;
                  });
        // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
        for (const auto& item : sorted) {
            out << "| " << markdownSafe(item.first) << " | " << item.second << " |\n";
        }
        // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
        out << "\n";
    };

    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    dumpHistogram("Unsupported Instructions", board.unsupportedHistogram);
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    dumpHistogram("Supported Instructions", board.supportedHistogram);
    // 流程说明：该注释位置用于解释当前统计链路的关键步骤。
    return static_cast<bool>(out);
}

// 进入 vmp 命名空间，实现覆盖率统计主流程。
}  // namespace vmp



