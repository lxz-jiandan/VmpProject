#include "zPipelineCoverage.h"

// 引入排序算法，供直方图输出前排序使用。
#include <algorithm>
// 引入 C 字符串工具，用于 mnemonic 比较。
#include <cstring>
// 引入文件流，用于输出 markdown 报告。
#include <fstream>
// 引入有序 map，用于稳定统计输出。
#include <map>
// 引入字符串流，用于拼接指令标签。
#include <sstream>
// 引入哈希集合，用于快速判断指令是否支持。
#include <unordered_set>
// 引入 move 语义工具。
#include <utility>
// 引入动态数组容器。
#include <vector>

// 引入 ARM64 指令 ID 枚举。
#include <capstone/arm64.h>
// 引入 capstone 核心接口。
#include <capstone/capstone.h>

// 引入日志能力。
#include "zLog.h"
// 引入输出路径拼接工具。
#include "zPipelineCli.h"

// 进入 vmp 主命名空间。
namespace vmp {

// 进入匿名命名空间，限制内部辅助函数作用域。
namespace {

// 构建“已支持翻译”的 ARM64 指令集合。
std::unordered_set<unsigned int> buildSupportedInsnIdSet() {
    // 先用初始化列表填充大部分稳定支持的指令 ID。
    std::unordered_set<unsigned int> ids = {
        ARM64_INS_ADD,
        ARM64_INS_ADDS,
#ifdef ARM64_INS_ASR
        ARM64_INS_ASR,
#endif
        ARM64_INS_ADRP,
        ARM64_INS_ALIAS_LSL,
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
#ifdef ARM64_INS_LDRH
        ARM64_INS_LDRH,
#endif
        ARM64_INS_LDUR,
        ARM64_INS_LDURB,
        ARM64_INS_LSL,
        ARM64_INS_LSLR,
#ifdef ARM64_INS_LSR
        ARM64_INS_LSR,
#endif
        ARM64_INS_MOV,
#ifdef ARM64_INS_MOVI
        ARM64_INS_MOVI,
#endif
        ARM64_INS_MOVK,
        ARM64_INS_MOVN,
        ARM64_INS_MOVZ,
        ARM64_INS_MRS,
        ARM64_INS_MUL,
#ifdef ARM64_INS_MADD
        ARM64_INS_MADD,
#endif
#ifdef ARM64_INS_MSUB
        ARM64_INS_MSUB,
#endif
#ifdef ARM64_INS_UDIV
        ARM64_INS_UDIV,
#endif
#ifdef ARM64_INS_SDIV
        ARM64_INS_SDIV,
#endif
        ARM64_INS_ORR,
#ifdef ARM64_INS_ADR
        ARM64_INS_ADR,
#endif
#ifdef ARM64_INS_ORN
        ARM64_INS_ORN,
#endif
#ifdef ARM64_INS_BIC
        ARM64_INS_BIC,
#endif
#ifdef ARM64_INS_BFM
        ARM64_INS_BFM,
#endif
#ifdef ARM64_INS_CCMP
        ARM64_INS_CCMP,
#endif
#ifdef ARM64_INS_CNEG
        ARM64_INS_CNEG,
#endif
#ifdef ARM64_INS_CINC
        ARM64_INS_CINC,
#endif
#ifdef ARM64_INS_CSETM
        ARM64_INS_CSETM,
#endif
#ifdef ARM64_INS_CMN
        ARM64_INS_CMN,
#endif
#ifdef ARM64_INS_TST
        ARM64_INS_TST,
#endif
#ifdef ARM64_INS_NEG
        ARM64_INS_NEG,
#endif
#ifdef ARM64_INS_MVN
        ARM64_INS_MVN,
#endif
#ifdef ARM64_INS_REV
        ARM64_INS_REV,
#endif
#ifdef ARM64_INS_REV16
        ARM64_INS_REV16,
#endif
#ifdef ARM64_INS_ROR
        ARM64_INS_ROR,
#endif
        ARM64_INS_RET,
        ARM64_INS_STP,
        ARM64_INS_STR,
        ARM64_INS_STRB,
#ifdef ARM64_INS_STRH
        ARM64_INS_STRH,
#endif
        ARM64_INS_STUR,
        ARM64_INS_SUB,
        ARM64_INS_SUBS,
        ARM64_INS_SBFM,
        ARM64_INS_TBNZ,
        ARM64_INS_TBZ,
        ARM64_INS_UBFM,
#ifdef ARM64_INS_LDAXR
        ARM64_INS_LDAXR,
#endif
#ifdef ARM64_INS_LDXR
        ARM64_INS_LDXR,
#endif
#ifdef ARM64_INS_STLXR
        ARM64_INS_STLXR,
#endif
#ifdef ARM64_INS_STXR
        ARM64_INS_STXR,
#endif
#ifdef ARM64_INS_NOP
        ARM64_INS_NOP,
#endif
#ifdef ARM64_INS_HINT
        ARM64_INS_HINT,
#endif
#ifdef ARM64_INS_CLREX
        ARM64_INS_CLREX,
#endif
#ifdef ARM64_INS_SVC
        ARM64_INS_SVC,
#endif
#ifdef ARM64_INS_BRK
        ARM64_INS_BRK,
#endif
    };
// 针对不同 capstone 版本，条件插入可选指令 ID。
#ifdef ARM64_INS_LDRSW
    ids.insert(ARM64_INS_LDRSW);
#endif
// 针对不同 capstone 版本，条件插入可选指令 ID。
#ifdef ARM64_INS_LDURSW
    ids.insert(ARM64_INS_LDURSW);
#endif
#ifdef ARM64_INS_EXTR
    ids.insert(ARM64_INS_EXTR);
#endif
#ifdef ARM64_INS_STURB
    ids.insert(ARM64_INS_STURB);
#endif
#ifdef ARM64_INS_STURH
    ids.insert(ARM64_INS_STURH);
#endif
#ifdef ARM64_INS_LDURH
    ids.insert(ARM64_INS_LDURH);
#endif
#ifdef ARM64_INS_LDRSB
    ids.insert(ARM64_INS_LDRSB);
#endif
#ifdef ARM64_INS_LDRSH
    ids.insert(ARM64_INS_LDRSH);
#endif
#ifdef ARM64_INS_LDARB
    ids.insert(ARM64_INS_LDARB);
#endif
#ifdef ARM64_INS_STLRB
    ids.insert(ARM64_INS_STLRB);
#endif
#ifdef ARM64_INS_STLRH
    ids.insert(ARM64_INS_STLRH);
#endif
#ifdef ARM64_INS_STLR
    ids.insert(ARM64_INS_STLR);
#endif
#ifdef ARM64_INS_LDARH
    ids.insert(ARM64_INS_LDARH);
#endif
#ifdef ARM64_INS_LDAR
    ids.insert(ARM64_INS_LDAR);
#endif
#ifdef ARM64_INS_CMP
    ids.insert(ARM64_INS_CMP);
#endif
    // 返回完整支持集合。
    return ids;
}

// 当指令 ID 不稳定时，回退到 mnemonic 文本判断是否支持。
bool isSupportedByFallbackMnemonic(const char* mnemonic) {
    // 防御空指针。
    if (mnemonic == nullptr) {
        return false;
    }
    // 仅对少量历史兼容指令名做兜底识别。
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
           std::strcmp(mnemonic, "bfi") == 0 ||
           std::strcmp(mnemonic, "bfxil") == 0 ||
           std::strcmp(mnemonic, "ldaxr") == 0 ||
           std::strcmp(mnemonic, "ldxr") == 0 ||
           std::strcmp(mnemonic, "stlxr") == 0 ||
           std::strcmp(mnemonic, "stxr") == 0 ||
           std::strcmp(mnemonic, "nop") == 0 ||
           std::strcmp(mnemonic, "hint") == 0 ||
           std::strcmp(mnemonic, "clrex") == 0 ||
           std::strcmp(mnemonic, "svc") == 0 ||
           std::strcmp(mnemonic, "brk") == 0;
}

// 统一判断一条指令是否可被当前翻译链路支持。
bool isInstructionSupported(const std::unordered_set<unsigned int>& supportedIds,
                            unsigned int insnId,
                            const char* mnemonic) {
    // 优先走 ID 集合判断，性能更高且语义更明确。
    if (supportedIds.find(insnId) != supportedIds.end()) {
        return true;
    }
    // ID 不命中时再走 mnemonic 兜底判断。
    return isSupportedByFallbackMnemonic(mnemonic);
}

// 生成用于报表展示的指令标签，例如 mov(123)。
std::string buildInstructionLabel(csh handle, unsigned int insnId, const char* mnemonic) {
    // 优先用 capstone 提供的规范名称。
    const char* capName = cs_insn_name(handle, insnId);
    // 保存最终可展示名称。
    std::string name;
    // capstone 名称有效时直接使用。
    if (capName != nullptr && capName[0] != '\0') {
        name = capName;
    // 否则回退到反汇编结果里的 mnemonic。
    } else if (mnemonic != nullptr && mnemonic[0] != '\0') {
        name = mnemonic;
    // 仍不可用则给默认值，避免空字符串污染报表。
    } else {
        name = "unknown";
    }
    // 统一拼接“名称(ID)”便于定位。
    std::ostringstream oss;
    oss << name << "(" << insnId << ")";
    return oss.str();
}

// 将字符串转换为 markdown 表格安全格式。
std::string markdownSafe(std::string value) {
    // markdown 表格列分隔符是 |，这里替换为 / 避免破坏列结构。
    for (char& ch : value) {
        if (ch == '|') {
            ch = '/';
        }
    }
    return value;
}

// 对单个函数执行覆盖率统计，并累计到总面板。
void analyzeCoverageForFunction(csh handle,
                                const std::unordered_set<unsigned int>& supportedIds,
                                const vmp::elfkit::FunctionView& function,
                                FunctionCoverageRow& row,
                                CoverageBoard& board) {
    // 没有代码数据时直接返回，仅保留翻译状态字段。
    if (function.getData() == nullptr || function.getSize() == 0) {
        return;
    }

    // capstone 反汇编结果数组指针。
    cs_insn* insn = nullptr;
    // 执行反汇编，起始地址使用函数 offset。
    const size_t instructionCount = cs_disasm(handle,
                                              function.getData(),
                                              function.getSize(),
                                              function.getOffset(),
                                              0,
                                              &insn);
    // 逐条统计支持/不支持情况。
    for (size_t instructionIndex = 0; instructionIndex < instructionCount; ++instructionIndex) {
        const cs_insn& currentInsn = insn[instructionIndex];
        // 判断当前指令是否在支持面内。
        const bool supported = isInstructionSupported(supportedIds,
                                                      currentInsn.id,
                                                      currentInsn.mnemonic);
        // 生成可读标签用于直方图。
        const std::string label = buildInstructionLabel(handle,
                                                        currentInsn.id,
                                                        currentInsn.mnemonic);
        // 函数维度总数 +1。
        ++row.totalInstructions;
        // 全局维度总数 +1。
        ++board.totalInstructions;
        // 按是否支持分流累计计数。
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
    // 释放反汇编结果，避免泄漏。
    if (insn != nullptr) {
        cs_free(insn, instructionCount);
    }
}

// 结束匿名命名空间。
}  // namespace

// 构建覆盖率总面板。
bool buildCoverageBoard(const std::vector<std::string>& functionNames,
                        const std::vector<elfkit::FunctionView>& functions,
                        CoverageBoard& board) {
    // 输入规模必须一致，避免名称和函数对象错位。
    if (functionNames.size() != functions.size()) {
        LOGE("coverage failed: functionNames/functions size mismatch nameCount=%llu functionCount=%llu",
             static_cast<unsigned long long>(functionNames.size()),
             static_cast<unsigned long long>(functions.size()));
        return false;
    }
    // capstone 句柄。
    csh handle = 0;
    // 打开 ARM64 反汇编引擎。
    if (cs_open(CS_ARCH_AARCH64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        LOGE("coverage failed: capstone cs_open failed");
        return false;
    }

    // 构建“可支持指令”集合。
    const std::unordered_set<unsigned int> supportedIds = buildSupportedInsnIdSet();
    // 预留函数行容量，减少扩容开销。
    board.functionRows.reserve(functions.size());
    // 遍历每个函数，填充函数级行数据并汇总到 board。
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

    // 关闭 capstone 句柄。
    cs_close(&handle);
    return true;
}

// 填充翻译状态：该阶段只负责 prepareTranslation 相关信息。
bool fillTranslationStatus(const std::vector<elfkit::FunctionView>& functions,
                           CoverageBoard& board) {
    // 输入规模必须一致，按索引回填。
    if (board.functionRows.size() != functions.size()) {
        LOGE("fillTranslationStatus failed: rowCount/functionCount mismatch rowCount=%llu functionCount=%llu",
             static_cast<unsigned long long>(board.functionRows.size()),
             static_cast<unsigned long long>(functions.size()));
        return false;
    }
    // 逐函数回填翻译状态和错误信息。
    for (size_t functionIndex = 0; functionIndex < functions.size(); ++functionIndex) {
        FunctionCoverageRow& row = board.functionRows[functionIndex];
        row.translateOk = functions[functionIndex].prepareTranslation(&row.translateError);
        row.translateError = markdownSafe(row.translateError);
    }
    return true;
}

// 执行覆盖率分析阶段（统计 + 翻译状态采集）。
bool runCoverageAnalyzeFlow(const std::vector<std::string>& functionNames,
                            const std::vector<elfkit::FunctionView>& functions,
                            CoverageBoard& board) {
    // 构建覆盖率统计面板。
    if (!buildCoverageBoard(functionNames, functions, board)) {
        return false;
    }
    // 补充翻译状态与错误信息。
    if (!fillTranslationStatus(functions, board)) {
        return false;
    }
    return true;
}

// 将覆盖率面板写入报告文件。
bool runCoverageReportFlow(const VmProtectConfig& config, const CoverageBoard& board) {
    // 组合 coverage 报告输出路径。
    const std::string coverageReportPath = joinOutputPath(config, config.coverageReport);
    // 落盘覆盖率报告。
    if (!writeCoverageReport(coverageReportPath, board)) {
        LOGE("failed to write coverage report: %s", coverageReportPath.c_str());
        return false;
    }
    // 输出成功日志。
    LOGI("coverage report written: %s", coverageReportPath.c_str());
    return true;
}

// 执行完整覆盖率流程。
bool runCoverageFlow(const VmProtectConfig& config,
                     const std::vector<std::string>& functionNames,
                     const std::vector<elfkit::FunctionView>& functions,
                     CoverageBoard* outBoard) {
    // 覆盖率看板对象。
    CoverageBoard board;
    // 先执行覆盖率分析阶段。
    if (!runCoverageAnalyzeFlow(functionNames, functions, board)) {
        return false;
    }
    // 再执行报告写入阶段。
    if (!runCoverageReportFlow(config, board)) {
        return false;
    }
    // 可选：把覆盖率结果回传给后续阶段复用。
    if (outBoard != nullptr) {
        *outBoard = board;
    }
    return true;
}

// 将覆盖率面板写入 markdown 报告。
bool writeCoverageReport(const std::string& reportPath, const CoverageBoard& board) {
    // 以覆盖模式打开输出文件。
    std::ofstream out(reportPath, std::ios::trunc);
    // 打开失败直接返回。
    if (!out) {
        return false;
    }

    // 输出总览标题。
    out << "# ARM64 Translation Coverage Board\n\n";
    // 输出总览表头。
    out << "| Metric | Value |\n";
    out << "| --- | ---: |\n";
    // 输出总指令数。
    out << "| Total instructions | " << board.totalInstructions << " |\n";
    // 输出可支持指令数。
    out << "| Supported instructions | " << board.supportedInstructions << " |\n";
    // 输出不支持指令数。
    out << "| Unsupported instructions | " << board.unsupportedInstructions << " |\n\n";

    // 输出函数级明细标题。
    out << "## Per Function\n\n";
    // 输出函数级表头。
    out << "| Function | Total | Supported | Unsupported | Translation OK | Translation Error |\n";
    out << "| --- | ---: | ---: | ---: | --- | --- |\n";
    // 逐函数输出统计行。
    for (const FunctionCoverageRow& row : board.functionRows) {
        out << "| " << row.functionName
            << " | " << row.totalInstructions
            << " | " << row.supportedInstructions
            << " | " << row.unsupportedInstructions
            << " | " << (row.translateOk ? "yes" : "no")
            << " | " << (row.translateError.empty() ? "-" : row.translateError)
            << " |\n";
    }
    // 输出空行分隔后续章节。
    out << "\n";

    // 定义直方图输出器，统一支持/不支持两类统计。
    auto dumpHistogram = [&out](const std::string& title,
                                const std::map<std::string, uint64_t>& hist) {
        // 输出章节标题。
        out << "## " << title << "\n\n";
        // 输出表头。
        out << "| Instruction | Count |\n";
        out << "| --- | ---: |\n";
        // 将 map 拷贝到数组，便于按计数排序。
        std::vector<std::pair<std::string, uint64_t>> sorted(hist.begin(), hist.end());
        // 先按次数降序，再按名称升序，保证可读和稳定。
        std::sort(sorted.begin(), sorted.end(),
                  [](const auto& lhs, const auto& rhs) {
                      if (lhs.second != rhs.second) {
                          return lhs.second > rhs.second;
                      }
                      return lhs.first < rhs.first;
                  });
        // 逐项输出。
        for (const auto& item : sorted) {
            out << "| " << markdownSafe(item.first) << " | " << item.second << " |\n";
        }
        // 每个直方图段落后输出空行。
        out << "\n";
    };

    // 输出不支持指令分布。
    dumpHistogram("Unsupported Instructions", board.unsupportedHistogram);
    // 输出支持指令分布。
    dumpHistogram("Supported Instructions", board.supportedHistogram);
    // 返回流状态。
    return static_cast<bool>(out);
}

// 结束 vmp 命名空间。
}  // namespace vmp



