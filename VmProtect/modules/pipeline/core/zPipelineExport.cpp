#include "zPipelineExport.h"

// 引入文件流用于写中间产物。
#include <fstream>
// 引入字符串类型。
#include <string>
// 引入哈希集合用于去重地址。
#include <unordered_set>
// 引入 move 语义工具。
#include <utility>
// 引入动态数组容器。
#include <vector>

// 引入 IO 基础工具函数。
#include "zFile.h"
// 引入日志工具。
#include "zLog.h"
// 引入 pipeline 路径拼接工具。
#include "zPipelineCli.h"
// 引入 expand so 打包器。
#include "zSoBinBundle.h"

// 进入 vmp 主命名空间。
namespace vmp {

// 进入匿名命名空间，收拢本文件内部辅助逻辑。
namespace {

// 将共享分支地址列表写成 C 源片段，供后续链路消费。
bool writeSharedBranchAddrList(const char* filePath,
                               const std::vector<uint64_t>& branchAddrs) {
    // 校验输出路径有效性。
    if (filePath == nullptr || filePath[0] == '\0') {
        return false;
    }
    // 以覆盖模式打开文件。
    std::ofstream out(filePath, std::ios::trunc);
    // 打开失败直接返回。
    if (!out) {
        return false;
    }
    // 始终输出地址数量常量。
    out << "static const uint64_t branch_addr_count = " << branchAddrs.size() << ";\n";
    // 空列表时输出占位数组，避免生成非法 C 代码。
    if (branchAddrs.empty()) {
        out << "uint64_t branch_addr_list[1] = {};\n";
        return static_cast<bool>(out);
    }
    // 非空时输出真实数组初始化列表。
    out << "uint64_t branch_addr_list[] = { ";
    for (size_t branchIndex = 0; branchIndex < branchAddrs.size(); ++branchIndex) {
        if (branchIndex > 0) {
            out << ", ";
        }
        // 地址按十六进制输出，便于和反汇编地址对照。
        out << "0x" << std::hex << branchAddrs[branchIndex] << std::dec;
    }
    out << " };\n";
    return static_cast<bool>(out);
}

// 将局部地址列表追加到全局共享列表，并做去重。
void appendUniqueBranchAddrs(const std::vector<uint64_t>& localAddrs,
                             std::unordered_set<uint64_t>& seenAddrs,
                             std::vector<uint64_t>& outShared) {
    // 遍历当前函数产生的共享分支地址。
    for (uint64_t addr : localAddrs) {
        // 首次出现才写入最终列表，保证唯一性。
        if (seenAddrs.insert(addr).second) {
            outShared.push_back(addr);
        }
    }
}

// 校验导出前的翻译状态。
// 优先复用覆盖率阶段产出的 translateOk 结果；缺失时回退到直接 prepareTranslation。
bool validateTranslationForExport(const std::vector<std::string>& functionNames,
                                  const std::vector<elfkit::FunctionView>& functions,
                                  const CoverageBoard* coverageBoard) {
    // 优先尝试复用 coverageBoard，避免重复 prepareTranslation。
    if (coverageBoard != nullptr) {
        const std::vector<FunctionCoverageRow>& rows = coverageBoard->functionRows;
        if (rows.size() == functions.size()) {
            bool nameAligned = true;
            for (size_t rowIndex = 0; rowIndex < rows.size(); ++rowIndex) {
                if (rows[rowIndex].functionName != functionNames[rowIndex]) {
                    nameAligned = false;
                    break;
                }
            }
            if (nameAligned) {
                for (size_t rowIndex = 0; rowIndex < rows.size(); ++rowIndex) {
                    if (!rows[rowIndex].translateOk) {
                        LOGE("translation failed for %s: %s",
                             functionNames[rowIndex].c_str(),
                             rows[rowIndex].translateError.c_str());
                        return false;
                    }
                }
                return true;
            }
            LOGW("coverage rows name order mismatch, fallback to direct prepareTranslation");
        } else {
            LOGW("coverage rows size mismatch, fallback to direct prepareTranslation: rowCount=%llu functionCount=%llu",
                 static_cast<unsigned long long>(rows.size()),
                 static_cast<unsigned long long>(functions.size()));
        }
    }

    // 回退路径：逐函数直接校验翻译状态。
    for (size_t functionIndex = 0; functionIndex < functions.size(); ++functionIndex) {
        std::string error;
        if (!functions[functionIndex].prepareTranslation(&error)) {
            LOGE("translation failed for %s: %s",
                 functionNames[functionIndex].c_str(),
                 error.c_str());
            return false;
        }
    }
    return true;
}

// 结束匿名命名空间。
}  // namespace

// 按函数名从 ELF 中收集函数视图对象。
bool collectFunctions(elfkit::ElfImage& elf,
                      const std::vector<std::string>& functionNames,
                      std::vector<elfkit::FunctionView>& functions) {
    // 清空旧结果，避免污染本轮导出。
    functions.clear();
    // 预留容量，降低扩容次数。
    functions.reserve(functionNames.size());
    // 按输入顺序逐个解析函数。
    for (const std::string& functionName : functionNames) {
        // 尝试从符号/映像中查找函数。
        elfkit::FunctionView function = elf.getFunction(functionName);
        // 任一函数找不到即整体失败，保持流程强一致。
        if (!function.isValid()) {
            LOGE("failed to resolve function: %s", functionName.c_str());
            return false;
        }
        // 输出函数解析结果，便于排查映射错误。
        LOGI("resolved function %s at 0x%llx",
             function.getName().c_str(),
             static_cast<unsigned long long>(function.getOffset()));
        // 写入收集结果数组。
        functions.push_back(function);
    }
    return true;
}

// 导出保护包：文本 dump、编码 payload、共享分支列表和 expand so。
bool exportProtectedPackage(const VmProtectConfig& config,
                            const std::vector<std::string>& functionNames,
                            const std::vector<elfkit::FunctionView>& functions,
                            const CoverageBoard* coverageBoard) {
    // 第一阶段：先验证每个函数能否进入翻译链路（优先复用 coverage 结果）。
    if (!validateTranslationForExport(functionNames, functions, coverageBoard)) {
        return false;
    }

    // 第二阶段：合并所有函数的共享分支地址并去重。
    std::vector<uint64_t> sharedBranchAddrs;
    std::unordered_set<uint64_t> seenAddrs;
    for (const elfkit::FunctionView& function : functions) {
        appendUniqueBranchAddrs(function.getSharedBranchAddrs(), seenAddrs, sharedBranchAddrs);
    }

    // 将共享分支地址写出到约定文件。
    const std::string sharedBranchFile = joinOutputPath(config, config.sharedBranchFile);
    if (!writeSharedBranchAddrList(sharedBranchFile.c_str(), sharedBranchAddrs)) {
        LOGE("failed to write shared branch list: %s", sharedBranchFile.c_str());
        return false;
    }

    // 第三阶段：逐函数生成 payload。
    std::vector<zSoBinPayload> payloads;
    payloads.reserve(functions.size());

    for (size_t functionIndex = 0; functionIndex < functions.size(); ++functionIndex) {
        const elfkit::FunctionView& function = functions[functionIndex];
        const std::string& functionName = functionNames[functionIndex];

        // 把 OP_BL 重映射到共享分支地址表索引体系。
        if (!function.remapBlToSharedBranchAddrs(sharedBranchAddrs)) {
            LOGE("failed to remap OP_BL for %s", functionName.c_str());
            return false;
        }

        // 生成人读文本产物和机器编码产物。
        const std::string txtPath = joinOutputPath(config, functionName + ".txt");
        const std::string binPath = joinOutputPath(config, functionName + ".bin");
        if (!function.dump(txtPath.c_str(), elfkit::DumpMode::kUnencoded)) {
            LOGE("failed to dump unencoded txt: %s", txtPath.c_str());
            return false;
        }
        if (!function.dump(binPath.c_str(), elfkit::DumpMode::kEncoded)) {
            LOGE("failed to dump encoded bin: %s", binPath.c_str());
            return false;
        }

        // 组装 so bundle 需要的 payload 结构。
        zSoBinPayload payload;
        // 记录函数地址，供运行时定位。
        payload.funAddr = static_cast<uint64_t>(function.getOffset());
        // 读取编码后的二进制字节。
        if (!base::file::readFileBytes(binPath.c_str(), &payload.encodedBytes) ||
            payload.encodedBytes.empty()) {
            LOGE("failed to read encoded payload: %s", binPath.c_str());
            return false;
        }
        // 压入总 payload 列表。
        payloads.push_back(std::move(payload));
    }

    // 第四阶段：把 payload 与地址表写入 expanded so。
    const std::string expandedSoPath = joinOutputPath(config, config.expandedSo);
    if (!zSoBinBundleWriter::writeExpandedSo(
            config.inputSo.c_str(),
            expandedSoPath.c_str(),
            payloads,
            sharedBranchAddrs)) {
        LOGE("failed to build expanded so: %s", expandedSoPath.c_str());
        return false;
    }

    // 输出导出完成摘要。
    LOGI("export completed: payload_count=%u shared_branch_addr_count=%u",
         static_cast<unsigned int>(payloads.size()),
         static_cast<unsigned int>(sharedBranchAddrs.size()));
    return true;
}

// 结束 vmp 命名空间。
}  // namespace vmp





