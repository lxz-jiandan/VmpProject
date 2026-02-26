#include "zPipelinePatch.h"

// 引入固定宽度整型格式支持。
#include <cinttypes>
// 引入 ptrdiff_t 等基础类型定义。
#include <cstddef>
// 引入文件系统路径处理。
#include <filesystem>
// 引入字符串类型。
#include <string>
// 引入动态数组容器。
#include <vector>

// 引入 embedded payload 尾部协议工具。
#include "zEmbeddedPayloadTail.h"
// 引入 patchbay donor 领域 API。
#include "zPatchbayDonor.h"
// 引入文件读写与存在性判断工具。
#include "zFile.h"
// 引入日志能力。
#include "zLog.h"
// 引入输出路径拼接工具。
#include "zPipelineCli.h"
// 引入流程配置结构。
#include "zPipelineTypes.h"

// 简化 std::filesystem 命名引用。
namespace fs = std::filesystem;

// 进入 vmp 主命名空间。
namespace vmp {

// 把 expanded so 嵌入 vmengine so，输出最终可发布 so。
bool embedExpandedSoIntoVmengine(const std::string& vmengineSo,
                                 const std::string& payloadSo,
                                 const std::string& outputSo) {
    // 校验 vmengine so 是否存在。
    if (!base::file::fileExists(vmengineSo)) {
        LOGE("vmengine so not found: %s", vmengineSo.c_str());
        return false;
    }
    // 校验 payload so 是否存在。
    if (!base::file::fileExists(payloadSo)) {
        LOGE("payload so not found: %s", payloadSo.c_str());
        return false;
    }
    // 校验输出路径非空。
    if (outputSo.empty()) {
        LOGE("output so path is empty");
        return false;
    }

    // 读取 vmengine so 全量字节。
    std::vector<uint8_t> vmengineBytes;
    if (!base::file::readFileBytes(vmengineSo.c_str(), &vmengineBytes)) {
        LOGE("failed to read vmengine so: %s", vmengineSo.c_str());
        return false;
    }
    // 读取 payload so 全量字节。
    std::vector<uint8_t> payloadBytes;
    if (!base::file::readFileBytes(payloadSo.c_str(), &payloadBytes) || payloadBytes.empty()) {
        LOGE("failed to read payload so: %s", payloadSo.c_str());
        return false;
    }

    // 解析 vmengine so 是否已有旧嵌入 payload。
    base::embedded::EmbeddedPayloadTailInfo tailInfo;
    std::string tailError;
    if (!base::embedded::parseEmbeddedPayloadTail(vmengineBytes, &tailInfo, &tailError)) {
        LOGE("failed to parse existing embedded payload in vmengine so: %s error=%s",
             vmengineSo.c_str(),
             tailError.empty() ? "(unknown)" : tailError.c_str());
        return false;
    }
    const size_t baseSize = tailInfo.baseSize;
    const size_t oldPayloadSize = tailInfo.hasTail ? tailInfo.payloadBytes.size() : 0U;

    // 组装输出字节：基础体 + 新 payload + 新 footer。
    std::vector<uint8_t> out;
    out.reserve(baseSize + payloadBytes.size() + base::embedded::getEmbeddedPayloadFooterSize());
    out.insert(out.end(),
               vmengineBytes.begin(),
               vmengineBytes.begin() + static_cast<std::ptrdiff_t>(baseSize));
    base::embedded::appendEmbeddedPayloadTail(&out, payloadBytes);

    // 写出最终 so 文件。
    if (!base::file::writeFileBytes(outputSo, out)) {
        LOGE("failed to write output so: %s", outputSo.c_str());
        return false;
    }

    // 根据是否替换旧 payload 输出不同日志语义。
    if (oldPayloadSize > 0) {
        LOGI("embed vmengine so: replaced existing payload old=%llu new=%llu output=%s",
             static_cast<unsigned long long>(oldPayloadSize),
             static_cast<unsigned long long>(payloadBytes.size()),
             outputSo.c_str());
    } else {
        LOGI("embed vmengine so: appended payload=%llu output=%s",
             static_cast<unsigned long long>(payloadBytes.size()),
             outputSo.c_str());
    }
    return true;
}

// 调用 patchbay：从 donor 导出 alias 并注入目标 so。
bool runPatchbayExportFromDonor(const std::string& inputSo,
                                const std::string& outputSo,
                                const std::string& donorSo,
                                const std::string& implSymbol,
                                bool patchAllExports,
                                bool allowValidateFail) {
    // 校验输入 so 存在。
    if (!base::file::fileExists(inputSo)) {
        LOGE("patch input so not found: %s", inputSo.c_str());
        return false;
    }
    // 校验输出路径非空。
    if (outputSo.empty()) {
        LOGE("patch output so is empty");
        return false;
    }
    // 校验 donor so 存在。
    if (!base::file::fileExists(donorSo)) {
        LOGE("patch donor so not found: %s", donorSo.c_str());
        return false;
    }
    // 校验实现符号名非空。
    if (implSymbol.empty()) {
        LOGE("patch impl symbol is empty");
        return false;
    }

    // 组装 donor API 请求对象。
    zPatchbayDonorRequest request;
    request.inputSoPath = inputSo;
    request.donorSoPath = donorSo;
    request.outputSoPath = outputSo;
    request.implSymbol = implSymbol;
    request.onlyFunJava = !patchAllExports;
    request.allowValidateFail = allowValidateFail;

    // 执行 donor API。
    zPatchbayDonorResult runResult;
    if (!runPatchbayExportAliasFromDonor(request, &runResult)) {
        LOGE("patchbay donor api failed: status=%d rc=%d error=%s",
             static_cast<int>(runResult.status),
             runResult.exitCode,
             runResult.error.empty() ? "(unknown)" : runResult.error.c_str());
        return false;
    }
    // 命令成功后再次校验输出文件确实生成。
    if (!base::file::fileExists(outputSo)) {
        LOGE("patch output not found: %s", outputSo.c_str());
        return false;
    }

    // 输出完成摘要，便于问题排查。
    LOGI("patchbay export completed: tool=domain_api input=%s output=%s donor=%s impl=%s patchAllExports=%d",
         inputSo.c_str(),
         outputSo.c_str(),
         donorSo.c_str(),
         implSymbol.c_str(),
         patchAllExports ? 1 : 0);
    return true;
}

// 执行 vmengine 保护流程（可选）。
bool runVmengineProtectFlow(const VmProtectConfig& config) {
    // 未指定 vmengine 时直接跳过。
    if (config.vmengineSo.empty()) {
        return true;
    }

    // expanded so 的完整路径。
    const std::string expandedSoPath = joinOutputPath(config, config.expandedSo);
    // 未指定 donor：仅做 embed。
    if (config.patchDonorSo.empty()) {
        // outputSo 在加固路线下必须显式传入，直接执行 embed。
        return embedExpandedSoIntoVmengine(config.vmengineSo, expandedSoPath, config.outputSo);
    }

    // 指定 donor：走 embed + patchbay 导出流程。
    const std::string outputSoPath = config.outputSo;
    // patch 前临时文件路径。
    const std::string embedTmpSoPath = outputSoPath + ".embed.tmp.so";
    // 先把 expanded so 注入临时 so。
    if (!embedExpandedSoIntoVmengine(config.vmengineSo, expandedSoPath, embedTmpSoPath)) {
        return false;
    }
    // 再执行 patchbay donor 导出流程。
    if (!runPatchbayExportFromDonor(embedTmpSoPath,
                                    outputSoPath,
                                    config.patchDonorSo,
                                    config.patchImplSymbol,
                                    config.patchAllExports,
                                    config.patchAllowValidateFail)) {
        return false;
    }

    // 清理临时文件（失败仅告警不阻断）。
    std::error_code ec;
    fs::remove(embedTmpSoPath, ec);
    if (ec) {
        LOGW("remove embed tmp so failed: %s", embedTmpSoPath.c_str());
    }
    return true;
}

// 结束 vmp 命名空间。
}  // namespace vmp





