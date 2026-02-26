#include "zPipelinePatch.h"

// 引入固定宽度整型格式支持。
#include <cinttypes>
// 引入内存拷贝工具。
#include <cstring>
// 引入文件系统路径处理。
#include <filesystem>
// 引入字符串类型。
#include <string>
// 引入动态数组容器。
#include <vector>

// 引入 CRC32 校验算法。
#include "zChecksum.h"
// 引入 patchbay 进程内入口。
#include "zPatchbayEntry.h"
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

// 进入匿名命名空间，封装本文件内部协议细节。
namespace {

// 按 1 字节对齐，确保 footer 布局可跨编译器稳定落盘。
#pragma pack(push, 1)
// 嵌入 payload 的尾部描述结构。
struct EmbeddedPayloadFooter {
    // 协议魔数，用于识别是否存在嵌入块。
    uint32_t magic;
    // 协议版本，便于未来升级。
    uint32_t version;
    // payload 字节长度。
    uint64_t payloadSize;
    // payload CRC32 校验值。
    uint32_t payloadCrc32;
    // 预留字段，当前写 0。
    uint32_t reserved;
};
#pragma pack(pop)

// 当前嵌入协议魔数，字符串语义为 'VME4'。
constexpr uint32_t kEmbeddedPayloadMagic = 0x34454D56U;  // 'VME4'
// 当前嵌入协议版本。
constexpr uint32_t kEmbeddedPayloadVersion = 1U;

// 解析 vmengine so 末尾是否已存在旧 payload，并给出基础体大小。
bool parseExistingEmbeddedPayload(const std::vector<uint8_t>& vmengineBytes,
                                  size_t* outBaseSize,
                                  size_t* outOldPayloadSize) {
    // 输出参数必须有效。
    if (outBaseSize == nullptr || outOldPayloadSize == nullptr) {
        return false;
    }
    // 默认假设“无历史 payload”，基础体就是整文件。
    *outBaseSize = vmengineBytes.size();
    *outOldPayloadSize = 0;
    // 文件长度不足一个 footer，说明不可能有嵌入块。
    if (vmengineBytes.size() < sizeof(EmbeddedPayloadFooter)) {
        return true;
    }

    // 从文件尾部拷贝 footer。
    EmbeddedPayloadFooter footer{};
    const size_t footerOff = vmengineBytes.size() - sizeof(EmbeddedPayloadFooter);
    std::memcpy(&footer, vmengineBytes.data() + footerOff, sizeof(EmbeddedPayloadFooter));
    // 魔数/版本不匹配时，按“无嵌入块”处理，不视为错误。
    if (footer.magic != kEmbeddedPayloadMagic || footer.version != kEmbeddedPayloadVersion) {
        return true;
    }
    // 校验 payloadSize 合法性，防止越界。
    if (footer.payloadSize == 0 ||
        footer.payloadSize > vmengineBytes.size() - sizeof(EmbeddedPayloadFooter)) {
        LOGE("embedded footer invalid payloadSize=%llu",
             static_cast<unsigned long long>(footer.payloadSize));
        return false;
    }

    // 计算 payload 起始偏移。
    const size_t payloadBegin = vmengineBytes.size() -
                                 sizeof(EmbeddedPayloadFooter) -
                                 static_cast<size_t>(footer.payloadSize);
    // 对 payload 重新计算 CRC32。
    const uint32_t actualCrc = base::checksum::crc32Ieee(
        vmengineBytes.data() + payloadBegin,
        static_cast<size_t>(footer.payloadSize));
    // CRC 不一致说明文件损坏或协议不匹配。
    if (actualCrc != footer.payloadCrc32) {
        LOGE("embedded footer crc mismatch expected=0x%x actual=0x%x",
             footer.payloadCrc32,
             actualCrc);
        return false;
    }

    // 记录基础体大小（不含旧 payload 与 footer）。
    *outBaseSize = payloadBegin;
    // 记录旧 payload 长度，便于日志输出替换语义。
    *outOldPayloadSize = static_cast<size_t>(footer.payloadSize);
    return true;
}

// 在同进程内调用 patchbay 子命令入口，避免额外进程开销。
int runPatchbayCommandInProcess(const std::vector<std::string>& args) {
    // 参数数组为空时直接返回错误码。
    if (args.empty()) {
        return -1;
    }
    // 组装 C 风格 argv。
    std::vector<char*> argv;
    argv.reserve(args.size());
    for (const std::string& arg : args) {
        argv.push_back(const_cast<char*>(arg.c_str()));
    }
    // 直接调用内嵌入口函数。
    return vmprotectPatchbayEntry(static_cast<int>(argv.size()), argv.data());
}

// 结束匿名命名空间。
}  // namespace

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
    size_t baseSize = vmengineBytes.size();
    size_t oldPayloadSize = 0;
    if (!parseExistingEmbeddedPayload(vmengineBytes, &baseSize, &oldPayloadSize)) {
        LOGE("failed to parse existing embedded payload in vmengine so: %s", vmengineSo.c_str());
        return false;
    }

    // 组装输出字节：基础体 + 新 payload + 新 footer。
    std::vector<uint8_t> out;
    out.reserve(baseSize + payloadBytes.size() + sizeof(EmbeddedPayloadFooter));
    out.insert(out.end(),
               vmengineBytes.begin(),
               vmengineBytes.begin() + static_cast<std::ptrdiff_t>(baseSize));
    out.insert(out.end(), payloadBytes.begin(), payloadBytes.end());

    // 填充 footer 字段。
    EmbeddedPayloadFooter footer{};
    footer.magic = kEmbeddedPayloadMagic;
    footer.version = kEmbeddedPayloadVersion;
    footer.payloadSize = static_cast<uint64_t>(payloadBytes.size());
    footer.payloadCrc32 = base::checksum::crc32Ieee(payloadBytes);
    footer.reserved = 0;
    // 将 footer 作为原始字节追加到输出尾部。
    const uint8_t* footerBytes = reinterpret_cast<const uint8_t*>(&footer);
    out.insert(out.end(), footerBytes, footerBytes + sizeof(EmbeddedPayloadFooter));

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

    // 组装 patchbay CLI 参数。
    std::vector<std::string> cmd = {
        "VmProtect.exe",
        "export_alias_from_patchbay",
        inputSo,
        donorSo,
        outputSo,
        implSymbol,
    };
    // 按调用方要求，允许校验失败继续。
    if (allowValidateFail) {
        cmd.emplace_back("--allow-validate-fail");
    }
    // 非全量 patch 时只处理 Java 导出函数。
    if (!patchAllExports) {
        cmd.emplace_back("--only-fun-java");
    }

    // 在进程内执行 patchbay 命令。
    const int rc = runPatchbayCommandInProcess(cmd);
    // 返回码非 0 视为失败。
    if (rc != 0) {
        LOGE("patchbay command failed rc=%d", rc);
        return false;
    }
    // 命令成功后再次校验输出文件确实生成。
    if (!base::file::fileExists(outputSo)) {
        LOGE("patch output not found: %s", outputSo.c_str());
        return false;
    }

    // 输出完成摘要，便于问题排查。
    LOGI("patchbay export completed: tool=embedded input=%s output=%s donor=%s impl=%s patchAllExports=%d",
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





