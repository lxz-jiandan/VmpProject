// 引入 embedded payload 尾部协议工具声明。
#include "zEmbeddedPayloadTail.h"

// 引入 CRC32 校验算法。
#include "zChecksum.h"

// 引入 memcpy。
#include <cstring>

// 进入基础层 embedded payload 命名空间。
namespace vmp::base::embedded {

// 进入匿名命名空间，封装协议内部细节。
namespace {

// 按 1 字节对齐，保证 footer 跨编译器稳定落盘。
#pragma pack(push, 1)
// embedded payload 尾部描述结构。
struct EmbeddedPayloadFooter {
    // 协议魔数（'VME4'）。
    uint32_t magic;
    // 协议版本。
    uint32_t version;
    // payload 字节长度。
    uint64_t payloadSize;
    // payload CRC32 校验值。
    uint32_t payloadCrc32;
    // 预留字段，当前固定写 0。
    uint32_t reserved;
};
#pragma pack(pop)

// 当前 embedded payload 协议魔数。
constexpr uint32_t kEmbeddedPayloadMagic = 0x34454D56U;  // 'VME4'
// 当前 embedded payload 协议版本。
constexpr uint32_t kEmbeddedPayloadVersion = 1U;

// 结束匿名命名空间。
}  // namespace

// 返回 footer 固定字节大小。
size_t getEmbeddedPayloadFooterSize() {
    return sizeof(EmbeddedPayloadFooter);
}

// 解析文件末尾 embedded payload 协议。
bool parseEmbeddedPayloadTail(const std::vector<uint8_t>& fileBytes,
                              EmbeddedPayloadTailInfo* outInfo,
                              std::string* error) {
    // 输出参数不能为空。
    if (outInfo == nullptr) {
        if (error != nullptr) {
            *error = "embedded payload parse output is null";
        }
        return false;
    }

    // 先填充“无尾部”的默认值。
    outInfo->hasTail = false;
    outInfo->baseSize = fileBytes.size();
    outInfo->payloadBytes.clear();

    // 文件长度小于 footer 时，不可能包含 embedded payload。
    if (fileBytes.size() < sizeof(EmbeddedPayloadFooter)) {
        return true;
    }

    // 从文件尾部读取 footer。
    EmbeddedPayloadFooter footer{};
    const size_t footerOff = fileBytes.size() - sizeof(EmbeddedPayloadFooter);
    std::memcpy(&footer, fileBytes.data() + footerOff, sizeof(EmbeddedPayloadFooter));

    // magic/version 不匹配时按“无尾部”处理，不视为错误。
    if (footer.magic != kEmbeddedPayloadMagic || footer.version != kEmbeddedPayloadVersion) {
        return true;
    }

    // 命中协议后必须校验 payloadSize 合法性。
    if (footer.payloadSize == 0 ||
        footer.payloadSize > fileBytes.size() - sizeof(EmbeddedPayloadFooter)) {
        if (error != nullptr) {
            *error = "embedded payload footer has invalid payload size";
        }
        return false;
    }

    // 计算 payload 起始偏移。
    const size_t payloadBegin = fileBytes.size() -
                                sizeof(EmbeddedPayloadFooter) -
                                static_cast<size_t>(footer.payloadSize);
    // 重新计算 payload CRC32。
    const uint32_t actualCrc = checksum::crc32Ieee(
        fileBytes.data() + payloadBegin,
        static_cast<size_t>(footer.payloadSize));
    // CRC 不一致说明尾部已损坏。
    if (actualCrc != footer.payloadCrc32) {
        if (error != nullptr) {
            *error = "embedded payload footer crc mismatch";
        }
        return false;
    }

    // 解析成功：回填结果结构。
    outInfo->hasTail = true;
    outInfo->baseSize = payloadBegin;
    outInfo->payloadBytes.assign(fileBytes.begin() + static_cast<std::ptrdiff_t>(payloadBegin),
                                 fileBytes.begin() + static_cast<std::ptrdiff_t>(footerOff));
    return true;
}

// 在文件尾部追加 payload 与 footer。
void appendEmbeddedPayloadTail(std::vector<uint8_t>* fileBytes,
                               const std::vector<uint8_t>& payloadBytes) {
    // 空文件缓冲或空 payload 直接返回。
    if (fileBytes == nullptr || payloadBytes.empty()) {
        return;
    }

    // 先追加 payload 原文。
    fileBytes->insert(fileBytes->end(), payloadBytes.begin(), payloadBytes.end());

    // 构建 footer 并追加。
    EmbeddedPayloadFooter footer{};
    footer.magic = kEmbeddedPayloadMagic;
    footer.version = kEmbeddedPayloadVersion;
    footer.payloadSize = static_cast<uint64_t>(payloadBytes.size());
    footer.payloadCrc32 = checksum::crc32Ieee(payloadBytes);
    footer.reserved = 0;
    const auto* footerBytes = reinterpret_cast<const uint8_t*>(&footer);
    fileBytes->insert(fileBytes->end(),
                      footerBytes,
                      footerBytes + sizeof(EmbeddedPayloadFooter));
}

// 结束命名空间。
}  // namespace vmp::base::embedded

