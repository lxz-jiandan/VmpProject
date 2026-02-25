/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - 从宿主 so 末尾读取嵌入 payload 并做 CRC 校验。
 * - 加固链路位置：第四路线 L1（内嵌 expand so 读取）。
 * - 输入：宿主 so 路径。
 * - 输出：校验通过的 payload 字节。
 */
// 对外接口声明（magic/version/status/crc/read API）。
#include "zEmbeddedPayload.h"

// 统一日志输出。
#include "zLog.h"
#include "zFileBytes.h"

// std::memcpy。
#include <cstring>

namespace {

#pragma pack(push, 1)
struct EmbeddedPayloadFooter {
    // 固定魔数，用来识别“这不是普通 so 尾部字节，而是我们定义的 footer”。
    uint32_t magic;
    // 协议版本，便于未来平滑升级。
    uint32_t version;
    // payload 长度（字节）。
    uint64_t payloadSize;
    // payload 的 CRC32 校验值。
    uint32_t payloadCrc32;
    // 预留字段（当前未使用，保持 ABI 稳定）。
    uint32_t reserved;
};
#pragma pack(pop)

} // namespace

uint32_t zEmbeddedPayload::crc32(const uint8_t* data, size_t size) {
    // 标准 CRC-32 (poly=0xEDB88320)。
    static uint32_t table[256];
    static bool table_inited = false;
    // 首次调用时构建 CRC 查表，加速后续计算。
    if (!table_inited) {
        // 逐项生成 256 个查表项。
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            // 每个字节做 8 轮多项式变换。
            for (int k = 0; k < 8; ++k) {
                c = (c & 1u) ? (0xEDB88320u ^ (c >> 1u)) : (c >> 1u);
            }
            table[i] = c;
        }
        // 标记查表已初始化。
        table_inited = true;
    }

    // CRC 初值。
    uint32_t c = 0xFFFFFFFFu;
    // 逐字节滚动更新 CRC。
    for (size_t i = 0; i < size; ++i) {
        c = table[(c ^ data[i]) & 0xFFu] ^ (c >> 8u);
    }
    // 末尾异或输出。
    return c ^ 0xFFFFFFFFu;
}

bool zEmbeddedPayload::readEmbeddedPayloadFromHostSo(
    const std::string& hostSoPath,
    std::vector<uint8_t>& outPayload,
    zEmbeddedPayloadReadStatus* outStatus
) {
    // 读取流程：
    // 1) 整体读入 host so；
    // 2) 反向读取 footer；
    // 3) 校验 magic/version/size/crc；
    // 4) 抽取 payload 返回。
    outPayload.clear();
    // 调用方提供 outStatus 时，先置为 invalid（默认失败态）。
    if (outStatus != nullptr) {
        *outStatus = zEmbeddedPayloadReadStatus::kInvalid;
    }

    // 承接整个宿主 so 字节。
    std::vector<uint8_t> hostBytes;
    // 读取宿主 so 到内存。
    if (!zFileBytes::readFileBytes(hostSoPath, hostBytes)) {
        LOGE("readEmbeddedPayloadFromHostSo failed to read file: %s", hostSoPath.c_str());
        return false;
    }

    // 文件长度小于 footer 大小，说明不可能包含嵌入 payload。
    if (hostBytes.size() < sizeof(EmbeddedPayloadFooter)) {
        if (outStatus != nullptr) {
            *outStatus = zEmbeddedPayloadReadStatus::kNotFound;
        }
        // not found 属于“正常无嵌入”情形，因此返回 true。
        return true;
    }

    // 承接解析出的 footer。
    EmbeddedPayloadFooter footer{};
    // footer 位于文件尾部。
    const size_t footerOffset = hostBytes.size() - sizeof(EmbeddedPayloadFooter);
    // 从尾部偏移读取 footer 结构体。
    if (!zFileBytes::readPodAt(hostBytes, footerOffset, footer)) {
        LOGE("readEmbeddedPayloadFromHostSo failed to read footer");
        return false;
    }

    // magic/version 任一不匹配，按“未嵌入 payload”处理。
    if (footer.magic != kFooterMagic || footer.version != kFooterVersion) {
        if (outStatus != nullptr) {
            *outStatus = zEmbeddedPayloadReadStatus::kNotFound;
        }
        // not found 返回 true，让上层决定是否需要强制失败。
        return true;
    }

    // payloadSize 必须非 0 且不能超过“去掉 footer 后的剩余长度”。
    if (footer.payloadSize == 0 ||
        footer.payloadSize > hostBytes.size() - sizeof(EmbeddedPayloadFooter)) {
        LOGE("readEmbeddedPayloadFromHostSo invalid payloadSize=%llu",
             static_cast<unsigned long long>(footer.payloadSize));
        if (outStatus != nullptr) {
            *outStatus = zEmbeddedPayloadReadStatus::kInvalid;
        }
        return false;
    }

    // 计算 payload 起始偏移：文件尾 - footer - payloadSize。
    const size_t payloadBegin = hostBytes.size() -
                                 sizeof(EmbeddedPayloadFooter) -
                                 static_cast<size_t>(footer.payloadSize);
    // payload 实际长度（size_t 版本）。
    const size_t payloadSize = static_cast<size_t>(footer.payloadSize);
    // 计算 payload 实际 CRC。
    const uint32_t actualCrc = crc32(hostBytes.data() + payloadBegin, payloadSize);
    // CRC 不一致说明 payload 被破坏或 footer 信息错误。
    if (actualCrc != footer.payloadCrc32) {
        LOGE("readEmbeddedPayloadFromHostSo crc mismatch expected=0x%x actual=0x%x",
             footer.payloadCrc32,
             actualCrc);
        if (outStatus != nullptr) {
            *outStatus = zEmbeddedPayloadReadStatus::kInvalid;
        }
        return false;
    }

    // 校验通过：分配输出缓冲并拷贝 payload。
    outPayload.resize(payloadSize);
    std::memcpy(outPayload.data(), hostBytes.data() + payloadBegin, payloadSize);
    // 回写成功状态。
    if (outStatus != nullptr) {
        *outStatus = zEmbeddedPayloadReadStatus::kOk;
    }
    // 返回读取成功。
    return true;
}
