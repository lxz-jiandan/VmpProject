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

// std::memcpy。
#include <cstring>
// 文件二进制读取。
#include <fstream>

namespace {

#pragma pack(push, 1)
struct EmbeddedPayloadFooter {
    // 固定魔数，用来识别“这不是普通 so 尾部字节，而是我们定义的 footer”。
    uint32_t magic;
    // 协议版本，便于未来平滑升级。
    uint32_t version;
    // payload 长度（字节）。
    uint64_t payload_size;
    // payload 的 CRC32 校验值。
    uint32_t payload_crc32;
    // 预留字段（当前未使用，保持 ABI 稳定）。
    uint32_t reserved;
};
#pragma pack(pop)

bool readFileBytes(const std::string& path, std::vector<uint8_t>& out) {
    // 每次读取前清空输出，避免残留旧数据。
    out.clear();
    // 空路径直接失败。
    if (path.empty()) {
        return false;
    }

    // 以二进制模式打开文件。
    std::ifstream in(path, std::ios::binary);
    // 打开失败直接返回 false。
    if (!in) {
        return false;
    }

    // 跳到文件末尾获取总大小。
    in.seekg(0, std::ios::end);
    // 读取当前偏移（即文件大小）。
    const std::streamoff size = in.tellg();
    // tellg 失败会返回负值。
    if (size < 0) {
        return false;
    }
    // 回到文件起始位置准备读取。
    in.seekg(0, std::ios::beg);

    // 按文件大小分配输出缓冲。
    out.resize(static_cast<size_t>(size));
    // 非空文件才执行 read，空文件直接返回 true。
    if (!out.empty()) {
        in.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()));
    }
    // 仅当读取流状态正常时返回 true。
    return static_cast<bool>(in);
}

template <typename T>
bool readPodAt(const std::vector<uint8_t>& bytes, size_t offset, T& out) {
    // 越界保护：offset 必须在缓冲内，且剩余长度足够读完整 T。
    if (offset > bytes.size() || bytes.size() - offset < sizeof(T)) {
        return false;
    }
    // 直接按 POD 字节拷贝，不涉及字节序转换（协议按当前小端约定）。
    std::memcpy(&out, bytes.data() + offset, sizeof(T));
    return true;
}

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
    const std::string& host_so_path,
    std::vector<uint8_t>& out_payload,
    zEmbeddedPayloadReadStatus* out_status
) {
    // 读取流程：
    // 1) 整体读入 host so；
    // 2) 反向读取 footer；
    // 3) 校验 magic/version/size/crc；
    // 4) 抽取 payload 返回。
    out_payload.clear();
    // 调用方提供 out_status 时，先置为 invalid（默认失败态）。
    if (out_status != nullptr) {
        *out_status = zEmbeddedPayloadReadStatus::kInvalid;
    }

    // 承接整个宿主 so 字节。
    std::vector<uint8_t> host_bytes;
    // 读取宿主 so 到内存。
    if (!readFileBytes(host_so_path, host_bytes)) {
        LOGE("readEmbeddedPayloadFromHostSo failed to read file: %s", host_so_path.c_str());
        return false;
    }

    // 文件长度小于 footer 大小，说明不可能包含嵌入 payload。
    if (host_bytes.size() < sizeof(EmbeddedPayloadFooter)) {
        if (out_status != nullptr) {
            *out_status = zEmbeddedPayloadReadStatus::kNotFound;
        }
        // not found 属于“正常无嵌入”情形，因此返回 true。
        return true;
    }

    // 承接解析出的 footer。
    EmbeddedPayloadFooter footer{};
    // footer 位于文件尾部。
    const size_t footer_offset = host_bytes.size() - sizeof(EmbeddedPayloadFooter);
    // 从尾部偏移读取 footer 结构体。
    if (!readPodAt(host_bytes, footer_offset, footer)) {
        LOGE("readEmbeddedPayloadFromHostSo failed to read footer");
        return false;
    }

    // magic/version 任一不匹配，按“未嵌入 payload”处理。
    if (footer.magic != kFooterMagic || footer.version != kFooterVersion) {
        if (out_status != nullptr) {
            *out_status = zEmbeddedPayloadReadStatus::kNotFound;
        }
        // not found 返回 true，让上层决定是否需要强制失败。
        return true;
    }

    // payload_size 必须非 0 且不能超过“去掉 footer 后的剩余长度”。
    if (footer.payload_size == 0 ||
        footer.payload_size > host_bytes.size() - sizeof(EmbeddedPayloadFooter)) {
        LOGE("readEmbeddedPayloadFromHostSo invalid payload_size=%llu",
             static_cast<unsigned long long>(footer.payload_size));
        if (out_status != nullptr) {
            *out_status = zEmbeddedPayloadReadStatus::kInvalid;
        }
        return false;
    }

    // 计算 payload 起始偏移：文件尾 - footer - payload_size。
    const size_t payload_begin = host_bytes.size() -
                                 sizeof(EmbeddedPayloadFooter) -
                                 static_cast<size_t>(footer.payload_size);
    // payload 实际长度（size_t 版本）。
    const size_t payload_size = static_cast<size_t>(footer.payload_size);
    // 计算 payload 实际 CRC。
    const uint32_t actual_crc = crc32(host_bytes.data() + payload_begin, payload_size);
    // CRC 不一致说明 payload 被破坏或 footer 信息错误。
    if (actual_crc != footer.payload_crc32) {
        LOGE("readEmbeddedPayloadFromHostSo crc mismatch expected=0x%x actual=0x%x",
             footer.payload_crc32,
             actual_crc);
        if (out_status != nullptr) {
            *out_status = zEmbeddedPayloadReadStatus::kInvalid;
        }
        return false;
    }

    // 校验通过：分配输出缓冲并拷贝 payload。
    out_payload.resize(payload_size);
    std::memcpy(out_payload.data(), host_bytes.data() + payload_begin, payload_size);
    // 回写成功状态。
    if (out_status != nullptr) {
        *out_status = zEmbeddedPayloadReadStatus::kOk;
    }
    // 返回读取成功。
    return true;
}
