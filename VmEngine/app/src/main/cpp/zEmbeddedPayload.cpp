#include "zEmbeddedPayload.h"

#include "zLog.h"

#include <cstring>
#include <fstream>

namespace {

#pragma pack(push, 1)
struct EmbeddedPayloadFooter {
    uint32_t magic;
    uint32_t version;
    uint64_t payload_size;
    uint32_t payload_crc32;
    uint32_t reserved;
};
#pragma pack(pop)

bool readFileBytes(const std::string& path, std::vector<uint8_t>& out) {
    out.clear();
    if (path.empty()) {
        return false;
    }

    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return false;
    }

    in.seekg(0, std::ios::end);
    const std::streamoff size = in.tellg();
    if (size < 0) {
        return false;
    }
    in.seekg(0, std::ios::beg);

    out.resize(static_cast<size_t>(size));
    if (!out.empty()) {
        in.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()));
    }
    return static_cast<bool>(in);
}

template <typename T>
bool readPodAt(const std::vector<uint8_t>& bytes, size_t offset, T& out) {
    if (offset > bytes.size() || bytes.size() - offset < sizeof(T)) {
        return false;
    }
    std::memcpy(&out, bytes.data() + offset, sizeof(T));
    return true;
}

} // namespace

uint32_t zEmbeddedPayload::crc32(const uint8_t* data, size_t size) {
    // 标准 CRC-32 (poly=0xEDB88320)。
    static uint32_t table[256];
    static bool table_inited = false;
    if (!table_inited) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) {
                c = (c & 1u) ? (0xEDB88320u ^ (c >> 1u)) : (c >> 1u);
            }
            table[i] = c;
        }
        table_inited = true;
    }

    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < size; ++i) {
        c = table[(c ^ data[i]) & 0xFFu] ^ (c >> 8u);
    }
    return c ^ 0xFFFFFFFFu;
}

bool zEmbeddedPayload::readEmbeddedPayloadFromHostSo(
    const std::string& host_so_path,
    std::vector<uint8_t>& out_payload,
    zEmbeddedPayloadReadStatus* out_status
) {
    out_payload.clear();
    if (out_status != nullptr) {
        *out_status = zEmbeddedPayloadReadStatus::kInvalid;
    }

    std::vector<uint8_t> host_bytes;
    if (!readFileBytes(host_so_path, host_bytes)) {
        LOGE("readEmbeddedPayloadFromHostSo failed to read file: %s", host_so_path.c_str());
        return false;
    }

    if (host_bytes.size() < sizeof(EmbeddedPayloadFooter)) {
        if (out_status != nullptr) {
            *out_status = zEmbeddedPayloadReadStatus::kNotFound;
        }
        return true;
    }

    EmbeddedPayloadFooter footer{};
    const size_t footer_offset = host_bytes.size() - sizeof(EmbeddedPayloadFooter);
    if (!readPodAt(host_bytes, footer_offset, footer)) {
        LOGE("readEmbeddedPayloadFromHostSo failed to read footer");
        return false;
    }

    if (footer.magic != kFooterMagic || footer.version != kFooterVersion) {
        if (out_status != nullptr) {
            *out_status = zEmbeddedPayloadReadStatus::kNotFound;
        }
        return true;
    }

    if (footer.payload_size == 0 ||
        footer.payload_size > host_bytes.size() - sizeof(EmbeddedPayloadFooter)) {
        LOGE("readEmbeddedPayloadFromHostSo invalid payload_size=%llu",
             static_cast<unsigned long long>(footer.payload_size));
        if (out_status != nullptr) {
            *out_status = zEmbeddedPayloadReadStatus::kInvalid;
        }
        return false;
    }

    const size_t payload_begin = host_bytes.size() -
                                 sizeof(EmbeddedPayloadFooter) -
                                 static_cast<size_t>(footer.payload_size);
    const size_t payload_size = static_cast<size_t>(footer.payload_size);
    const uint32_t actual_crc = crc32(host_bytes.data() + payload_begin, payload_size);
    if (actual_crc != footer.payload_crc32) {
        LOGE("readEmbeddedPayloadFromHostSo crc mismatch expected=0x%x actual=0x%x",
             footer.payload_crc32,
             actual_crc);
        if (out_status != nullptr) {
            *out_status = zEmbeddedPayloadReadStatus::kInvalid;
        }
        return false;
    }

    out_payload.resize(payload_size);
    std::memcpy(out_payload.data(), host_bytes.data() + payload_begin, payload_size);
    if (out_status != nullptr) {
        *out_status = zEmbeddedPayloadReadStatus::kOk;
    }
    return true;
}

