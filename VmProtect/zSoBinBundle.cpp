#include "zSoBinBundle.h"

#include "zLog.h"

#include <cstring>
#include <fstream>
#include <unordered_set>

namespace {

#pragma pack(push, 1)
struct SoBinBundleHeader {
    uint32_t magic;
    uint32_t version;
    uint32_t payload_count;
    uint32_t branch_addr_count;
};

struct SoBinBundleEntry {
    uint64_t fun_addr;
    uint64_t data_offset; // 相对 bundle 起始地址
    uint64_t data_size;
};

struct SoBinBundleFooter {
    uint32_t magic;
    uint32_t version;
    uint64_t bundle_size; // 从 header 到 footer（含 footer）的总长度
};
#pragma pack(pop)

constexpr uint32_t kSoBinBundleHeaderMagic = 0x48424D56; // 'VMBH'
constexpr uint32_t kSoBinBundleFooterMagic = 0x46424D56; // 'VMBF'
constexpr uint32_t kSoBinBundleVersion = 1;

bool readFileBytes(const char* path, std::vector<uint8_t>& out) {
    out.clear();
    if (!path || path[0] == '\0') {
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

bool writeFileBytes(const char* path, const std::vector<uint8_t>& bytes) {
    if (!path || path[0] == '\0') {
        return false;
    }

    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        return false;
    }

    if (!bytes.empty()) {
        out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    }
    return static_cast<bool>(out);
}

template <typename T>
void appendPod(std::vector<uint8_t>& out, const T& pod) {
    const size_t old_size = out.size();
    out.resize(old_size + sizeof(T));
    std::memcpy(out.data() + old_size, &pod, sizeof(T));
}

} // namespace

bool zSoBinBundleWriter::writeExpandedSo(
    const char* input_so_path,
    const char* output_so_path,
    const std::vector<zSoBinPayload>& payloads,
    const std::vector<uint64_t>& shared_branch_addrs
) {
    if (!input_so_path || input_so_path[0] == '\0' || !output_so_path || output_so_path[0] == '\0') {
        LOGE("writeExpandedSo invalid path");
        return false;
    }
    if (payloads.empty()) {
        LOGE("writeExpandedSo payloads is empty");
        return false;
    }

    std::vector<uint8_t> so_bytes;
    if (!readFileBytes(input_so_path, so_bytes)) {
        LOGE("read input so failed: %s", input_so_path);
        return false;
    }

    std::unordered_set<uint64_t> unique_fun_addrs;
    std::vector<SoBinBundleEntry> entries;
    entries.reserve(payloads.size());

    const uint64_t prefix_size =
        static_cast<uint64_t>(sizeof(SoBinBundleHeader)) +
        static_cast<uint64_t>(payloads.size() * sizeof(SoBinBundleEntry)) +
        static_cast<uint64_t>(shared_branch_addrs.size() * sizeof(uint64_t));
    uint64_t data_cursor = prefix_size;
    for (const zSoBinPayload& payload : payloads) {
        if (payload.fun_addr == 0) {
            LOGE("writeExpandedSo found payload with fun_addr=0");
            return false;
        }
        if (payload.encoded_bytes.empty()) {
            LOGE("writeExpandedSo found empty payload for fun_addr=0x%llx",
                 static_cast<unsigned long long>(payload.fun_addr));
            return false;
        }
        if (!unique_fun_addrs.insert(payload.fun_addr).second) {
            LOGE("writeExpandedSo found duplicated fun_addr=0x%llx",
                 static_cast<unsigned long long>(payload.fun_addr));
            return false;
        }

        SoBinBundleEntry entry{};
        entry.fun_addr = payload.fun_addr;
        entry.data_offset = data_cursor;
        entry.data_size = static_cast<uint64_t>(payload.encoded_bytes.size());
        entries.push_back(entry);
        data_cursor += entry.data_size;
    }

    const uint64_t payload_bytes_size = data_cursor - prefix_size;
    const uint64_t bundle_size_u64 = prefix_size + payload_bytes_size + static_cast<uint64_t>(sizeof(SoBinBundleFooter));

    SoBinBundleHeader header{};
    header.magic = kSoBinBundleHeaderMagic;
    header.version = kSoBinBundleVersion;
    header.payload_count = static_cast<uint32_t>(entries.size());
    header.branch_addr_count = static_cast<uint32_t>(shared_branch_addrs.size());

    SoBinBundleFooter footer{};
    footer.magic = kSoBinBundleFooterMagic;
    footer.version = kSoBinBundleVersion;
    footer.bundle_size = bundle_size_u64;

    std::vector<uint8_t> out_bytes;
    out_bytes.reserve(
        so_bytes.size() +
        static_cast<size_t>(bundle_size_u64)
    );
    out_bytes.insert(out_bytes.end(), so_bytes.begin(), so_bytes.end());
    appendPod(out_bytes, header);
    for (const SoBinBundleEntry& entry : entries) {
        appendPod(out_bytes, entry);
    }
    for (uint64_t addr : shared_branch_addrs) {
        appendPod(out_bytes, addr);
    }
    for (const zSoBinPayload& payload : payloads) {
        out_bytes.insert(out_bytes.end(), payload.encoded_bytes.begin(), payload.encoded_bytes.end());
    }
    appendPod(out_bytes, footer);

    if (!writeFileBytes(output_so_path, out_bytes)) {
        LOGE("write output so failed: %s", output_so_path);
        return false;
    }

    LOGI("writeExpandedSo success: input=%s output=%s payload_count=%u branch_addr_count=%u",
         input_so_path,
         output_so_path,
         static_cast<unsigned int>(entries.size()),
         static_cast<unsigned int>(shared_branch_addrs.size()));
    return true;
}
