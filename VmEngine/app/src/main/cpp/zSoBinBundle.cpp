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

bool zSoBinBundleReader::readFromExpandedSo(
    const std::string& so_path,
    std::vector<zSoBinEntry>& out_entries,
    std::vector<uint64_t>& out_shared_branch_addrs
) {
    out_entries.clear();
    out_shared_branch_addrs.clear();

    std::vector<uint8_t> file_bytes;
    if (!readFileBytes(so_path, file_bytes)) {
        LOGE("readFromExpandedSo failed to read file: %s", so_path.c_str());
        return false;
    }
    if (file_bytes.size() < sizeof(SoBinBundleFooter)) {
        LOGE("readFromExpandedSo file too small: %s", so_path.c_str());
        return false;
    }

    SoBinBundleFooter footer{};
    const size_t footer_offset = file_bytes.size() - sizeof(SoBinBundleFooter);
    if (!readPodAt(file_bytes, footer_offset, footer)) {
        LOGE("readFromExpandedSo failed to read footer");
        return false;
    }
    if (footer.magic != kSoBinBundleFooterMagic || footer.version != kSoBinBundleVersion) {
        LOGE("readFromExpandedSo invalid footer magic/version");
        return false;
    }

    const uint64_t min_bundle_size =
        static_cast<uint64_t>(sizeof(SoBinBundleHeader) + sizeof(SoBinBundleFooter));
    if (footer.bundle_size < min_bundle_size || footer.bundle_size > file_bytes.size()) {
        LOGE("readFromExpandedSo invalid bundle_size=%llu",
             static_cast<unsigned long long>(footer.bundle_size));
        return false;
    }

    const size_t bundle_start = file_bytes.size() - static_cast<size_t>(footer.bundle_size);
    SoBinBundleHeader header{};
    if (!readPodAt(file_bytes, bundle_start, header)) {
        LOGE("readFromExpandedSo failed to read header");
        return false;
    }
    if (header.magic != kSoBinBundleHeaderMagic || header.version != kSoBinBundleVersion) {
        LOGE("readFromExpandedSo invalid header magic/version");
        return false;
    }

    const uint64_t required_prefix =
        static_cast<uint64_t>(sizeof(SoBinBundleHeader)) +
        static_cast<uint64_t>(header.payload_count) * sizeof(SoBinBundleEntry) +
        static_cast<uint64_t>(header.branch_addr_count) * sizeof(uint64_t) +
        sizeof(SoBinBundleFooter);
    if (required_prefix > footer.bundle_size) {
        LOGE("readFromExpandedSo invalid payload_count=%u", header.payload_count);
        return false;
    }

    std::unordered_set<uint64_t> seen_fun_addrs;
    out_entries.reserve(header.payload_count);

    const size_t entry_table_offset = bundle_start + sizeof(SoBinBundleHeader);
    const size_t branch_addr_table_offset =
        entry_table_offset + static_cast<size_t>(header.payload_count) * sizeof(SoBinBundleEntry);
    const uint64_t payload_data_begin_min =
        static_cast<uint64_t>(branch_addr_table_offset) +
        static_cast<uint64_t>(header.branch_addr_count) * sizeof(uint64_t);
    const uint64_t payload_data_end = static_cast<uint64_t>(bundle_start) + footer.bundle_size - sizeof(SoBinBundleFooter);

    out_shared_branch_addrs.reserve(header.branch_addr_count);
    for (uint32_t i = 0; i < header.branch_addr_count; ++i) {
        uint64_t branch_addr = 0;
        const size_t branch_addr_offset = branch_addr_table_offset + static_cast<size_t>(i) * sizeof(uint64_t);
        if (!readPodAt(file_bytes, branch_addr_offset, branch_addr)) {
            LOGE("readFromExpandedSo failed to read branch_addr index=%u", i);
            return false;
        }
        out_shared_branch_addrs.push_back(branch_addr);
    }

    for (uint32_t i = 0; i < header.payload_count; ++i) {
        SoBinBundleEntry raw_entry{};
        const size_t entry_offset = entry_table_offset + static_cast<size_t>(i) * sizeof(SoBinBundleEntry);
        if (!readPodAt(file_bytes, entry_offset, raw_entry)) {
            LOGE("readFromExpandedSo failed to read entry index=%u", i);
            return false;
        }
        if (raw_entry.fun_addr == 0 || raw_entry.data_size == 0) {
            LOGE("readFromExpandedSo invalid entry index=%u", i);
            return false;
        }
        if (!seen_fun_addrs.insert(raw_entry.fun_addr).second) {
            LOGE("readFromExpandedSo duplicated fun_addr=0x%llx",
                 static_cast<unsigned long long>(raw_entry.fun_addr));
            return false;
        }

        const uint64_t abs_data_begin = static_cast<uint64_t>(bundle_start) + raw_entry.data_offset;
        const uint64_t abs_data_end = abs_data_begin + raw_entry.data_size;
        if (abs_data_begin < payload_data_begin_min ||
            abs_data_end > payload_data_end ||
            abs_data_begin >= abs_data_end) {
            LOGE("readFromExpandedSo out-of-range entry index=%u", i);
            return false;
        }

        zSoBinEntry entry;
        entry.fun_addr = raw_entry.fun_addr;
        entry.encoded_data.resize(static_cast<size_t>(raw_entry.data_size));
        std::memcpy(entry.encoded_data.data(), file_bytes.data() + static_cast<size_t>(abs_data_begin), entry.encoded_data.size());
        out_entries.push_back(std::move(entry));
    }

    LOGI("readFromExpandedSo success: path=%s payload_count=%zu branch_addr_count=%zu",
         so_path.c_str(),
         out_entries.size(),
         out_shared_branch_addrs.size());
    return true;
}
