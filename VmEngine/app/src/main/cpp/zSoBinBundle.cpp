/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - 运行时 expand so 尾部 bundle 读取器。
 * - 加固链路位置：route4 payload 加载。
 * - 输入：expand so 路径。
 * - 输出：函数 payload 列表与共享 branch 地址。
 */
#include "zSoBinBundle.h"

#include "zFileBytes.h"
#include "zLog.h"

#include <cstring>
#include <unordered_set>

namespace {

// 按字节对齐写入，确保 header/footer 与写入端结构严格一致。
#pragma pack(push, 1)
struct SoBinBundleHeader {
    // 头部魔数（'VMBH'）。
    uint32_t magic;
    // 协议版本。
    uint32_t version;
    // 函数载荷数量。
    uint32_t payload_count;
    // 共享 branch 地址数量。
    uint32_t branch_addr_count;
};

struct SoBinBundleEntry {
    // 函数地址标识。
    uint64_t fun_addr;
    uint64_t data_offset; // 相对 bundle 起始地址。
    // 函数编码数据长度。
    uint64_t data_size;
};

struct SoBinBundleFooter {
    // 尾部魔数（'VMBF'）。
    uint32_t magic;
    // 协议版本。
    uint32_t version;
    uint64_t bundle_size; // 从 header 到 footer（含 footer）的总长度。
};
#pragma pack(pop)

// 头部标识。
constexpr uint32_t kSoBinBundleHeaderMagic = 0x48424D56; // 'VMBH'
// 尾部标识。
constexpr uint32_t kSoBinBundleFooterMagic = 0x46424D56; // 'VMBF'
// 当前支持的 bundle 版本。
constexpr uint32_t kSoBinBundleVersion = 1;

} // namespace

namespace {

// 解析 expand so 字节中的 bundle。
bool parseExpandedSoBundleBytes(
    const std::vector<uint8_t>& fileBytes,
    const char* sourceTag,
    std::vector<zSoBinEntry>& outEntries,
    std::vector<uint64_t>& outSharedBranchAddrs
) {
    // 文件至少要容纳一个 footer。
    if (fileBytes.size() < sizeof(SoBinBundleFooter)) {
        LOGE("readFromExpandedSo file too small: %s", sourceTag);
        return false;
    }

    // 从文件尾部解析 footer。
    SoBinBundleFooter footer{};
    const size_t footerOffset = fileBytes.size() - sizeof(SoBinBundleFooter);
    if (!zFileBytes::readPodAt(fileBytes, footerOffset, footer)) {
        LOGE("readFromExpandedSo failed to read footer");
        return false;
    }
    // 校验尾部魔数与版本。
    if (footer.magic != kSoBinBundleFooterMagic || footer.version != kSoBinBundleVersion) {
        LOGE("readFromExpandedSo invalid footer magic/version");
        return false;
    }

    // bundle 最小长度必须覆盖 header + footer。
    const uint64_t minBundleSize =
        static_cast<uint64_t>(sizeof(SoBinBundleHeader) + sizeof(SoBinBundleFooter));
    // 长度非法（过小或越界）直接拒绝。
    if (footer.bundle_size < minBundleSize || footer.bundle_size > fileBytes.size()) {
        LOGE("readFromExpandedSo invalid bundle_size=%llu",
             static_cast<unsigned long long>(footer.bundle_size));
        return false;
    }

    // 根据 bundle_size 反推出 header 起始位置。
    const size_t bundleStart = fileBytes.size() - static_cast<size_t>(footer.bundle_size);
    SoBinBundleHeader header{};
    // 读取头部。
    if (!zFileBytes::readPodAt(fileBytes, bundleStart, header)) {
        LOGE("readFromExpandedSo failed to read header");
        return false;
    }
    // 校验头部魔数与版本。
    if (header.magic != kSoBinBundleHeaderMagic || header.version != kSoBinBundleVersion) {
        LOGE("readFromExpandedSo invalid header magic/version");
        return false;
    }

    // 计算 header + entry 表 + branch 表 + footer 的最小前缀长度。
    const uint64_t requiredPrefix =
        static_cast<uint64_t>(sizeof(SoBinBundleHeader)) +
        static_cast<uint64_t>(header.payload_count) * sizeof(SoBinBundleEntry) +
        static_cast<uint64_t>(header.branch_addr_count) * sizeof(uint64_t) +
        sizeof(SoBinBundleFooter);
    // 最小前缀都超出 bundle_size，说明表项计数异常。
    if (requiredPrefix > footer.bundle_size) {
        LOGE("readFromExpandedSo invalid payload_count=%u", header.payload_count);
        return false;
    }

    // 用于检测 fun_addr 是否重复。
    std::unordered_set<uint64_t> seenFunAddrs;
    // 预留输出容量，减少扩容开销。
    outEntries.reserve(header.payload_count);

    // entry 表起点（紧跟 header）。
    const size_t entryTableOffset = bundleStart + sizeof(SoBinBundleHeader);
    // branch 地址表起点（紧跟 entry 表）。
    const size_t branchAddrTableOffset =
        entryTableOffset + static_cast<size_t>(header.payload_count) * sizeof(SoBinBundleEntry);
    // 载荷数据区最小起点（紧跟 branch 地址表）。
    const uint64_t payloadDataBeginMin =
        static_cast<uint64_t>(branchAddrTableOffset) +
        static_cast<uint64_t>(header.branch_addr_count) * sizeof(uint64_t);
    // 载荷数据区上界（不含 footer）。
    const uint64_t payloadDataEnd =
        static_cast<uint64_t>(bundleStart) + footer.bundle_size - sizeof(SoBinBundleFooter);

    // 预留共享 branch 地址输出容量。
    outSharedBranchAddrs.reserve(header.branch_addr_count);
    // 读取共享 branch 地址表。
    for (uint32_t i = 0; i < header.branch_addr_count; ++i) {
        uint64_t branchAddr = 0;
        const size_t branchAddrOffset = branchAddrTableOffset + static_cast<size_t>(i) * sizeof(uint64_t);
        if (!zFileBytes::readPodAt(fileBytes, branchAddrOffset, branchAddr)) {
            LOGE("readFromExpandedSo failed to read branch_addr index=%u", i);
            return false;
        }
        outSharedBranchAddrs.push_back(branchAddr);
    }

    // 逐条读取函数 entry 并拷贝对应 payload 数据。
    for (uint32_t i = 0; i < header.payload_count; ++i) {
        SoBinBundleEntry rawEntry{};
        const size_t entryOffset = entryTableOffset + static_cast<size_t>(i) * sizeof(SoBinBundleEntry);
        if (!zFileBytes::readPodAt(fileBytes, entryOffset, rawEntry)) {
            LOGE("readFromExpandedSo failed to read entry index=%u", i);
            return false;
        }
        if (rawEntry.fun_addr == 0 || rawEntry.data_size == 0) {
            LOGE("readFromExpandedSo invalid entry index=%u", i);
            return false;
        }
        // fun_addr 必须唯一。
        if (!seenFunAddrs.insert(rawEntry.fun_addr).second) {
            LOGE("readFromExpandedSo duplicated fun_addr=0x%llx",
                 static_cast<unsigned long long>(rawEntry.fun_addr));
            return false;
        }

        // 把相对偏移换算成文件绝对偏移区间。
        const uint64_t absDataBegin = static_cast<uint64_t>(bundleStart) + rawEntry.data_offset;
        const uint64_t absDataEnd = absDataBegin + rawEntry.data_size;
        // 校验区间必须落在 payload 数据区内。
        if (absDataBegin < payloadDataBeginMin ||
            absDataEnd > payloadDataEnd ||
            absDataBegin >= absDataEnd) {
            LOGE("readFromExpandedSo out-of-range entry index=%u", i);
            return false;
        }

        zSoBinEntry entry;
        // 复制函数地址。
        entry.fun_addr = rawEntry.fun_addr;
        // 按 data_size 分配输出缓冲。
        entry.encoded_data.resize(static_cast<size_t>(rawEntry.data_size));
        // 拷贝函数编码字节。
        std::memcpy(entry.encoded_data.data(),
                    fileBytes.data() + static_cast<size_t>(absDataBegin),
                    entry.encoded_data.size());
        // 写入输出列表。
        outEntries.push_back(std::move(entry));
    }

    LOGI("readFromExpandedSo success: source=%s payload_count=%zu branch_addr_count=%zu",
         sourceTag,
         outEntries.size(),
         outSharedBranchAddrs.size());
    return true;
}

} // namespace

bool zSoBinBundleReader::readFromExpandedSo(
    const std::string& so_path,
    std::vector<zSoBinEntry>& out_entries,
    std::vector<uint64_t>& out_shared_branch_addrs
) {
    // 先清空输出，避免失败时残留旧数据。
    out_entries.clear();
    out_shared_branch_addrs.clear();

    // 读取整个 so 文件到内存。
    std::vector<uint8_t> file_bytes;
    if (!zFileBytes::readFileBytes(so_path, file_bytes)) {
        LOGE("readFromExpandedSo failed to read file: %s", so_path.c_str());
        return false;
    }
    return parseExpandedSoBundleBytes(file_bytes,
                                      so_path.c_str(),
                                      out_entries,
                                      out_shared_branch_addrs);
}

bool zSoBinBundleReader::readFromExpandedSoBytes(
    const uint8_t* soBytes,
    size_t soSize,
    std::vector<zSoBinEntry>& outEntries,
    std::vector<uint64_t>& outSharedBranchAddrs
) {
    // 先清空输出，避免失败时残留旧数据。
    outEntries.clear();
    outSharedBranchAddrs.clear();

    // 入参校验：内存地址和大小必须有效。
    if (soBytes == nullptr || soSize == 0) {
        LOGE("readFromExpandedSoBytes invalid input bytes");
        return false;
    }

    // 复用统一解析逻辑：拷贝到本地字节数组后按既有校验流程处理。
    std::vector<uint8_t> fileBytes(soBytes, soBytes + soSize);
    return parseExpandedSoBundleBytes(fileBytes,
                                      "<memory>",
                                      outEntries,
                                      outSharedBranchAddrs);
}
