/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - 运行时 expand so 尾部 bundle 读取器。
 * - 加固链路位置：route3/route4 payload 加载。
 * - 输入：expand so 路径。
 * - 输出：函数 payload 列表与共享 branch 地址。
 */
#include "zSoBinBundle.h"

#include "zLog.h"

#include <cstring>
#include <fstream>
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

bool readFileBytes(const std::string& path, std::vector<uint8_t>& out) {
    // 每次读取前清空输出。
    out.clear();
    // 路径为空直接失败。
    if (path.empty()) {
        return false;
    }

    // 二进制方式打开文件。
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return false;
    }

    // 先定位到末尾获取总长度。
    in.seekg(0, std::ios::end);
    const std::streamoff size = in.tellg();
    // 获取长度失败直接返回。
    if (size < 0) {
        return false;
    }
    // 回到文件起点准备读取。
    in.seekg(0, std::ios::beg);

    // 按文件长度分配缓冲。
    out.resize(static_cast<size_t>(size));
    // 非空文件时执行读取。
    if (!out.empty()) {
        in.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()));
    }
    // 返回读取状态。
    return static_cast<bool>(in);
}

template <typename T>
bool readPodAt(const std::vector<uint8_t>& bytes, size_t offset, T& out) {
    // 校验 offset 与读取长度都在范围内。
    if (offset > bytes.size() || bytes.size() - offset < sizeof(T)) {
        return false;
    }
    // 直接按 POD 字节复制。
    std::memcpy(&out, bytes.data() + offset, sizeof(T));
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
    if (!readFileBytes(so_path, file_bytes)) {
        LOGE("readFromExpandedSo failed to read file: %s", so_path.c_str());
        return false;
    }
    // 文件至少要容纳一个 footer。
    if (file_bytes.size() < sizeof(SoBinBundleFooter)) {
        LOGE("readFromExpandedSo file too small: %s", so_path.c_str());
        return false;
    }

    // 从文件尾部解析 footer。
    SoBinBundleFooter footer{};
    const size_t footer_offset = file_bytes.size() - sizeof(SoBinBundleFooter);
    if (!readPodAt(file_bytes, footer_offset, footer)) {
        LOGE("readFromExpandedSo failed to read footer");
        return false;
    }
    // 校验尾部魔数与版本。
    if (footer.magic != kSoBinBundleFooterMagic || footer.version != kSoBinBundleVersion) {
        LOGE("readFromExpandedSo invalid footer magic/version");
        return false;
    }

    // bundle 最小长度必须覆盖 header + footer。
    const uint64_t min_bundle_size =
        static_cast<uint64_t>(sizeof(SoBinBundleHeader) + sizeof(SoBinBundleFooter));
    // 长度非法（过小或越界）直接拒绝。
    if (footer.bundle_size < min_bundle_size || footer.bundle_size > file_bytes.size()) {
        LOGE("readFromExpandedSo invalid bundle_size=%llu",
             static_cast<unsigned long long>(footer.bundle_size));
        return false;
    }

    // 根据 bundle_size 反推出 header 起始位置。
    const size_t bundle_start = file_bytes.size() - static_cast<size_t>(footer.bundle_size);
    SoBinBundleHeader header{};
    // 读取头部。
    if (!readPodAt(file_bytes, bundle_start, header)) {
        LOGE("readFromExpandedSo failed to read header");
        return false;
    }
    // 校验头部魔数与版本。
    if (header.magic != kSoBinBundleHeaderMagic || header.version != kSoBinBundleVersion) {
        LOGE("readFromExpandedSo invalid header magic/version");
        return false;
    }

    // 计算 header + entry 表 + branch 表 + footer 的最小前缀长度。
    const uint64_t required_prefix =
        static_cast<uint64_t>(sizeof(SoBinBundleHeader)) +
        static_cast<uint64_t>(header.payload_count) * sizeof(SoBinBundleEntry) +
        static_cast<uint64_t>(header.branch_addr_count) * sizeof(uint64_t) +
        sizeof(SoBinBundleFooter);
    // 最小前缀都超出 bundle_size，说明表项计数异常。
    if (required_prefix > footer.bundle_size) {
        LOGE("readFromExpandedSo invalid payload_count=%u", header.payload_count);
        return false;
    }

    // 用于检测 fun_addr 是否重复。
    std::unordered_set<uint64_t> seen_fun_addrs;
    // 预留输出容量，减少扩容开销。
    out_entries.reserve(header.payload_count);

    // entry 表起点（紧跟 header）。
    const size_t entry_table_offset = bundle_start + sizeof(SoBinBundleHeader);
    // branch 地址表起点（紧跟 entry 表）。
    const size_t branch_addr_table_offset =
        entry_table_offset + static_cast<size_t>(header.payload_count) * sizeof(SoBinBundleEntry);
    // 载荷数据区最小起点（紧跟 branch 地址表）。
    const uint64_t payload_data_begin_min =
        static_cast<uint64_t>(branch_addr_table_offset) +
        static_cast<uint64_t>(header.branch_addr_count) * sizeof(uint64_t);
    // 载荷数据区上界（不含 footer）。
    const uint64_t payload_data_end = static_cast<uint64_t>(bundle_start) + footer.bundle_size - sizeof(SoBinBundleFooter);

    // 预留共享 branch 地址输出容量。
    out_shared_branch_addrs.reserve(header.branch_addr_count);
    // 读取共享 branch 地址表。
    for (uint32_t i = 0; i < header.branch_addr_count; ++i) {
        uint64_t branch_addr = 0;
        const size_t branch_addr_offset = branch_addr_table_offset + static_cast<size_t>(i) * sizeof(uint64_t);
        if (!readPodAt(file_bytes, branch_addr_offset, branch_addr)) {
            LOGE("readFromExpandedSo failed to read branch_addr index=%u", i);
            return false;
        }
        out_shared_branch_addrs.push_back(branch_addr);
    }

    // 逐条读取函数 entry 并拷贝对应 payload 数据。
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
        // fun_addr 必须唯一。
        if (!seen_fun_addrs.insert(raw_entry.fun_addr).second) {
            LOGE("readFromExpandedSo duplicated fun_addr=0x%llx",
                 static_cast<unsigned long long>(raw_entry.fun_addr));
            return false;
        }

        // 把相对偏移换算成文件绝对偏移区间。
        const uint64_t abs_data_begin = static_cast<uint64_t>(bundle_start) + raw_entry.data_offset;
        const uint64_t abs_data_end = abs_data_begin + raw_entry.data_size;
        // 校验区间必须落在 payload 数据区内。
        if (abs_data_begin < payload_data_begin_min ||
            abs_data_end > payload_data_end ||
            abs_data_begin >= abs_data_end) {
            LOGE("readFromExpandedSo out-of-range entry index=%u", i);
            return false;
        }

        zSoBinEntry entry;
        // 复制函数地址。
        entry.fun_addr = raw_entry.fun_addr;
        // 按 data_size 分配输出缓冲。
        entry.encoded_data.resize(static_cast<size_t>(raw_entry.data_size));
        // 拷贝函数编码字节。
        std::memcpy(entry.encoded_data.data(), file_bytes.data() + static_cast<size_t>(abs_data_begin), entry.encoded_data.size());
        // 写入输出列表。
        out_entries.push_back(std::move(entry));
    }

    LOGI("readFromExpandedSo success: path=%s payload_count=%zu branch_addr_count=%zu",
         so_path.c_str(),
         out_entries.size(),
         out_shared_branch_addrs.size());
    return true;
}
