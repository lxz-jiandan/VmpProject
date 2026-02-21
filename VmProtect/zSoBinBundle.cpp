#include "zSoBinBundle.h"

#include "zLog.h"

#include <cstring>        // std::memcpy。
#include <fstream>        // std::ifstream / std::ofstream。
#include <unordered_set>  // fun_addr 去重校验。

namespace {

// 强制 1 字节对齐，确保写入布局与读取端定义一致。
#pragma pack(push, 1)
struct SoBinBundleHeader {
    // 头部魔数（'VMBH'）。
    uint32_t magic;
    // 协议版本。
    uint32_t version;
    // 函数 payload 数量。
    uint32_t payload_count;
    // 共享 branch 地址数量。
    uint32_t branch_addr_count;
};

struct SoBinBundleEntry {
    // 函数地址主键。
    uint64_t fun_addr;
    // payload 数据偏移（相对 bundle 起始地址）。
    uint64_t data_offset;
    // payload 字节长度。
    uint64_t data_size;
};

struct SoBinBundleFooter {
    // 尾部魔数（'VMBF'）。
    uint32_t magic;
    // 协议版本。
    uint32_t version;
    // bundle 总长度（从 header 到 footer，且包含 footer）。
    uint64_t bundle_size;
};
#pragma pack(pop)

// 固定头部魔数。
constexpr uint32_t kSoBinBundleHeaderMagic = 0x48424D56; // 'VMBH'
// 固定尾部魔数。
constexpr uint32_t kSoBinBundleFooterMagic = 0x46424D56; // 'VMBF'
// 当前协议版本。
constexpr uint32_t kSoBinBundleVersion = 1;

bool readFileBytes(const char* path, std::vector<uint8_t>& out) {
    // 清空输出缓冲。
    out.clear();
    // 路径为空直接失败。
    if (!path || path[0] == '\0') {
        return false;
    }

    // 二进制方式打开输入文件。
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return false;
    }

    // 先定位末尾获取长度。
    in.seekg(0, std::ios::end);
    const std::streamoff size = in.tellg();
    // 获取失败直接返回。
    if (size < 0) {
        return false;
    }
    // 回到起点读取全部内容。
    in.seekg(0, std::ios::beg);

    // 按文件长度分配缓冲。
    out.resize(static_cast<size_t>(size));
    // 非空内容才执行 read。
    if (!out.empty()) {
        in.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()));
    }
    // 返回读流状态：读取不足或 I/O 错误会返回 false。
    return static_cast<bool>(in);
}

bool writeFileBytes(const char* path, const std::vector<uint8_t>& bytes) {
    // 输出路径为空直接失败。
    if (!path || path[0] == '\0') {
        return false;
    }

    // 二进制 + 截断方式写出最终文件。
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        return false;
    }

    // 有内容时写入字节流。
    if (!bytes.empty()) {
        out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    }
    // 返回写流状态：写盘失败会返回 false。
    return static_cast<bool>(out);
}

template <typename T>
void appendPod(std::vector<uint8_t>& out, const T& pod) {
    // 记录追加前长度。
    const size_t old_size = out.size();
    // 扩容容纳一个 POD。
    out.resize(old_size + sizeof(T));
    // 直接按字节复制到尾部（要求 T 为稳定布局 POD）。
    std::memcpy(out.data() + old_size, &pod, sizeof(T));
}

} // namespace

bool zSoBinBundleWriter::writeExpandedSo(
    const char* input_so_path,
    const char* output_so_path,
    const std::vector<zSoBinPayload>& payloads,
    const std::vector<uint64_t>& shared_branch_addrs
) {
    // 输入输出路径都必须有效。
    if (!input_so_path || input_so_path[0] == '\0' || !output_so_path || output_so_path[0] == '\0') {
        LOGE("writeExpandedSo invalid path");
        return false;
    }
    // 至少需要一个 payload。
    if (payloads.empty()) {
        LOGE("writeExpandedSo payloads is empty");
        return false;
    }

    // 读取基础 so 字节。
    std::vector<uint8_t> so_bytes;
    if (!readFileBytes(input_so_path, so_bytes)) {
        LOGE("read input so failed: %s", input_so_path);
        return false;
    }

    // 用于校验 fun_addr 唯一性。
    std::unordered_set<uint64_t> unique_fun_addrs;
    // 暂存每个 payload 对应 entry。
    std::vector<SoBinBundleEntry> entries;
    entries.reserve(payloads.size());

    // bundle 前缀长度：
    // header + entry 表 + 全局共享 branch 地址表。
    const uint64_t prefix_size =
        static_cast<uint64_t>(sizeof(SoBinBundleHeader)) +
        static_cast<uint64_t>(payloads.size() * sizeof(SoBinBundleEntry)) +
        static_cast<uint64_t>(shared_branch_addrs.size() * sizeof(uint64_t));
    // data_cursor 指向当前 payload 写入位置（相对 bundle 起点）。
    uint64_t data_cursor = prefix_size;
    // 遍历 payload 生成 entry，并累计 data_cursor。
    for (const zSoBinPayload& payload : payloads) {
        // fun_addr 不能为空。
        if (payload.fun_addr == 0) {
            LOGE("writeExpandedSo found payload with fun_addr=0");
            return false;
        }
        // 编码内容不能为空。
        if (payload.encoded_bytes.empty()) {
            LOGE("writeExpandedSo found empty payload for fun_addr=0x%llx",
                 static_cast<unsigned long long>(payload.fun_addr));
            return false;
        }
        // fun_addr 必须唯一。
        if (!unique_fun_addrs.insert(payload.fun_addr).second) {
            LOGE("writeExpandedSo found duplicated fun_addr=0x%llx",
                 static_cast<unsigned long long>(payload.fun_addr));
            return false;
        }

        // 填充 entry 元信息。
        SoBinBundleEntry entry{};
        entry.fun_addr = payload.fun_addr;
        entry.data_offset = data_cursor;
        entry.data_size = static_cast<uint64_t>(payload.encoded_bytes.size());
        // 追加到 entry 列表（顺序与 payload 写入顺序一致）。
        entries.push_back(entry);
        // 游标前移到下一个 payload 起点。
        data_cursor += entry.data_size;
    }

    // 所有 payload 字节总长度（仅数据区，不含头尾与索引区）。
    const uint64_t payload_bytes_size = data_cursor - prefix_size;
    // bundle 总长度（含 footer）。
    const uint64_t bundle_size_u64 = prefix_size + payload_bytes_size + static_cast<uint64_t>(sizeof(SoBinBundleFooter));

    // 组装 header：供 Engine 从 so 尾部解析时识别 bundle。
    SoBinBundleHeader header{};
    header.magic = kSoBinBundleHeaderMagic;
    header.version = kSoBinBundleVersion;
    header.payload_count = static_cast<uint32_t>(entries.size());
    header.branch_addr_count = static_cast<uint32_t>(shared_branch_addrs.size());

    // 组装 footer：记录 bundle 总长度，便于从 so 尾部反向定位。
    SoBinBundleFooter footer{};
    footer.magic = kSoBinBundleFooterMagic;
    footer.version = kSoBinBundleVersion;
    footer.bundle_size = bundle_size_u64;

    // 最终输出字节布局：原始 so + bundle。
    std::vector<uint8_t> out_bytes;
    // 提前 reserve，减少重复扩容。
    out_bytes.reserve(
        so_bytes.size() +
        static_cast<size_t>(bundle_size_u64)
    );
    // 先写入原始 so。
    out_bytes.insert(out_bytes.end(), so_bytes.begin(), so_bytes.end());
    // 写入 header。
    appendPod(out_bytes, header);
    // 写入 entry 表。
    for (const SoBinBundleEntry& entry : entries) {
        appendPod(out_bytes, entry);
    }
    // 写入共享 branch 地址表（所有函数共享同一份）。
    for (uint64_t addr : shared_branch_addrs) {
        appendPod(out_bytes, addr);
    }
    // 依次写入各函数 payload 字节。
    for (const zSoBinPayload& payload : payloads) {
        out_bytes.insert(out_bytes.end(), payload.encoded_bytes.begin(), payload.encoded_bytes.end());
    }
    // 最后写入 footer。
    appendPod(out_bytes, footer);

    // 落盘输出 expanded so。
    if (!writeFileBytes(output_so_path, out_bytes)) {
        LOGE("write output so failed: %s", output_so_path);
        return false;
    }

    // 成功路径输出统计信息，便于回归核对。
    LOGI("writeExpandedSo success: input=%s output=%s payload_count=%u branch_addr_count=%u",
         input_so_path,
         output_so_path,
         static_cast<unsigned int>(entries.size()),
         static_cast<unsigned int>(shared_branch_addrs.size()));
    return true;
}
