// 引入 CRC 接口声明。
#include "zChecksum.h"

// 进入基础校验和命名空间。
namespace vmp::base::checksum {

// 内部实现命名空间（仅当前编译单元可见）。
namespace {

// 返回 CRC32 查找表指针（懒初始化）。
const uint32_t* crc32Table() {
    // CRC32 查表缓存。
    static uint32_t table[256];
    // 是否已初始化标记。
    static bool inited = false;
    // 首次调用时构建查找表。
    if (!inited) {
        // 逐个字节值构建 256 项。
        for (uint32_t tableIndex = 0; tableIndex < 256; ++tableIndex) {
            // 当前项临时寄存器。
            uint32_t crcState = tableIndex;
            // 每项执行 8 轮多项式迭代。
            for (int bitRound = 0; bitRound < 8; ++bitRound) {
                crcState = (crcState & 1u) ? (0xEDB88320u ^ (crcState >> 1u)) : (crcState >> 1u);
            }
            // 回填到查找表。
            table[tableIndex] = crcState;
        }
        // 标记初始化完成。
        inited = true;
    }
    // 返回查表指针。
    return table;
}

// 结束内部命名空间。
}  // namespace

// 直接计算内存块的 CRC32。
uint32_t crc32Ieee(const uint8_t* data, const size_t size) {
    // 非空长度但 data 为空视为非法输入，返回 0。
    if (data == nullptr && size > 0) {
        return 0;
    }

    // 组合流程：init -> update -> final。
    return crc32IeeeFinal(crc32IeeeUpdate(crc32IeeeInit(), data, size));
}

// 直接计算字节数组 CRC32。
uint32_t crc32Ieee(const std::vector<uint8_t>& data) {
    // 空数组走统一路径（等价空输入）。
    if (data.empty()) {
        return crc32Ieee(nullptr, 0);
    }
    // 非空时传入 data 指针和长度。
    return crc32Ieee(data.data(), data.size());
}

// 返回 CRC32 初始状态。
uint32_t crc32IeeeInit() {
    return 0xFFFFFFFFu;
}

// 基于旧状态增量更新 CRC32。
uint32_t crc32IeeeUpdate(uint32_t crc, const uint8_t* data, const size_t size) {
    // 空输入时状态不变。
    if (data == nullptr || size == 0) {
        return crc;
    }
    // 获取查找表。
    const uint32_t* table = crc32Table();
    // 复制一份工作状态。
    uint32_t crcState = crc;
    // 逐字节更新。
    for (size_t byteIndex = 0; byteIndex < size; ++byteIndex) {
        crcState = table[(crcState ^ data[byteIndex]) & 0xFFu] ^ (crcState >> 8u);
    }
    // 返回新状态。
    return crcState;
}

// 返回 CRC32 收尾值。
uint32_t crc32IeeeFinal(uint32_t crc) {
    return crc ^ 0xFFFFFFFFu;
}

// 结束命名空间。
}  // namespace vmp::base::checksum
