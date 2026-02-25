#include "zPatchbayCrc.h"

// 引入区域校验工具。
#include "zBytes.h"
// 引入 CRC32 算法实现。
#include "zChecksum.h"

// 引入 offsetof。
#include <cstddef>
// 引入 memcpy/memset。
#include <cstring>

// 根据数量构建低位 bitmask。
uint64_t bitmaskForCountU32(uint32_t count) {
    // 0 个槽位时位图为空。
    if (count == 0) {
        return 0ULL;
    }
    // >=64 时整个位图全 1。
    if (count >= 64U) {
        return ~0ULL;
    }
    // 低 count 位为 1，其余位为 0。
    return (1ULL << count) - 1ULL;
}

// 基于完整文件字节和 patchbay 头计算 CRC32。
bool computePatchbayCrcFromFile(const std::vector<uint8_t>& fileBytes,
                                uint64_t patchbayOffset,
                                const PatchBayHeader& header,
                                uint32_t* outCrc,
                                std::string* error) {
    // 调用方必须提供输出指针。
    if (outCrc == nullptr) {
        if (error != nullptr) {
            *error = "crc output pointer is null";
        }
        return false;
    }

    // 基础边界校验：header 结构必须完整且总大小不能越界。
    if (header.headerSize < sizeof(PatchBayHeader) ||
        header.totalSize < header.headerSize ||
        patchbayOffset > fileBytes.size() ||
        header.totalSize > fileBytes.size() - static_cast<size_t>(patchbayOffset)) {
        if (error != nullptr) {
            *error = "patchbay header/section bounds invalid for crc";
        }
        return false;
    }

    // headerSize 至少要覆盖 crc32 字段位置。
    if (offsetof(PatchBayHeader, crc32) + sizeof(uint32_t) > header.headerSize) {
        if (error != nullptr) {
            *error = "patchbay header too small for crc field";
        }
        return false;
    }

    // 拷贝一份 header 原始字节，避免修改输入文件字节。
    std::vector<uint8_t> headerBlob(static_cast<size_t>(header.headerSize), 0);
    std::memcpy(headerBlob.data(), fileBytes.data() + patchbayOffset, headerBlob.size());
    // 按协议要求：crc 字段本身参与计算时需要先清零。
    std::memset(headerBlob.data() + offsetof(PatchBayHeader, crc32), 0, sizeof(uint32_t));

    // 统一检查每个子区域（off/cap/used）是否位于 patchbay 区间内。
    std::string regionError;
    if (!vmp::base::bytes::validateUsedRegion(header.headerSize,
                                              header.totalSize,
                                              header.dynsymOffset,
                                              header.dynsymCapacity,
                                              header.usedDynsym,
                                              "dynsym",
                                              &regionError) ||
        !vmp::base::bytes::validateUsedRegion(header.headerSize,
                                              header.totalSize,
                                              header.dynstrOffset,
                                              header.dynstrCapacity,
                                              header.usedDynstr,
                                              "dynstr",
                                              &regionError) ||
        !vmp::base::bytes::validateUsedRegion(header.headerSize,
                                              header.totalSize,
                                              header.gnuHashOffset,
                                              header.gnuHashCapacity,
                                              header.usedGnuHash,
                                              "gnuhash",
                                              &regionError) ||
        !vmp::base::bytes::validateUsedRegion(header.headerSize,
                                              header.totalSize,
                                              header.sysvHashOffset,
                                              header.sysvHashCapacity,
                                              header.usedSysvHash,
                                              "sysvhash",
                                              &regionError) ||
        !vmp::base::bytes::validateUsedRegion(header.headerSize,
                                              header.totalSize,
                                              header.versymOffset,
                                              header.versymCapacity,
                                              header.usedVersym,
                                              "versym",
                                              &regionError)) {
        if (error != nullptr) {
            *error = "patchbay region invalid for crc: " + regionError;
        }
        return false;
    }

    // 初始化 CRC 累计器。
    uint32_t crc = vmp::base::checksum::crc32IeeeInit();
    // 先累计 header（crc 字段已清零）。
    crc = vmp::base::checksum::crc32IeeeUpdate(crc, headerBlob.data(), headerBlob.size());

    // 定义局部工具：累加某个“已使用子区域”的 CRC。
    auto updateUsedRegion = [&crc, &fileBytes, patchbayOffset](uint32_t off, uint32_t used) {
        // 空区域不参与累计。
        if (used == 0) {
            return;
        }
        // 计算该区域在整文件内的绝对偏移。
        const size_t absOffset = static_cast<size_t>(patchbayOffset + off);
        // 累加该区域的 used 字节。
        crc = vmp::base::checksum::crc32IeeeUpdate(crc, fileBytes.data() + absOffset, used);
    };

    // 按固定顺序累计 dynsym。
    updateUsedRegion(header.dynsymOffset, header.usedDynsym);
    // 按固定顺序累计 dynstr。
    updateUsedRegion(header.dynstrOffset, header.usedDynstr);
    // 按固定顺序累计 gnu hash。
    updateUsedRegion(header.gnuHashOffset, header.usedGnuHash);
    // 按固定顺序累计 sysv hash。
    updateUsedRegion(header.sysvHashOffset, header.usedSysvHash);
    // 按固定顺序累计 versym。
    updateUsedRegion(header.versymOffset, header.usedVersym);

    // 收尾得到最终 CRC 值。
    *outCrc = vmp::base::checksum::crc32IeeeFinal(crc);
    return true;
}

