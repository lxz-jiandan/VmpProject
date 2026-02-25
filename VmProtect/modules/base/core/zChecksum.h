// 防止头文件重复包含。
#pragma once

// 引入 size_t 定义。
#include <cstddef>
// 引入固定宽度整数定义。
#include <cstdint>
// 引入字节数组容器。
#include <vector>

// 基础层校验和工具命名空间。
namespace vmp::base::checksum {

// 返回 CRC32-IEEE 初始值。
uint32_t crc32IeeeInit();
// 用一段数据更新 CRC 状态。
uint32_t crc32IeeeUpdate(uint32_t crc, const uint8_t* data, size_t size);
// 返回 CRC32-IEEE 结束值。
uint32_t crc32IeeeFinal(uint32_t crc);

// 便捷接口：直接计算一段内存的 CRC32-IEEE。
uint32_t crc32Ieee(const uint8_t* data, size_t size);
// 便捷接口：直接计算字节数组的 CRC32-IEEE。
uint32_t crc32Ieee(const std::vector<uint8_t>& data);

// 结束命名空间。
}  // namespace vmp::base::checksum
