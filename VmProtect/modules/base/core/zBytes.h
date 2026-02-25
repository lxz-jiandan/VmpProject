// 防止头文件重复包含。
#pragma once

// 引入固定宽度整数类型。
#include <cstdint>
// 引入字符串类型。
#include <string>
// 引入字节数组容器。
#include <vector>

// 基础层字节区间与写入工具命名空间。
namespace vmp::base::bytes {

// 校验一个“可为空区域”是否在合法范围内。
// 语义：当 cap==0 时允许直接通过。
bool validateRegionAllowEmpty(uint32_t headerSize,
                              uint32_t totalSize,
                              uint32_t off,
                              uint32_t cap,
                              const char* name,
                              std::string* error);

// 校验“已使用区域”是否合法。
// 语义：used 必须 <= cap，且 [off, off+cap) 在总范围内。
bool validateUsedRegion(uint32_t headerSize,
                        uint32_t totalSize,
                        uint32_t off,
                        uint32_t cap,
                        uint32_t used,
                        const char* name,
                        std::string* error);

// 将 payload 写入目标区域，并把剩余空间补零。
// 语义：payload.size() 必须 <= cap。
bool writeRegionPadded(std::vector<uint8_t>* bytes,
                       uint64_t baseOff,
                       uint32_t off,
                       uint32_t cap,
                       const std::vector<uint8_t>& payload,
                       std::string* error);

// 结束命名空间。
}  // namespace vmp::base::bytes
