// 防止头文件重复包含。
#pragma once

// 引入定宽整数类型。
#include <cstdint>
// 引入 numeric_limits。
#include <limits>

// 基础层 uint64 数学工具命名空间。
namespace vmp::base::u64math {

// 向上对齐到 align 的倍数；align=0 时直接返回原值。
inline uint64_t alignUpU64(uint64_t value, uint64_t align) {
    if (align == 0) {
        return value;
    }
    return ((value + align - 1) / align) * align;
}

// 安全加法：检测 uint64 溢出，成功后写出结果。
inline bool addU64Checked(uint64_t a, uint64_t b, uint64_t* out) {
    if (out == nullptr) {
        return false;
    }
    if (std::numeric_limits<uint64_t>::max() - a < b) {
        return false;
    }
    *out = a + b;
    return true;
}

// 判断是否是 2 的幂。
inline bool isPowerOfTwoU64(uint64_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

// 结束命名空间。
}  // namespace vmp::base::u64math
