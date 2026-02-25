// 引入哈希函数接口声明。
#include "zHash.h"

// 进入基础哈希命名空间。
namespace vmp::base::hash {

// 计算 ELF SYSV 哈希。
uint32_t elfSysvHash(const char* name) {
    // 空指针直接返回 0，避免崩溃。
    if (name == nullptr) {
        return 0;
    }
    // 累计哈希值。
    uint32_t h = 0;
    // 按字符逐步更新。
    while (*name) {
        // 左移 4 并加当前字符。
        h = (h << 4) + static_cast<uint8_t>(*name++);
        // 提取高位 nibble。
        const uint32_t g = h & 0xf0000000U;
        // 若高位非零则执行折叠。
        if (g != 0) {
            h ^= g >> 24;
        }
        // 清理高位参与位，保持值稳定。
        h &= ~g;
    }
    // 返回结果。
    return h;
}

// 计算 ELF GNU 哈希。
uint32_t elfGnuHash(const char* name) {
    // 空指针直接返回 0，避免崩溃。
    if (name == nullptr) {
        return 0;
    }
    // GNU hash 初始值固定为 5381。
    uint32_t h = 5381U;
    // 按字符滚动计算：h = h*33 + c。
    while (*name) {
        h = (h << 5) + h + static_cast<uint8_t>(*name++);
    }
    // 返回结果。
    return h;
}

// 依据符号数量选择桶数。
uint32_t chooseBucketCount(const uint32_t nchain) {
    // 预选素数表，常用于哈希桶分配。
    static const uint32_t kPrimes[] = {
        3, 5, 7, 11, 17, 29, 53, 97, 193, 389, 769, 1543, 3079, 6151,
        12289, 24593, 49157, 98317, 196613, 393241, 786433
    };
    // 目标策略：符号少时至少 8，常规取 n/2+1。
    const uint32_t target = (nchain < 8U) ? 8U : (nchain / 2U + 1U);
    // 取第一个 >= target 的素数。
    for (const uint32_t p : kPrimes) {
        if (p >= target) {
            return p;
        }
    }
    // 超过表上限时返回最后一个素数。
    return kPrimes[sizeof(kPrimes) / sizeof(kPrimes[0]) - 1];
}

// 结束命名空间。
}  // namespace vmp::base::hash
