// 防止头文件重复包含。
#pragma once

// 引入固定宽度整数类型。
#include <cstdint>

// 基础层哈希函数命名空间。
namespace vmp::base::hash {

// 计算 ELF SYSV 哈希值（传统 .hash 使用）。
uint32_t elfSysvHash(const char* name);
// 计算 ELF GNU 哈希值（.gnu.hash 使用）。
uint32_t elfGnuHash(const char* name);
// 按符号数量选择一个合适的哈希桶数。
uint32_t chooseBucketCount(uint32_t nchain);

// 结束命名空间。
}  // namespace vmp::base::hash
