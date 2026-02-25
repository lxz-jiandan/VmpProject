#ifndef VMPROTECT_PATCHBAY_HASH_H
#define VMPROTECT_PATCHBAY_HASH_H

// 引入 ELF 符号结构定义。
#include "zElfAbi.h"

// 引入基础整型定义。
#include <cstdint>
// 引入字节数组容器。
#include <vector>

// 计算 ELF SYSV hash（兼容 .hash）。
// 入参：
// - name: 以 '\0' 结尾的符号名。
// 出参：
// - 返回 32 位 hash 值。
uint32_t elfSysvHash(const char* name);

// 按符号总数选择 bucket 数。
// 入参：
// - nchain: dynsym 条目总数。
// 出参：
// - 返回 bucket 数（至少 1）。
uint32_t chooseBucketCount(uint32_t nchain);

// 基于 dynsym + dynstr 构建 SYSV hash payload。
// 入参：
// - dynsymSymbols: 动态符号表条目。
// - dynstrBytes: 动态字符串表原始字节。
// 出参：
// - 返回序列化后的 .hash 内容；失败时为空。
std::vector<uint8_t> buildSysvHashPayloadFromBytes(const std::vector<Elf64_Sym>& dynsymSymbols,
                                                   const std::vector<uint8_t>& dynstrBytes);

// 计算 ELF GNU hash（兼容 .gnu.hash）。
// 入参：
// - name: 以 '\0' 结尾的符号名。
// 出参：
// - 返回 32 位 hash 值。
uint32_t elfGnuHash(const char* name);

// 基于 dynsym + dynstr 构建 GNU hash payload。
// 入参：
// - dynsymSymbols: 动态符号表条目。
// - dynstrBytes: 动态字符串表原始字节。
// 出参：
// - 返回序列化后的 .gnu.hash 内容；失败时为空。
std::vector<uint8_t> buildGnuHashPayloadFromBytes(const std::vector<Elf64_Sym>& dynsymSymbols,
                                                  const std::vector<uint8_t>& dynstrBytes);

#endif // VMPROTECT_PATCHBAY_HASH_H

