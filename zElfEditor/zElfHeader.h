#ifndef OVERT_ZELF_HEADER_H
#define OVERT_ZELF_HEADER_H

#include "elf.h"

#include <cstddef>
#include <cstdint>

/**
 * @brief ELF Header 的轻量模型。
 *
 * 用于承载 `Elf64_Ehdr` 原始结构，并提供基础格式校验能力。
 */
class zElfHeader {
public:
    Elf64_Ehdr raw{};  ///< 原始 ELF 头结构。

    /**
     * @brief 从字节流解析 ELF Header。
     * @param data 字节流起始地址。
     * @param size 可读字节总数。
     * @return true 表示解析成功且长度足够。
     */
    bool fromRaw(const uint8_t* data, size_t size);

    /**
     * @brief 判断是否为 ELF64 + AArch64 + 小端格式。
     */
    bool isElf64AArch64() const;
};

#endif // OVERT_ZELF_HEADER_H
