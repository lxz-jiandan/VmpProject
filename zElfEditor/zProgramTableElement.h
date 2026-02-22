#ifndef OVERT_ZPROGRAM_TABLE_ELEMENT_H
#define OVERT_ZPROGRAM_TABLE_ELEMENT_H

#include "elf.h"

#include <cstdint>

/**
 * @brief Program Header 单条目的模型封装。
 *
 * 对 `Elf64_Phdr` 做了字段直映射，并提供常用范围判断/关系校验辅助函数。
 */
class zProgramTableElement {
public:
    Elf64_Word type = PT_NULL;  ///< 段类型（`PT_*`）。
    Elf64_Word flags = 0;       ///< 段权限标志（`PF_R/PF_W/PF_X`）。
    Elf64_Off offset = 0;       ///< 文件偏移 `p_offset`。
    Elf64_Addr vaddr = 0;       ///< 虚拟地址 `p_vaddr`。
    Elf64_Addr paddr = 0;       ///< 物理地址 `p_paddr`（多数场景与 vaddr 相同）。
    Elf64_Xword filesz = 0;     ///< 文件映像大小 `p_filesz`。
    Elf64_Xword memsz = 0;      ///< 内存映像大小 `p_memsz`。
    Elf64_Xword align = 0;      ///< 段对齐 `p_align`。

    /** @brief 从 `Elf64_Phdr` 构造模型对象。 */
    static zProgramTableElement fromPhdr(const Elf64_Phdr& phdr);

    /** @brief 序列化为 `Elf64_Phdr`。 */
    Elf64_Phdr toPhdr() const;

    /** @brief 判断给定虚拟地址是否落在 `[vaddr, vaddr + memsz)` 内。 */
    bool containsVaddr(Elf64_Addr addr) const;

    /** @brief 判断给定文件偏移是否落在 `[offset, offset + filesz)` 内。 */
    bool containsFileOffset(Elf64_Off off) const;

    /** @brief 检查 ELF 规范关系：`memsz >= filesz`。 */
    bool validateMemFileRelation() const;

    /** @brief 返回文件范围末尾偏移：`offset + filesz`。 */
    uint64_t fileEnd() const;

    /** @brief 返回虚拟地址范围末尾：`vaddr + memsz`。 */
    uint64_t vaddrEnd() const;
};

#endif // OVERT_ZPROGRAM_TABLE_ELEMENT_H
