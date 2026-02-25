#ifndef VMP_PATCHBAY_PROGRAM_ENTRY_H
#define VMP_PATCHBAY_PROGRAM_ENTRY_H

// ELF 基础类型（Elf64_Phdr / Elf64_Addr / PT_* / PF_*）。
#include "zPatchElfTypes.h"

// uint64_t。
#include <cstdint>

/**
 * @brief Program Header 单条目的模型封装。
 *
 * 设计目标：
 * - 与 `Elf64_Phdr` 保持一一对应，降低理解成本；
 * - 提供常用区间判断工具，避免上层反复写边界逻辑；
 * - 作为 Program Table 与地址转换逻辑的基础数据单元。
 */
class zProgramTableElement {
public:
    // 段类型（PT_LOAD / PT_DYNAMIC / PT_NOTE ...）。
    Elf64_Word type = PT_NULL;
    // 段权限位（PF_R / PF_W / PF_X）。
    Elf64_Word flags = 0;
    // 文件偏移（p_offset）。
    Elf64_Off offset = 0;
    // 虚拟地址（p_vaddr）。
    Elf64_Addr vaddr = 0;
    // 物理地址（p_paddr），多数 Linux/Android 可视作保留字段。
    Elf64_Addr paddr = 0;
    // 文件中实际占用字节数（p_filesz）。
    Elf64_Xword filesz = 0;
    // 内存映射后字节数（p_memsz）。
    Elf64_Xword memsz = 0;
    // 对齐粒度（p_align）。
    Elf64_Xword align = 0;

    /**
     * @brief 从原始 `Elf64_Phdr` 转换为模型对象。
     * @param phdr 原始 program header 条目。
     * @return 对应的模型副本。
     */
    static zProgramTableElement fromPhdr(const Elf64_Phdr& phdr);

    /**
     * @brief 将模型对象序列化回 `Elf64_Phdr`。
     * @return 可直接写回文件镜像的原始结构。
     */
    Elf64_Phdr toPhdr() const;

    /**
     * @brief 判断虚拟地址是否落在当前段内。
     * @param addr 目标虚拟地址。
     * @return true 表示 `addr` 在 `[vaddr, vaddr + memsz)`。
     */
    bool containsVaddr(Elf64_Addr addr) const;

    /**
     * @brief 判断文件偏移是否落在当前段内。
     * @param off 目标文件偏移。
     * @return true 表示 `off` 在 `[offset, offset + filesz)`。
     */
    bool containsFileOffset(Elf64_Off off) const;

    /**
     * @brief 校验 ELF 约束关系 `memsz >= filesz`。
     * @return true 表示关系合法。
     */
    bool isMemFileRelationValid() const;

    /**
     * @brief 计算文件范围末尾偏移。
     * @return `offset + filesz`（以 uint64_t 返回防止窄类型溢出）。
     */
    uint64_t getFileEnd() const;

    /**
     * @brief 计算虚拟地址范围末尾。
     * @return `vaddr + memsz`（以 uint64_t 返回防止窄类型溢出）。
     */
    uint64_t getVaddrEnd() const;
};

#endif // VMP_PATCHBAY_PROGRAM_ENTRY_H

