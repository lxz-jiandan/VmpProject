#include "zProgramEntry.h"

// 从 ELF 原始 Program Header 构建内部模型对象。
zProgramTableElement zProgramTableElement::fromPhdr(const Elf64_Phdr& phdr) {
    // 创建目标对象。
    zProgramTableElement item;
    // 类型。
    item.type = phdr.p_type;
    // 权限标志。
    item.flags = phdr.p_flags;
    // 文件偏移。
    item.offset = phdr.p_offset;
    // 虚拟地址。
    item.vaddr = phdr.p_vaddr;
    // 物理地址。
    item.paddr = phdr.p_paddr;
    // 文件大小。
    item.filesz = phdr.p_filesz;
    // 内存大小。
    item.memsz = phdr.p_memsz;
    // 对齐。
    item.align = phdr.p_align;
    return item;
}

// 将内部模型转换回 ELF 原始 Program Header。
Elf64_Phdr zProgramTableElement::toPhdr() const {
    // 零初始化输出结构。
    Elf64_Phdr ph{};
    // 类型。
    ph.p_type = type;
    // 权限标志。
    ph.p_flags = flags;
    // 文件偏移。
    ph.p_offset = offset;
    // 虚拟地址。
    ph.p_vaddr = vaddr;
    // 物理地址。
    ph.p_paddr = paddr;
    // 文件大小。
    ph.p_filesz = filesz;
    // 内存大小。
    ph.p_memsz = memsz;
    // 对齐。
    ph.p_align = align;
    return ph;
}

// 判断地址是否落在段虚拟地址区间内（左闭右开）。
bool zProgramTableElement::containsVaddr(Elf64_Addr addr) const {
    // memsz=0 表示无有效虚拟区间。
    return memsz > 0 && addr >= vaddr && addr < vaddr + memsz;
}

// 判断文件偏移是否落在段文件区间内（左闭右开）。
bool zProgramTableElement::containsFileOffset(Elf64_Off off) const {
    // filesz=0 表示无有效文件区间。
    return filesz > 0 && off >= offset && off < offset + filesz;
}

// ELF 基础约束：段内存尺寸不得小于文件尺寸。
bool zProgramTableElement::isMemFileRelationValid() const {
    return memsz >= filesz;
}

// 计算段文件区间结束位置（开区间终点）。
uint64_t zProgramTableElement::getFileEnd() const {
    return (uint64_t)offset + (uint64_t)filesz;
}

// 计算段虚拟地址区间结束位置（开区间终点）。
uint64_t zProgramTableElement::getVaddrEnd() const {
    return (uint64_t)vaddr + (uint64_t)memsz;
}

