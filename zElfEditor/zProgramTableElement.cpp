#include "zProgramTableElement.h"

// 从 ELF 原始 Program Header 构建内部模型对象。
zProgramTableElement zProgramTableElement::fromPhdr(const Elf64_Phdr& phdr) {
    zProgramTableElement item;
    item.type = phdr.p_type;
    item.flags = phdr.p_flags;
    item.offset = phdr.p_offset;
    item.vaddr = phdr.p_vaddr;
    item.paddr = phdr.p_paddr;
    item.filesz = phdr.p_filesz;
    item.memsz = phdr.p_memsz;
    item.align = phdr.p_align;
    return item;
}

// 将内部模型转换回 ELF 原始 Program Header。
Elf64_Phdr zProgramTableElement::toPhdr() const {
    Elf64_Phdr ph{};
    ph.p_type = type;
    ph.p_flags = flags;
    ph.p_offset = offset;
    ph.p_vaddr = vaddr;
    ph.p_paddr = paddr;
    ph.p_filesz = filesz;
    ph.p_memsz = memsz;
    ph.p_align = align;
    return ph;
}

// 判断地址是否落在段虚拟地址区间内（左闭右开）。
bool zProgramTableElement::containsVaddr(Elf64_Addr addr) const {
    return memsz > 0 && addr >= vaddr && addr < vaddr + memsz;
}

// 判断文件偏移是否落在段文件区间内（左闭右开）。
bool zProgramTableElement::containsFileOffset(Elf64_Off off) const {
    return filesz > 0 && off >= offset && off < offset + filesz;
}

// ELF 基础约束：段内存尺寸不得小于文件尺寸。
bool zProgramTableElement::validateMemFileRelation() const {
    return memsz >= filesz;
}

// 计算段文件区间结束位置。
uint64_t zProgramTableElement::fileEnd() const {
    return (uint64_t)offset + (uint64_t)filesz;
}

// 计算段虚拟地址区间结束位置。
uint64_t zProgramTableElement::vaddrEnd() const {
    return (uint64_t)vaddr + (uint64_t)memsz;
}
