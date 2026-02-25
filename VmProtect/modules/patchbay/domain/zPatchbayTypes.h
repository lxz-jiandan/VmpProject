#ifndef VMPROTECT_PATCHBAY_TYPES_H
#define VMPROTECT_PATCHBAY_TYPES_H

// 引入 ELF ABI 基础类型（Elf64_*）。
#include "zElfAbi.h"

// 引入基础整型定义。
#include <cstdint>
// 引入字符串类型。
#include <string>

// alias 对：表示“新增导出名 -> 实现符号名”的映射。
struct AliasPair {
    // 需要新增/补齐的导出名（对外可见符号）。
    std::string exportName;
    // exportName 最终要指向的实现符号名。
    std::string implName;
    // 若非 0，则写入新增符号 st_size（用于承载 key=donor.st_value）。
    uint64_t exportKey = 0;
};

// PatchBayHeader 与 VmEngine/app/src/main/cpp/zPatchBay.h 必须严格同布局。
// 两端需按同一二进制协议读写，否则运行时无法识别 patchbay 元数据。
#pragma pack(push, 1)
struct PatchBayHeader {
    // 固定魔数（'VMPB'）。
    uint32_t magic;
    // header 版本号。
    uint16_t version;
    // 状态位（是否已写入新表、是否已更新 dynamic 等）。
    uint16_t flags;
    // patchbay 总大小（含 header + payload）。
    uint32_t totalSize;
    // 头部大小（允许向后兼容扩展）。
    uint32_t headerSize;
    // payload 区域大小（可用于快速容量判断）。
    uint32_t payloadSize;
    // dynsym 子区偏移（相对 patchbay 起点）。
    uint32_t dynsymOffset;
    // dynsym 子区容量。
    uint32_t dynsymCapacity;
    // dynstr 子区偏移。
    uint32_t dynstrOffset;
    // dynstr 子区容量。
    uint32_t dynstrCapacity;
    // gnu hash 子区偏移。
    uint32_t gnuHashOffset;
    // gnu hash 子区容量。
    uint32_t gnuHashCapacity;
    // sysv hash 子区偏移。
    uint32_t sysvHashOffset;
    // sysv hash 子区容量。
    uint32_t sysvHashCapacity;
    // versym 子区偏移。
    uint32_t versymOffset;
    // versym 子区容量。
    uint32_t versymCapacity;
    // takeover 槽位总数。
    uint32_t takeoverSlotTotal;
    // 已使用 takeover 槽位数。
    uint32_t takeoverSlotUsed;
    // 首次 patch 前的原始 DT_SYMTAB 快照。
    uint64_t originalDtSymtab;
    // 首次 patch 前的原始 DT_STRTAB 快照。
    uint64_t originalDtStrtab;
    // 首次 patch 前的原始 DT_GNU_HASH 快照。
    uint64_t originalDtGnuHash;
    // 首次 patch 前的原始 DT_HASH 快照。
    uint64_t originalDtHash;
    // 首次 patch 前的原始 DT_VERSYM 快照。
    uint64_t originalDtVersym;
    // dynsym 当前已使用字节数。
    uint32_t usedDynsym;
    // dynstr 当前已使用字节数。
    uint32_t usedDynstr;
    // gnu hash 当前已使用字节数。
    uint32_t usedGnuHash;
    // sysv hash 当前已使用字节数。
    uint32_t usedSysvHash;
    // versym 当前已使用字节数。
    uint32_t usedVersym;
    // takeover 槽位位图低 64 位。
    uint64_t takeoverSlotBitmapLo;
    // takeover 槽位位图高 64 位。
    uint64_t takeoverSlotBitmapHi;
    // 对 header(清零crc)+used payload 的 CRC32 校验值。
    uint32_t crc32;
};
#pragma pack(pop)

// 编译期断言：协议结构大小必须保持不变。
static_assert(sizeof(PatchBayHeader) == 148, "PatchBayHeader layout mismatch");

// patchbay 魔数常量（'VMPB'）。
constexpr uint32_t kPatchBayMagic = 0x42504d56U;
// patchbay 协议版本常量。
constexpr uint16_t kPatchBayVersion = 1;

#endif // VMPROTECT_PATCHBAY_TYPES_H

