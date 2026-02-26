// PatchBay 跨端协议定义：
// - 离线侧（VmProtect）与运行时（VmEngine）必须共用同一份布局；
// - 避免双端手工拷贝导致字段漂移。
#pragma once

// 固定宽度整数类型。
#include <cstdint>

namespace vmp::patchbay::protocol {

// PatchBay 固定魔数（'VMPB'）。
constexpr uint32_t kPatchBayMagic = 0x42504d56U;
// PatchBay 协议版本。
constexpr uint16_t kPatchBayVersion = 1;

#pragma pack(push, 1)
// PatchBay 元信息头（二进制布局协议）。
struct PatchBayHeader {
    // 固定魔数（'VMPB'）。
    uint32_t magic;
    // 头版本。
    uint16_t version;
    // 状态位。
    uint16_t flags;
    // patchbay 总大小（header + payload）。
    uint32_t totalSize;
    // header 大小。
    uint32_t headerSize;
    // payload 大小。
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
    // takeover 入口总数。
    uint32_t takeoverEntryTotal;
    // takeover 已使用入口数。
    uint32_t takeoverEntryUsed;
    // 首次 patch 前 DT_SYMTAB 快照。
    uint64_t originalDtSymtab;
    // 首次 patch 前 DT_STRTAB 快照。
    uint64_t originalDtStrtab;
    // 首次 patch 前 DT_GNU_HASH 快照。
    uint64_t originalDtGnuHash;
    // 首次 patch 前 DT_HASH 快照。
    uint64_t originalDtHash;
    // 首次 patch 前 DT_VERSYM 快照。
    uint64_t originalDtVersym;
    // dynsym 已使用字节数。
    uint32_t usedDynsym;
    // dynstr 已使用字节数。
    uint32_t usedDynstr;
    // gnu hash 已使用字节数。
    uint32_t usedGnuHash;
    // sysv hash 已使用字节数。
    uint32_t usedSysvHash;
    // versym 已使用字节数。
    uint32_t usedVersym;
    // takeover 位图低 64 位。
    uint64_t takeoverEntryBitmapLo;
    // takeover 位图高 64 位。
    uint64_t takeoverEntryBitmapHi;
    // header + used payload 的 crc32。
    uint32_t crc32;
};
#pragma pack(pop)

// 协议结构大小固定保护。
static_assert(sizeof(PatchBayHeader) == 148, "PatchBayHeader layout mismatch");

// 各子区容量预算。
constexpr uint32_t kPatchBayDynsymCap = 128U * 1024U;
constexpr uint32_t kPatchBayDynstrCap = 192U * 1024U;
constexpr uint32_t kPatchBayGnuHashCap = 128U * 1024U;
constexpr uint32_t kPatchBaySysvHashCap = 64U * 1024U;
constexpr uint32_t kPatchBayVersymCap = 32U * 1024U;

// 派生偏移与总大小。
constexpr uint32_t kPatchBayHeaderSize = static_cast<uint32_t>(sizeof(PatchBayHeader));
constexpr uint32_t kPatchBayDynsymOff = kPatchBayHeaderSize;
constexpr uint32_t kPatchBayDynstrOff = kPatchBayDynsymOff + kPatchBayDynsymCap;
constexpr uint32_t kPatchBayGnuHashOff = kPatchBayDynstrOff + kPatchBayDynstrCap;
constexpr uint32_t kPatchBaySysvHashOff = kPatchBayGnuHashOff + kPatchBayGnuHashCap;
constexpr uint32_t kPatchBayVersymOff = kPatchBaySysvHashOff + kPatchBaySysvHashCap;
constexpr uint32_t kPatchBayTotalSize = kPatchBayVersymOff + kPatchBayVersymCap;
constexpr uint32_t kPatchBayPayloadSize = kPatchBayTotalSize - kPatchBayHeaderSize;

}  // namespace vmp::patchbay::protocol

