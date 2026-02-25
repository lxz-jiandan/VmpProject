#ifndef VMP_PATCHBAY_ZELF_UTILS_H
#define VMP_PATCHBAY_ZELF_UTILS_H

/**
 * @file zPatchElfUtils.h
 * @brief ELF 操作公共工具函数与常量。
 *
 * 集中定义各模块共用的对齐、区间判断、动态标签常量等基础设施，
 * 消除跨文件重复并保证行为一致性。
 */

#include "zPatchElfTypes.h"
#include "zCodec.h"

#include <cstdint>
#include <limits>
#include <string>
#include <unordered_map>
#include <vector>

// 前置声明，避免引入 zPatchElf.h 造成循环依赖。
class PatchElf;
class zProgramTableElement;
class zSectionTableElement;

// ============================================================================
// 常量：内核 elf.h 中未定义的动态标签
// ============================================================================

constexpr Elf64_Sxword DT_INIT_ARRAY_TAG      = 25;         // .init_array 起始地址
constexpr Elf64_Sxword DT_FINI_ARRAY_TAG      = 26;         // .fini_array 起始地址
constexpr Elf64_Sxword DT_PREINIT_ARRAY_TAG   = 32;         // .preinit_array 起始地址
constexpr Elf64_Sxword DT_RELRSZ_TAG          = 35;         // DT_RELR 总字节数
constexpr Elf64_Sxword DT_RELR_TAG            = 36;         // DT_RELR 表地址
constexpr Elf64_Sxword DT_RELRENT_TAG         = 37;         // DT_RELR 单项大小
constexpr Elf64_Sxword DT_ANDROID_REL_TAG     = 0x6000000f; // Android packed REL 地址
constexpr Elf64_Sxword DT_ANDROID_RELSZ_TAG   = 0x60000010; // Android packed REL 大小
constexpr Elf64_Sxword DT_ANDROID_RELA_TAG    = 0x60000011; // Android packed RELA 地址
constexpr Elf64_Sxword DT_ANDROID_RELASZ_TAG  = 0x60000012; // Android packed RELA 大小

// ============================================================================
// 纯工具函数（inline，无外部类型依赖）
// ============================================================================

// 通用向上对齐工具。
inline uint64_t alignUpU64(uint64_t value, uint64_t align) {
    if (align == 0) {
        // align=0 视作“不对齐”，直接返回原值。
        return value;
    }
    // 整数上取整到 align 的倍数。
    return ((value + align - 1) / align) * align;
}

// 通用向上对齐工具（Elf64_Off 版本）。
inline Elf64_Off alignUpOff(Elf64_Off value, Elf64_Off align) {
    if (align == 0) {
        return value;
    }
    return ((value + align - 1) / align) * align;
}

// 安全加法：检测 uint64 溢出。
inline bool addU64Checked(uint64_t a, uint64_t b, uint64_t* out) {
    if (!out) {
        return false;
    }
    if (std::numeric_limits<uint64_t>::max() - a < b) {
        return false;
    }
    *out = a + b;
    return true;
}

// 判断两个区间是否重叠。
inline bool rangesOverlapU64(uint64_t aBegin, uint64_t aSize,
                             uint64_t bBegin, uint64_t bSize) {
    // 空区间与任何区间都不重叠。
    if (aSize == 0 || bSize == 0) {
        return false;
    }
    // 任一区间在计算 end 前发生溢出则视为非法输入，不判重叠。
    if (aBegin > std::numeric_limits<uint64_t>::max() - aSize) {
        return false;
    }
    if (bBegin > std::numeric_limits<uint64_t>::max() - bSize) {
        return false;
    }
    uint64_t aEnd = aBegin + aSize;
    uint64_t bEnd = bBegin + bSize;
    // 半开区间相交判定：[a_begin, a_end) 与 [b_begin, b_end)。
    return aBegin < bEnd && bBegin < aEnd;
}

// 判断地址区间是否完全落在给定基址区间内。
inline bool containsAddrRangeU64(uint64_t base, uint64_t size,
                                 uint64_t addr, uint64_t addrSize) {
    if (size == 0) {
        return false;
    }
    uint64_t end = 0;
    if (!addU64Checked(base, size, &end)) {
        return false;
    }
    if (addrSize == 0) {
        // 0 长度时退化为“点是否落在区间端点内”。
        return addr >= base && addr <= end;
    }
    uint64_t addrEnd = 0;
    if (!addU64Checked(addr, addrSize, &addrEnd)) {
        return false;
    }
    // 要求 [addr, addr_end) 完整落入 [base, end]。
    return addr >= base && addrEnd <= end;
}

// 判断是否为 2 的幂。
inline bool isPowerOfTwoU64(uint64_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

// 判断是否为保留/特殊节索引。
inline bool isSpecialShndx(uint16_t shndx) {
    // 常见特殊索引：UNDEF/ABS/COMMON。
    if (shndx == SHN_UNDEF || shndx == SHN_ABS || shndx == SHN_COMMON) {
        return true;
    }
    // 保留区间索引也视为特殊索引。
    return shndx >= SHN_LORESERVE && shndx <= SHN_HIRESERVE;
}

// 小端读取 32 位整数。
inline bool readU32LeBytes(const std::vector<uint8_t>& bytes,
                              size_t off, uint32_t* out) {
    return vmp::base::codec::readU32Le(bytes, off, out);
}

// 小端写入 32 位整数。
inline bool writeU32LeBytes(std::vector<uint8_t>* bytes,
                               size_t off, uint32_t value) {
    return vmp::base::codec::writeU32Le(bytes, off, value);
}

// ============================================================================
// 需要完整类型定义的函数（声明于此，实现在 elf_utils.cpp）
// ============================================================================

// 根据 PT_LOAD 的 p_align 推断运行时页大小。
uint64_t inferRuntimePageSizeFromPhdrs(
        const std::vector<zProgramTableElement>& phs);

// 判断 LOAD 段的权限标志是否匹配 section 标志。
bool loadSegmentMatchesSectionFlags(
        const zProgramTableElement& ph,
        const zSectionTableElement& section);

// 判断动态标签是否表示"地址指针字段"。
bool isDynamicPointerTag(Elf64_Sxword tag);

// 收集动态标签到 map（优先 SHT_DYNAMIC，必要时回退 PT_DYNAMIC）。
bool collectDynamicTags(
        const PatchElf& elf,
        std::unordered_map<int64_t, uint64_t>* tags,
        std::string* error);

// 从 PT_DYNAMIC 段读取动态条目。
bool readDynamicEntriesFromPhdr(
        const PatchElf& elf,
        std::vector<Elf64_Dyn>* outEntries,
        Elf64_Off* outOff,
        Elf64_Xword* outSize,
        bool* outHasPtDynamic,
        std::string* error);

#endif // VMP_PATCHBAY_ZELF_UTILS_H



