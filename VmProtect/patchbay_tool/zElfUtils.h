#ifndef OVERT_ZELF_UTILS_H
#define OVERT_ZELF_UTILS_H

/**
 * @file zElfUtils.h
 * @brief ELF 操作公共工具函数与常量。
 *
 * 集中定义各模块共用的对齐、区间判断、动态标签常量等基础设施，
 * 消除跨文件重复并保证行为一致性。
 */

#include "elf.h"

#include <cstdint>
#include <limits>
#include <string>
#include <unordered_map>
#include <vector>

// 前置声明，避免引入 zElf.h 造成循环依赖。
class zElf;
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
inline uint64_t align_up_u64(uint64_t value, uint64_t align) {
    if (align == 0) {
        // align=0 视作“不对齐”，直接返回原值。
        return value;
    }
    // 整数上取整到 align 的倍数。
    return ((value + align - 1) / align) * align;
}

// 通用向上对齐工具（Elf64_Off 版本）。
inline Elf64_Off align_up_off(Elf64_Off value, Elf64_Off align) {
    if (align == 0) {
        return value;
    }
    return ((value + align - 1) / align) * align;
}

// 安全加法：检测 uint64 溢出。
inline bool add_u64_checked(uint64_t a, uint64_t b, uint64_t* out) {
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
inline bool ranges_overlap_u64(uint64_t a_begin, uint64_t a_size,
                               uint64_t b_begin, uint64_t b_size) {
    // 空区间与任何区间都不重叠。
    if (a_size == 0 || b_size == 0) {
        return false;
    }
    // 任一区间在计算 end 前发生溢出则视为非法输入，不判重叠。
    if (a_begin > std::numeric_limits<uint64_t>::max() - a_size) {
        return false;
    }
    if (b_begin > std::numeric_limits<uint64_t>::max() - b_size) {
        return false;
    }
    uint64_t a_end = a_begin + a_size;
    uint64_t b_end = b_begin + b_size;
    // 半开区间相交判定：[a_begin, a_end) 与 [b_begin, b_end)。
    return a_begin < b_end && b_begin < a_end;
}

// 判断地址区间是否完全落在给定基址区间内。
inline bool contains_addr_range_u64(uint64_t base, uint64_t size,
                                    uint64_t addr, uint64_t addr_size) {
    if (size == 0) {
        return false;
    }
    uint64_t end = 0;
    if (!add_u64_checked(base, size, &end)) {
        return false;
    }
    if (addr_size == 0) {
        // 0 长度时退化为“点是否落在区间端点内”。
        return addr >= base && addr <= end;
    }
    uint64_t addr_end = 0;
    if (!add_u64_checked(addr, addr_size, &addr_end)) {
        return false;
    }
    // 要求 [addr, addr_end) 完整落入 [base, end]。
    return addr >= base && addr_end <= end;
}

// 判断是否为 2 的幂。
inline bool is_power_of_two_u64(uint64_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

// 判断是否为保留/特殊节索引。
inline bool is_special_shndx(uint16_t shndx) {
    // 常见特殊索引：UNDEF/ABS/COMMON。
    if (shndx == SHN_UNDEF || shndx == SHN_ABS || shndx == SHN_COMMON) {
        return true;
    }
    // 保留区间索引也视为特殊索引。
    return shndx >= SHN_LORESERVE && shndx <= SHN_HIRESERVE;
}

// 小端读取 32 位整数。
inline bool read_u32_le_bytes(const std::vector<uint8_t>& bytes,
                              size_t off, uint32_t* out) {
    if (!out || off + 4 > bytes.size()) {
        return false;
    }
    // 按 little-endian 组合 4 字节。
    *out = (uint32_t)bytes[off] |
           ((uint32_t)bytes[off + 1] << 8) |
           ((uint32_t)bytes[off + 2] << 16) |
           ((uint32_t)bytes[off + 3] << 24);
    return true;
}

// 小端写入 32 位整数。
inline bool write_u32_le_bytes(std::vector<uint8_t>* bytes,
                               size_t off, uint32_t value) {
    if (!bytes || off + 4 > bytes->size()) {
        return false;
    }
    // 按 little-endian 拆分并写回 4 字节。
    (*bytes)[off] = (uint8_t)(value & 0xff);
    (*bytes)[off + 1] = (uint8_t)((value >> 8) & 0xff);
    (*bytes)[off + 2] = (uint8_t)((value >> 16) & 0xff);
    (*bytes)[off + 3] = (uint8_t)((value >> 24) & 0xff);
    return true;
}

// ============================================================================
// 需要完整类型定义的函数（声明于此，实现在 zElfUtils.cpp）
// ============================================================================

// 根据 PT_LOAD 的 p_align 推断运行时页大小。
uint64_t infer_runtime_page_size_from_phdrs(
        const std::vector<zProgramTableElement>& phs);

// 判断 LOAD 段的权限标志是否匹配 section 标志。
bool load_segment_matches_section_flags(
        const zProgramTableElement& ph,
        const zSectionTableElement& section);

// 判断动态标签是否表示"地址指针字段"。
bool is_dynamic_pointer_tag(Elf64_Sxword tag);

// 收集动态标签到 map（优先 SHT_DYNAMIC，必要时回退 PT_DYNAMIC）。
bool collect_dynamic_tags(
        const zElf& elf,
        std::unordered_map<int64_t, uint64_t>* tags,
        std::string* error);

// 从 PT_DYNAMIC 段读取动态条目。
bool read_dynamic_entries_from_phdr(
        const zElf& elf,
        std::vector<Elf64_Dyn>* out_entries,
        Elf64_Off* out_off,
        Elf64_Xword* out_size,
        bool* out_has_pt_dynamic,
        std::string* error);

#endif // OVERT_ZELF_UTILS_H
