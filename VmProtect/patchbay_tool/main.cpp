/**
 * @file main.cpp
 * @brief Patchbay 子命令入口。
 *
 * 该文件仅保留 VmProtect 生产链路使用的 patchbay 命令：
 * - export_alias_from_patchbay
 */

#include "zElf.h"
#include "zLog.h"
#include "patchbay_entry.h"

#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <limits>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <vector>

// 打印命令行帮助。
static void print_usage(const char* exe_name) {
    const char* name = exe_name ? exe_name : "VmProtect.exe";
    std::printf("Usage:\n");
    std::printf("  %s export_alias_from_patchbay <input_elf> <donor_elf> <output_elf> <impl_symbol> [--allow-validate-fail] [--only-fun-java]\n", name);
}

struct FullSymbolInfo {
    // 符号值（通常是运行时虚拟地址或相对地址语义，取决于符号类型）。
    Elf64_Addr value = 0;
    // 符号大小（字节）。
    Elf64_Xword size = 0;
    // 符号所在节索引（SHN_UNDEF 表示未定义/导入符号）。
    Elf64_Half shndx = SHN_UNDEF;
    // 符号类型（STT_FUNC/STT_OBJECT/...）。
    unsigned type = STT_NOTYPE;
    // 是否成功解析到该符号。
    bool found = false;
};

struct AliasPair {
    // 需要新增/补齐的导出名（对外可见符号）。
    std::string export_name;
    // export_name 最终要指向的实现符号名。
    std::string impl_name;
    // 若非 0，则写入新增符号 st_size（用于承载 key=donor.st_value）。
    uint64_t export_key = 0;
};

struct DynamicExportInfo {
    // 导出符号名称。
    std::string name;
    // donor 导出符号原始 st_value（用于 route4 key）。
    uint64_t value = 0;
};

// PatchBayHeader 与 VmEngine/app/src/main/cpp/zPatchBay.h 保持完全同布局。
// 两端必须按同一二进制协议读写，否则运行时无法识别 patchbay 元数据。
#pragma pack(push, 1)
struct PatchBayHeader {
    // 固定魔数（'VMPB'）。
    uint32_t magic;
    // header 版本号。
    uint16_t version;
    // 状态位（是否已写入新表、是否已更新 dynamic 等）。
    uint16_t flags;
    // patchbay 总大小（含 header + payload）。
    uint32_t total_size;
    // 头部大小（允许向后兼容扩展）。
    uint32_t header_size;
    // payload 区域大小（可用于快速容量判断）。
    uint32_t payload_size;
    // dynsym 子区偏移/容量。
    uint32_t dynsym_off;
    uint32_t dynsym_cap;
    // dynstr 子区偏移/容量。
    uint32_t dynstr_off;
    uint32_t dynstr_cap;
    // gnu hash 子区偏移/容量。
    uint32_t gnuhash_off;
    uint32_t gnuhash_cap;
    // sysv hash 子区偏移/容量。
    uint32_t sysvhash_off;
    uint32_t sysvhash_cap;
    // versym 子区偏移/容量。
    uint32_t versym_off;
    uint32_t versym_cap;
    // takeover 槽位总数/已使用数。
    uint32_t takeover_slot_total;
    uint32_t takeover_slot_used;
    // 首次 patch 前的原始 DT_* 指针快照（用于排障或回滚参考）。
    uint64_t orig_dt_symtab;
    uint64_t orig_dt_strtab;
    uint64_t orig_dt_gnu_hash;
    uint64_t orig_dt_hash;
    uint64_t orig_dt_versym;
    // 当前“已使用”字节计数（小于等于对应 cap）。
    uint32_t used_dynsym;
    uint32_t used_dynstr;
    uint32_t used_gnuhash;
    uint32_t used_sysvhash;
    uint32_t used_versym;
    // takeover 槽位位图（低 64 位 + 高 64 位）。
    uint64_t takeover_slot_bitmap_lo;
    uint64_t takeover_slot_bitmap_hi;
    // 对 header(清零crc)+used payload 的 CRC32 校验值。
    uint32_t crc32;
};
#pragma pack(pop)

static_assert(sizeof(PatchBayHeader) == 148, "PatchBayHeader layout mismatch");
constexpr uint32_t kPatchBayMagic = 0x42504d56U;  // 'VMPB'
constexpr uint16_t kPatchBayVersion = 1;

static uint64_t bitmask_for_count_u32(uint32_t count) {
    // 0 个槽位时位图为空。
    if (count == 0) {
        return 0ULL;
    }
    // >=64 时整个位图全 1。
    if (count >= 64U) {
        return ~0ULL;
    }
    // 低 count 位为 1，其余位为 0。
    return (1ULL << count) - 1ULL;
}

static uint32_t crc32_ieee_update(uint32_t crc, const uint8_t* data, size_t size) {
    // 空输入直接返回当前 crc。
    if (!data || size == 0) {
        return crc;
    }
    // 使用局部变量滚动更新。
    uint32_t c = crc;
    // 逐字节更新 CRC。
    for (size_t i = 0; i < size; ++i) {
        c ^= data[i];
        // 每字节做 8 次多项式更新。
        for (int bit = 0; bit < 8; ++bit) {
            const uint32_t mask = (c & 1U) ? 0xEDB88320U : 0U;
            c = (c >> 1) ^ mask;
        }
    }
    return c;
}

static bool compute_patchbay_crc_from_file(const std::vector<uint8_t>& file_bytes,
                                           uint64_t patchbay_off,
                                           const PatchBayHeader& hdr,
                                           uint32_t* out_crc,
                                           std::string* error) {
    // 调用方必须提供输出指针。
    if (!out_crc) {
        if (error) {
            *error = "crc output pointer is null";
        }
        return false;
    }
    // 先做头部与区间边界校验，防止越界读取。
    if (hdr.header_size < sizeof(PatchBayHeader) ||
        hdr.total_size < hdr.header_size ||
        patchbay_off > file_bytes.size() ||
        hdr.total_size > file_bytes.size() - (size_t)patchbay_off) {
        if (error) {
            *error = "patchbay header/section bounds invalid for crc";
        }
        return false;
    }
    // header_size 至少要覆盖 crc32 字段位置。
    if (offsetof(PatchBayHeader, crc32) + sizeof(uint32_t) > hdr.header_size) {
        if (error) {
            *error = "patchbay header too small for crc field";
        }
        return false;
    }

    // 复制一份 header，并把 crc 字段清零后参与计算。
    std::vector<uint8_t> header_blob((size_t)hdr.header_size, 0);
    std::memcpy(header_blob.data(), file_bytes.data() + patchbay_off, header_blob.size());
    std::memset(header_blob.data() + offsetof(PatchBayHeader, crc32), 0, sizeof(uint32_t));

    // 统一校验每个子区域（off/cap/used）是否合法。
    auto check_region = [&hdr](uint32_t off, uint32_t cap, uint32_t used, const char* name, std::string* region_error) {
        if (off < hdr.header_size) {
            if (region_error) {
                *region_error = std::string(name) + " off before header";
            }
            return false;
        }
        if ((uint64_t)off + (uint64_t)cap > hdr.total_size) {
            if (region_error) {
                *region_error = std::string(name) + " cap out of total";
            }
            return false;
        }
        if (used > cap) {
            if (region_error) {
                *region_error = std::string(name) + " used exceeds cap";
            }
            return false;
        }
        return true;
    };

    std::string region_error;
    if (!check_region(hdr.dynsym_off, hdr.dynsym_cap, hdr.used_dynsym, "dynsym", &region_error) ||
        !check_region(hdr.dynstr_off, hdr.dynstr_cap, hdr.used_dynstr, "dynstr", &region_error) ||
        !check_region(hdr.gnuhash_off, hdr.gnuhash_cap, hdr.used_gnuhash, "gnuhash", &region_error) ||
        !check_region(hdr.sysvhash_off, hdr.sysvhash_cap, hdr.used_sysvhash, "sysvhash", &region_error) ||
        !check_region(hdr.versym_off, hdr.versym_cap, hdr.used_versym, "versym", &region_error)) {
        if (error) {
            *error = "patchbay region invalid for crc: " + region_error;
        }
        return false;
    }

    uint32_t crc = 0xFFFFFFFFU;
    crc = crc32_ieee_update(crc, header_blob.data(), header_blob.size());

    auto update_used_region = [&crc, &file_bytes, patchbay_off](uint32_t off, uint32_t used) {
        if (used == 0) {
            return;
        }
        const size_t abs_off = (size_t)(patchbay_off + off);
        crc = crc32_ieee_update(crc, file_bytes.data() + abs_off, used);
    };
    update_used_region(hdr.dynsym_off, hdr.used_dynsym);
    update_used_region(hdr.dynstr_off, hdr.used_dynstr);
    update_used_region(hdr.gnuhash_off, hdr.used_gnuhash);
    update_used_region(hdr.sysvhash_off, hdr.used_sysvhash);
    update_used_region(hdr.versym_off, hdr.used_versym);

    // IEEE CRC 结果按约定取按位取反。
    *out_crc = ~crc;
    return true;
}

// 前置声明：文件读写工具函数定义在文件后部。
static bool load_file_bytes(const char* path, std::vector<uint8_t>* out);
static bool save_file_bytes(const char* path, const std::vector<uint8_t>& bytes);

static uint32_t elf_sysv_hash(const char* name) {
    // 空字符串返回 0。
    if (!name) {
        return 0;
    }
    // SYSV ELF hash 标准实现。
    uint32_t h = 0;
    while (*name) {
        h = (h << 4) + static_cast<uint8_t>(*name++);
        const uint32_t g = h & 0xf0000000U;
        if (g != 0) {
            h ^= g >> 24;
        }
        h &= ~g;
    }
    return h;
}

static uint32_t choose_bucket_count(uint32_t nchain) {
    // 经验质数表：在 nchain 变化时选择较稳定的 bucket 数量。
    static const uint32_t primes[] = {
        3, 5, 7, 11, 17, 29, 53, 97, 193, 389, 769, 1543, 3079, 6151,
        12289, 24593, 49157, 98317, 196613, 393241, 786433
    };
    // 小规模符号表至少给 8 的目标下界，避免过度冲突。
    const uint32_t target = (nchain < 8) ? 8U : (nchain / 2U + 1U);
    // 返回第一个 >=target 的质数。
    for (uint32_t p : primes) {
        if (p >= target) {
            return p;
        }
    }
    // 极大规模时返回表中最大值。
    return primes[sizeof(primes) / sizeof(primes[0]) - 1];
}

static std::vector<uint8_t> build_sysv_hash_payload(const zSymbolSection* dynsym, const zStrTabSection* dynstr) {
    if (!dynsym || !dynstr || dynsym->symbols.empty()) {
        return {};
    }

    // SYSV .hash 结构：nbucket/nchain + bucket[] + chain[]。
    const uint32_t nchain = static_cast<uint32_t>(dynsym->symbols.size());
    const uint32_t nbucket = choose_bucket_count(nchain);
    // buckets 保存每个桶链表头，chains 保存同桶后继索引。
    std::vector<uint32_t> buckets(nbucket, 0);
    std::vector<uint32_t> chains(nchain, 0);

    // 建桶流程：同 bucket 内链到 chain 单链表尾部。
    for (uint32_t sym_index = 1; sym_index < nchain; ++sym_index) {
        const Elf64_Sym& sym = dynsym->symbols[sym_index];
        const char* name = dynstr->getStringAt(sym.st_name);
        if (!name || name[0] == '\0') {
            continue;
        }
        const uint32_t h = elf_sysv_hash(name);
        const uint32_t b = h % nbucket;
        if (buckets[b] == 0) {
            // 桶为空时直接挂到头结点。
            buckets[b] = sym_index;
            continue;
        }
        // 桶非空时串到链表末尾。
        uint32_t cursor = buckets[b];
        while (chains[cursor] != 0) {
            cursor = chains[cursor];
        }
        chains[cursor] = sym_index;
    }

    // 序列化为连续字节，供 patchbay 写入。
    std::vector<uint8_t> payload;
    payload.resize(static_cast<size_t>(2 + nbucket + nchain) * sizeof(uint32_t));
    // 直接按 u32 数组视图写入 header + buckets + chains。
    uint32_t* out = reinterpret_cast<uint32_t*>(payload.data());
    out[0] = nbucket;
    out[1] = nchain;
    std::memcpy(out + 2, buckets.data(), static_cast<size_t>(nbucket) * sizeof(uint32_t));
    std::memcpy(out + 2 + nbucket, chains.data(), static_cast<size_t>(nchain) * sizeof(uint32_t));
    return payload;
}

static bool find_symbol_in_table(const zSymbolSection* symtab,
                                 const zStrTabSection* strtab,
                                 const char* symbol_name,
                                 FullSymbolInfo* out_info) {
    // 入参保护。
    if (!symtab || !strtab || !symbol_name || !out_info) {
        return false;
    }
    // 线性遍历符号表（规模可控，逻辑直观）。
    for (size_t idx = 0; idx < symtab->symbols.size(); ++idx) {
        const Elf64_Sym& sym = symtab->symbols[idx];
        // st_name 为 0 表示空名，直接跳过。
        if (sym.st_name == 0) {
            continue;
        }
        // 从字符串表解引用符号名。
        const char* name = strtab->getStringAt(sym.st_name);
        if (!name) {
            continue;
        }
        // 命中目标符号后填充全部字段。
        if (std::strcmp(name, symbol_name) == 0) {
            out_info->value = sym.st_value;
            out_info->size = sym.st_size;
            out_info->shndx = sym.st_shndx;
            out_info->type = ELF64_ST_TYPE(sym.st_info);
            out_info->found = true;
            return true;
        }
    }
    return false;
}

static bool resolve_impl_symbol(const zElf& elf, const char* impl_name, FullSymbolInfo* out_info) {
    // 入参保护。
    if (!impl_name || !out_info) {
        return false;
    }
    // 先清空输出。
    *out_info = FullSymbolInfo{};

    // 先查 .symtab/.strtab（常含完整符号信息）。
    const auto& sht = elf.sectionHeaderModel();
    const int symtab_idx = sht.findByName(".symtab");
    const int strtab_idx = sht.findByName(".strtab");
    if (symtab_idx >= 0 && strtab_idx >= 0) {
        const auto* symtab = dynamic_cast<const zSymbolSection*>(sht.get((size_t)symtab_idx));
        const auto* strtab = dynamic_cast<const zStrTabSection*>(sht.get((size_t)strtab_idx));
        if (find_symbol_in_table(symtab, strtab, impl_name, out_info)) {
            return true;
        }
    }

    // 再查 .dynsym/.dynstr（导出/动态符号）。
    const int dynsym_idx = sht.findByName(".dynsym");
    const int dynstr_idx = sht.findByName(".dynstr");
    if (dynsym_idx >= 0 && dynstr_idx >= 0) {
        const auto* dynsym = dynamic_cast<const zSymbolSection*>(sht.get((size_t)dynsym_idx));
        const auto* dynstr = dynamic_cast<const zStrTabSection*>(sht.get((size_t)dynstr_idx));
        if (find_symbol_in_table(dynsym, dynstr, impl_name, out_info)) {
            return true;
        }
    }
    return false;
}

static bool collect_defined_dynamic_exports(const zElf& elf,
                                            std::vector<std::string>* out_exports,
                                            std::string* error) {
    // 输出容器必须有效。
    if (!out_exports) {
        if (error) {
            *error = "invalid output list";
        }
        return false;
    }
    // 每次调用先清空输出。
    out_exports->clear();

    // 定位 .dynsym 节索引。
    const auto& sht = elf.sectionHeaderModel();
    const int dynsym_idx = sht.findByName(".dynsym");
    if (dynsym_idx < 0) {
        if (error) {
            *error = "missing .dynsym";
        }
        return false;
    }
    const auto* dynsym = dynamic_cast<const zSymbolSection*>(sht.get((size_t)dynsym_idx));
    if (!dynsym) {
        if (error) {
            *error = ".dynsym type mismatch";
        }
        return false;
    }
    if (dynsym->link >= sht.elements.size()) {
        if (error) {
            *error = ".dynsym link out of range";
        }
        return false;
    }
    const auto* dynstr = dynamic_cast<const zStrTabSection*>(sht.get((size_t)dynsym->link));
    if (!dynstr) {
        if (error) {
            *error = ".dynstr type mismatch";
        }
        return false;
    }

    // 去重集合，避免同名重复导出。
    std::unordered_set<std::string> seen;
    seen.reserve(dynsym->symbols.size());
    // 从 1 开始，跳过保留的 STN_UNDEF 项。
    for (size_t i = 1; i < dynsym->symbols.size(); ++i) {
        const Elf64_Sym& sym = dynsym->symbols[i];
        // 未命名或未定义符号不是“已定义导出”。
        if (sym.st_name == 0 || sym.st_shndx == SHN_UNDEF) {
            continue;
        }
        const unsigned bind = ELF64_ST_BIND(sym.st_info);
        const unsigned type = ELF64_ST_TYPE(sym.st_info);
        if (bind != STB_GLOBAL && bind != STB_WEAK) {
            continue;
        }
        if (type == STT_SECTION || type == STT_FILE) {
            continue;
        }
        const char* name = dynstr->getStringAt(sym.st_name);
        if (!name || name[0] == '\0') {
            continue;
        }
        // 已见过同名导出则跳过。
        if (!seen.insert(name).second) {
            continue;
        }
        // 收集导出名。
        out_exports->emplace_back(name);
    }

    return true;
}

static bool collect_defined_dynamic_export_infos(const zElf& elf,
                                                 std::vector<DynamicExportInfo>* out_exports,
                                                 std::string* error) {
    // 输出容器必须有效。
    if (!out_exports) {
        if (error) {
            *error = "invalid output list";
        }
        return false;
    }
    // 每次调用先清空输出。
    out_exports->clear();

    // 定位 .dynsym 节索引。
    const auto& sht = elf.sectionHeaderModel();
    const int dynsym_idx = sht.findByName(".dynsym");
    if (dynsym_idx < 0) {
        if (error) {
            *error = "missing .dynsym";
        }
        return false;
    }
    const auto* dynsym = dynamic_cast<const zSymbolSection*>(sht.get((size_t)dynsym_idx));
    if (!dynsym) {
        if (error) {
            *error = ".dynsym type mismatch";
        }
        return false;
    }
    if (dynsym->link >= sht.elements.size()) {
        if (error) {
            *error = ".dynsym link out of range";
        }
        return false;
    }
    const auto* dynstr = dynamic_cast<const zStrTabSection*>(sht.get((size_t)dynsym->link));
    if (!dynstr) {
        if (error) {
            *error = ".dynstr type mismatch";
        }
        return false;
    }

    // 去重集合，避免同名重复导出。
    std::unordered_set<std::string> seen;
    seen.reserve(dynsym->symbols.size());
    // 从 1 开始，跳过保留的 STN_UNDEF 项。
    for (size_t i = 1; i < dynsym->symbols.size(); ++i) {
        const Elf64_Sym& sym = dynsym->symbols[i];
        if (sym.st_name == 0 || sym.st_shndx == SHN_UNDEF) {
            continue;
        }
        const unsigned bind = ELF64_ST_BIND(sym.st_info);
        const unsigned type = ELF64_ST_TYPE(sym.st_info);
        if (bind != STB_GLOBAL && bind != STB_WEAK) {
            continue;
        }
        if (type == STT_SECTION || type == STT_FILE) {
            continue;
        }
        const char* name = dynstr->getStringAt(sym.st_name);
        if (!name || name[0] == '\0') {
            continue;
        }
        if (!seen.insert(name).second) {
            continue;
        }
        DynamicExportInfo info{};
        info.name = name;
        info.value = static_cast<uint64_t>(sym.st_value);
        out_exports->push_back(std::move(info));
    }

    return true;
}

static bool is_fun_or_java_symbol(const std::string& name) {
    // fun_* 属于 demo 普通函数导出。
    if (name.rfind("fun_", 0) == 0) {
        return true;
    }
    // Java_* 属于 JNI 导出符号。
    if (name.rfind("Java_", 0) == 0) {
        return true;
    }
    // 其它导出默认不纳入 only_fun_java 模式。
    return false;
}

static bool is_cxx_mangled_symbol(const std::string& name) {
    // Itanium C++ ABI 下，C++ 符号通常以 "_Z" 开头。
    return name.rfind("_Z", 0) == 0;
}

static bool is_vm_namespace_cxx_symbol(const std::string& name) {
    // 根命名空间 vm 在 mangled 名里应编码为 "N2vm"（NestedName + len=2 + "vm"）。
    // 例如：_ZN2vm3Foo3barEv / _ZNK2vm3Foo3barEv / _ZTIN2vm3FooE
    return name.find("N2vm") != std::string::npos;
}

static bool is_takeover_slot_mode_impl(const char* impl_name) {
    // 以 vm_takeover_slot_ 作为前缀时启用“按槽位自动分配”模式。
    if (!impl_name) {
        return false;
    }
    return std::strncmp(impl_name, "vm_takeover_slot_", 17) == 0;
}

static std::string build_takeover_slot_symbol_name(uint32_t slot_id) {
    // 槽位符号统一使用四位十进制编号：vm_takeover_slot_0000。
    char buffer[64] = {0};
    std::snprintf(buffer, sizeof(buffer), "vm_takeover_slot_%04u", slot_id);
    return std::string(buffer);
}

static bool validate_vmengine_export_naming_rules(const std::vector<std::string>& input_exports,
                                                  std::string* error) {
    // 规则：
    // 1) C 导出：必须以 vm_ 开头；
    // 2) C++ 导出：必须位于 vm namespace（mangled 包含 N2vm）。
    for (const std::string& name : input_exports) {
        if (is_cxx_mangled_symbol(name)) {
            if (!is_vm_namespace_cxx_symbol(name)) {
                if (error) {
                    *error = "invalid vmengine C++ export (must be under vm namespace): " + name;
                }
                return false;
            }
            continue;
        }
        if (name.rfind("vm_", 0) != 0) {
            if (error) {
                *error = "invalid vmengine C export (must start with vm_): " + name;
            }
            return false;
        }
    }
    return true;
}

static const char* dynstr_name_at(const std::vector<uint8_t>& dynstr_bytes, uint32_t off) {
    // 偏移越界直接返回空。
    if (off >= dynstr_bytes.size()) {
        return nullptr;
    }
    // 返回 dynstr 起点 + off 的 C 字符串指针。
    return reinterpret_cast<const char*>(dynstr_bytes.data() + off);
}

static std::vector<uint8_t> build_sysv_hash_payload_from_bytes(const std::vector<Elf64_Sym>& dynsym_symbols,
                                                               const std::vector<uint8_t>& dynstr_bytes) {
    // 空 dynsym 无法构建 hash 表。
    if (dynsym_symbols.empty()) {
        return {};
    }
    // nchain 等于 dynsym 条目数。
    const uint32_t nchain = static_cast<uint32_t>(dynsym_symbols.size());
    // 选择 bucket 数。
    const uint32_t nbucket = choose_bucket_count(nchain);
    // 初始化 bucket/chain。
    std::vector<uint32_t> buckets(nbucket, 0);
    std::vector<uint32_t> chains(nchain, 0);

    // 从 1 开始遍历（跳过 STN_UNDEF）。
    for (uint32_t sym_index = 1; sym_index < nchain; ++sym_index) {
        const Elf64_Sym& sym = dynsym_symbols[sym_index];
        // 解析符号名。
        const char* name = dynstr_name_at(dynstr_bytes, sym.st_name);
        // 空名跳过。
        if (!name || name[0] == '\0') {
            continue;
        }
        // 计算 SYSV hash 并映射 bucket。
        const uint32_t h = elf_sysv_hash(name);
        const uint32_t b = h % nbucket;
        if (buckets[b] == 0) {
            buckets[b] = sym_index;
            continue;
        }
        uint32_t cursor = buckets[b];
        while (chains[cursor] != 0) {
            cursor = chains[cursor];
        }
        chains[cursor] = sym_index;
    }

    // 输出格式：[nbucket, nchain, buckets..., chains...]
    std::vector<uint8_t> payload;
    payload.resize(static_cast<size_t>(2 + nbucket + nchain) * sizeof(uint32_t));
    uint32_t* out = reinterpret_cast<uint32_t*>(payload.data());
    out[0] = nbucket;
    out[1] = nchain;
    std::memcpy(out + 2, buckets.data(), static_cast<size_t>(nbucket) * sizeof(uint32_t));
    std::memcpy(out + 2 + nbucket, chains.data(), static_cast<size_t>(nchain) * sizeof(uint32_t));
    return payload;
}

static uint32_t elf_gnu_hash(const char* name) {
    // 空字符串返回 0。
    if (!name) {
        return 0;
    }
    // GNU hash 初值。
    uint32_t h = 5381U;
    // djb2 变体迭代。
    while (*name) {
        h = (h << 5) + h + static_cast<uint8_t>(*name++);
    }
    return h;
}

static std::vector<uint8_t> build_gnu_hash_payload_from_bytes(const std::vector<Elf64_Sym>& dynsym_symbols,
                                                              const std::vector<uint8_t>& dynstr_bytes) {
    // 仅保留 STN_UNDEF 时没有可哈希符号。
    if (dynsym_symbols.size() <= 1) {
        return {};
    }

    const uint32_t nchain = static_cast<uint32_t>(dynsym_symbols.size());
    const uint32_t symoffset = 1;
    // patchbay 模式保持 dynsym 原顺序，仅在末尾追加 alias。
    // 为避免“按 GNU hash 规则重排符号”带来的连锁风险，这里固定单 bucket，
    // 让 chain 覆盖 [symoffset, nchain) 连续区间，确保所有符号可达。
    const uint32_t nbuckets = 1;
    const uint32_t bloom_size = 1;
    const uint32_t bloom_shift = 6;

    // bloom/bucket/chain 三块分别对应 GNU hash 三段结构。
    std::vector<uint64_t> bloom(bloom_size, 0);
    std::vector<uint32_t> buckets(nbuckets, 0);
    std::vector<uint32_t> chain(nchain > symoffset ? (nchain - symoffset) : 0, 0);
    std::vector<uint32_t> last_in_bucket(nbuckets, 0);

    // 第一遍：构建 bucket + bloom + last_in_bucket。
    for (uint32_t idx = symoffset; idx < nchain; ++idx) {
        const Elf64_Sym& sym = dynsym_symbols[idx];
        const char* name = dynstr_name_at(dynstr_bytes, sym.st_name);
        if (!name || name[0] == '\0') {
            continue;
        }
        const uint32_t h = elf_gnu_hash(name);
        const uint32_t b = h % nbuckets;
        if (buckets[b] == 0) {
            // 记录桶内第一个符号索引。
            buckets[b] = idx;
        }
        last_in_bucket[b] = idx;
        const uint32_t word = (h / 64U) % bloom_size;
        const uint32_t bit1 = h % 64U;
        const uint32_t bit2 = (h >> bloom_shift) % 64U;
        bloom[word] |= (1ULL << bit1) | (1ULL << bit2);
    }

    // 第二遍：填 chain（最后一个元素置最低位 1）。
    for (uint32_t idx = symoffset; idx < nchain; ++idx) {
        const Elf64_Sym& sym = dynsym_symbols[idx];
        const char* name = dynstr_name_at(dynstr_bytes, sym.st_name);
        if (!name || name[0] == '\0') {
            continue;
        }
        const uint32_t h = elf_gnu_hash(name);
        const uint32_t b = h % nbuckets;
        const uint32_t chain_idx = idx - symoffset;
        uint32_t val = h & ~1U;
        if (idx == last_in_bucket[b]) {
            // 桶内最后一个 chain 元素最低位标 1。
            val |= 1U;
        }
        if (chain_idx < chain.size()) {
            chain[chain_idx] = val;
        }
    }

    // 序列化输出：header(4*u32) + bloom + buckets + chain。
    std::vector<uint8_t> payload;
    payload.resize(sizeof(uint32_t) * 4 +
                   sizeof(uint64_t) * bloom.size() +
                   sizeof(uint32_t) * buckets.size() +
                   sizeof(uint32_t) * chain.size());

    uint8_t* out = payload.data();
    auto write_u32 = [&out](uint32_t v) {
        // 按小端机器字节序原样写入 u32。
        std::memcpy(out, &v, sizeof(uint32_t));
        out += sizeof(uint32_t);
    };
    write_u32(nbuckets);
    write_u32(symoffset);
    write_u32(static_cast<uint32_t>(bloom.size()));
    write_u32(bloom_shift);
    std::memcpy(out, bloom.data(), bloom.size() * sizeof(uint64_t));
    out += bloom.size() * sizeof(uint64_t);
    std::memcpy(out, buckets.data(), buckets.size() * sizeof(uint32_t));
    out += buckets.size() * sizeof(uint32_t);
    if (!chain.empty()) {
        std::memcpy(out, chain.data(), chain.size() * sizeof(uint32_t));
    }
    return payload;
}

static bool validate_elf_tables_for_android(const std::vector<uint8_t>& file_bytes, std::string* error) {
    // 至少要有 ELF64 头。
    if (file_bytes.size() < sizeof(Elf64_Ehdr)) {
        if (error) {
            *error = "output image too small for ELF header";
        }
        return false;
    }
    // 直接视图解释 ELF 头。
    const auto* ehdr = reinterpret_cast<const Elf64_Ehdr*>(file_bytes.data());

    // 校验 program header 表范围与 PT_LOAD 对齐一致性。
    if (ehdr->e_phnum > 0) {
        const uint64_t phdr_table_size = (uint64_t)ehdr->e_phnum * (uint64_t)ehdr->e_phentsize;
        if (ehdr->e_phentsize == 0 || phdr_table_size == 0) {
            if (error) {
                *error = "invalid program header entry size/count";
            }
            return false;
        }
        if (ehdr->e_phoff > file_bytes.size() || phdr_table_size > (file_bytes.size() - (size_t)ehdr->e_phoff)) {
            if (error) {
                *error = "program header table out of range";
            }
            return false;
        }
        const auto* phdrs = reinterpret_cast<const Elf64_Phdr*>(file_bytes.data() + ehdr->e_phoff);
        for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
            const Elf64_Phdr& ph = phdrs[i];
            if (ph.p_type != PT_LOAD || ph.p_align <= 1) {
                continue;
            }
            if ((ph.p_offset % ph.p_align) != (ph.p_vaddr % ph.p_align)) {
                if (error) {
                    *error = "PT_LOAD alignment congruence broken";
                }
                return false;
            }
        }
    }

    // 校验 section header 表范围与对齐。
    if (ehdr->e_shnum > 0) {
        const uint64_t shdr_table_size = (uint64_t)ehdr->e_shnum * (uint64_t)ehdr->e_shentsize;
        if (ehdr->e_shentsize == 0 || shdr_table_size == 0) {
            if (error) {
                *error = "invalid section header entry size/count";
            }
            return false;
        }
        if (ehdr->e_shoff == 0) {
            if (error) {
                *error = "section header table offset is zero";
            }
            return false;
        }
        constexpr uint64_t kAndroidShdrAlign = sizeof(Elf64_Addr);
        if ((ehdr->e_shoff % kAndroidShdrAlign) != 0) {
            if (error) {
                *error = "section header table offset is not 8-byte aligned";
            }
            return false;
        }
        if (ehdr->e_shoff > file_bytes.size() || shdr_table_size > (file_bytes.size() - (size_t)ehdr->e_shoff)) {
            if (error) {
                *error = "section header table out of range";
            }
            return false;
        }
    }
    // 结构检查通过。
    return true;
}

static bool try_export_alias_symbols_patchbay(const zElf& elf,
                                              const char* input_path,
                                              const char* output_path,
                                              const zDynamicSection* dynamic_sec,
                                              const std::vector<uint8_t>& new_dynsym_bytes,
                                              const std::vector<uint8_t>& new_dynstr,
                                              const std::vector<uint8_t>& new_versym,
                                              const std::vector<uint8_t>& new_gnu_hash,
                                              const std::vector<uint8_t>& new_sysv_hash,
                                              uint32_t slot_used_hint,
                                              bool allow_validate_fail,
                                              bool* handled,
                                              std::string* error) {
    // 默认“未处理”，除非明确命中 .vmp_patchbay 路径。
    if (handled) {
        *handled = false;
    }
    // 基础入参校验。
    if (!input_path || !output_path || !dynamic_sec) {
        if (error) {
            *error = "invalid patchbay arguments";
        }
        return false;
    }

    // 只有存在 .vmp_patchbay 节时才走 patchbay 快速改写路径。
    const auto& sht = elf.sectionHeaderModel();
    const int patchbay_idx = sht.findByName(".vmp_patchbay");
    if (patchbay_idx < 0) {
        // 返回 true 表示“此路径未命中但不是错误”，上层可尝试其它策略。
        return true;
    }
    if (handled) {
        *handled = true;
    }

    // 读取 patchbay 节元信息。
    const zSectionTableElement* patchbay = sht.get((size_t)patchbay_idx);
    if (!patchbay) {
        if (error) {
            *error = "patchbay section is null";
        }
        return false;
    }
    if (patchbay->size < sizeof(PatchBayHeader)) {
        if (error) {
            *error = "patchbay section too small";
        }
        return false;
    }

    // 读入输入文件原始字节，后续在内存中原地 patch。
    std::vector<uint8_t> new_file;
    if (!load_file_bytes(input_path, &new_file)) {
        if (error) {
            *error = "failed to read input bytes";
        }
        return false;
    }
    // patchbay 节在文件中必须完整可寻址。
    if (patchbay->offset > new_file.size() || patchbay->size > (new_file.size() - (size_t)patchbay->offset)) {
        if (error) {
            *error = "patchbay section range out of file";
        }
        return false;
    }

    // 解释 patchbay header。
    auto* patch_hdr = reinterpret_cast<PatchBayHeader*>(new_file.data() + patchbay->offset);
    // 校验 magic/version。
    if (patch_hdr->magic != kPatchBayMagic || patch_hdr->version != kPatchBayVersion) {
        if (error) {
            *error = "patchbay header magic/version mismatch";
        }
        return false;
    }
    // 校验 header_size 与 total_size。
    if (patch_hdr->header_size < sizeof(PatchBayHeader) || patch_hdr->total_size > patchbay->size) {
        if (error) {
            *error = "patchbay header size/capacity invalid";
        }
        return false;
    }

    // 校验每个 region 的 off/cap 都在 patchbay 范围内。
    auto check_region = [patch_hdr, patchbay](uint32_t off, uint32_t cap, const char* name, std::string* region_error) {
        if (cap == 0) {
            return true;
        }
        if (off < patch_hdr->header_size) {
            if (region_error) {
                *region_error = std::string(name) + " off before header";
            }
            return false;
        }
        const uint64_t end = (uint64_t)off + (uint64_t)cap;
        if (end > patch_hdr->total_size || end > patchbay->size) {
            if (region_error) {
                *region_error = std::string(name) + " range out of patchbay";
            }
            return false;
        }
        return true;
    };

    std::string region_error;
    if (!check_region(patch_hdr->dynsym_off, patch_hdr->dynsym_cap, "dynsym", &region_error) ||
        !check_region(patch_hdr->dynstr_off, patch_hdr->dynstr_cap, "dynstr", &region_error) ||
        !check_region(patch_hdr->gnuhash_off, patch_hdr->gnuhash_cap, "gnu_hash", &region_error) ||
        !check_region(patch_hdr->versym_off, patch_hdr->versym_cap, "versym", &region_error) ||
        !check_region(patch_hdr->sysvhash_off, patch_hdr->sysvhash_cap, "sysv_hash", &region_error)) {
        if (error) {
            *error = "patchbay layout invalid: " + region_error;
        }
        return false;
    }

    // 新 payload 不能超过 patchbay 预留容量。
    if (new_dynsym_bytes.size() > patch_hdr->dynsym_cap ||
        new_dynstr.size() > patch_hdr->dynstr_cap ||
        new_gnu_hash.size() > patch_hdr->gnuhash_cap ||
        new_versym.size() > patch_hdr->versym_cap ||
        (!new_sysv_hash.empty() && new_sysv_hash.size() > patch_hdr->sysvhash_cap)) {
        if (error) {
            *error = "patchbay capacity exceeded";
        }
        return false;
    }

    // 通用写区函数：先拷贝 payload，再把剩余容量清零。
    auto write_region = [&new_file, patchbay](uint32_t off, uint32_t cap, const std::vector<uint8_t>& payload) {
        const size_t abs_off = (size_t)(patchbay->offset + off);
        if (!payload.empty()) {
            std::memcpy(new_file.data() + abs_off, payload.data(), payload.size());
        }
        if (cap > payload.size()) {
            std::memset(new_file.data() + abs_off + payload.size(), 0, cap - payload.size());
        }
    };

    // 回写 dynsym/dynstr/hash/versym 等区域。
    write_region(patch_hdr->dynsym_off, patch_hdr->dynsym_cap, new_dynsym_bytes);
    write_region(patch_hdr->dynstr_off, patch_hdr->dynstr_cap, new_dynstr);
    write_region(patch_hdr->gnuhash_off, patch_hdr->gnuhash_cap, new_gnu_hash);
    write_region(patch_hdr->versym_off, patch_hdr->versym_cap, new_versym);
    if (!new_sysv_hash.empty() && patch_hdr->sysvhash_cap > 0) {
        write_region(patch_hdr->sysvhash_off, patch_hdr->sysvhash_cap, new_sysv_hash);
    }

    // 计算绝对文件偏移（用于 section header patch）。
    const uint64_t dynsym_abs_off = patchbay->offset + patch_hdr->dynsym_off;
    const uint64_t dynstr_abs_off = patchbay->offset + patch_hdr->dynstr_off;
    const uint64_t gnu_hash_abs_off = patchbay->offset + patch_hdr->gnuhash_off;
    const uint64_t versym_abs_off = patchbay->offset + patch_hdr->versym_off;
    const uint64_t sysv_hash_abs_off = patchbay->offset + patch_hdr->sysvhash_off;

    // 计算运行时虚拟地址（用于 DT_* 指针更新）。
    const uint64_t dynsym_abs_vaddr = patchbay->addr + patch_hdr->dynsym_off;
    const uint64_t dynstr_abs_vaddr = patchbay->addr + patch_hdr->dynstr_off;
    const uint64_t gnu_hash_abs_vaddr = patchbay->addr + patch_hdr->gnuhash_off;
    const uint64_t versym_abs_vaddr = patchbay->addr + patch_hdr->versym_off;
    const uint64_t sysv_hash_abs_vaddr = patchbay->addr + patch_hdr->sysvhash_off;

    // 复制一份动态段条目，准备修改 DT_* 指针。
    std::vector<Elf64_Dyn> dyn_entries = dynamic_sec->entries;
    auto get_dyn_ptr = [&dyn_entries](Elf64_Sxword tag, Elf64_Xword* out) -> bool {
        if (!out) {
            return false;
        }
        for (const Elf64_Dyn& ent : dyn_entries) {
            if (ent.d_tag == tag) {
                // d_un.d_ptr / d_un.d_val 在这里按地址语义处理。
                *out = ent.d_un.d_ptr;
                return true;
            }
        }
        return false;
    };
    auto set_dyn_ptr = [&dyn_entries](Elf64_Sxword tag, Elf64_Xword value) -> bool {
        for (Elf64_Dyn& ent : dyn_entries) {
            if (ent.d_tag == tag) {
                ent.d_un.d_ptr = value;
                return true;
            }
        }
        // 没有该 tag 时返回 false，由上层决定是否报错。
        return false;
    };

    // 记录旧 DT 值（首次 patch 时写入 orig_* 字段留痕）。
    Elf64_Xword old_symtab = 0;
    Elf64_Xword old_strtab = 0;
    Elf64_Xword old_gnuhash = 0;
    Elf64_Xword old_hash = 0;
    Elf64_Xword old_versym = 0;
    get_dyn_ptr(DT_SYMTAB, &old_symtab);
    get_dyn_ptr(DT_STRTAB, &old_strtab);
    get_dyn_ptr(DT_GNU_HASH, &old_gnuhash);
    get_dyn_ptr(DT_HASH, &old_hash);
    get_dyn_ptr(DT_VERSYM, &old_versym);

    // 更新动态段关键指针，让 loader 指向 patchbay 中的新表。
    if (!set_dyn_ptr(DT_SYMTAB, (Elf64_Xword)dynsym_abs_vaddr) ||
        !set_dyn_ptr(DT_STRTAB, (Elf64_Xword)dynstr_abs_vaddr) ||
        !set_dyn_ptr(DT_STRSZ, (Elf64_Xword)new_dynstr.size()) ||
        !set_dyn_ptr(DT_SYMENT, sizeof(Elf64_Sym)) ||
        !set_dyn_ptr(DT_GNU_HASH, (Elf64_Xword)gnu_hash_abs_vaddr) ||
        !set_dyn_ptr(DT_VERSYM, (Elf64_Xword)versym_abs_vaddr)) {
        if (error) {
            *error = "required DT_* tag missing for patchbay";
        }
        return false;
    }
    // 若存在 sysv hash 容量，则一并更新 DT_HASH。
    if (!new_sysv_hash.empty() && patch_hdr->sysvhash_cap > 0) {
        set_dyn_ptr(DT_HASH, (Elf64_Xword)sysv_hash_abs_vaddr);
    }

    // 把更新后的 dynamic 条目序列化成字节。
    std::vector<uint8_t> dyn_bytes(dyn_entries.size() * sizeof(Elf64_Dyn), 0);
    if (!dyn_bytes.empty()) {
        std::memcpy(dyn_bytes.data(), dyn_entries.data(), dyn_bytes.size());
    }
    if (dynamic_sec->offset + dyn_bytes.size() > new_file.size()) {
        if (error) {
            *error = "dynamic section patch range out of file";
        }
        return false;
    }
    // 回写 .dynamic 区域。
    std::memcpy(new_file.data() + dynamic_sec->offset, dyn_bytes.data(), dyn_bytes.size());

    // 下面补丁 ELF 头中的 section header 信息，保证工具链一致性。
    if (new_file.size() < sizeof(Elf64_Ehdr)) {
        if (error) {
            *error = "output image too small";
        }
        return false;
    }
    auto* ehdr = reinterpret_cast<Elf64_Ehdr*>(new_file.data());
    if (ehdr->e_shnum > 0) {
        const uint64_t shdr_size = (uint64_t)ehdr->e_shnum * (uint64_t)ehdr->e_shentsize;
        if (ehdr->e_shoff == 0 || ehdr->e_shoff + shdr_size > new_file.size()) {
            if (error) {
                *error = "section headers out of range";
            }
            return false;
        }
        auto* shdrs = reinterpret_cast<Elf64_Shdr*>(new_file.data() + ehdr->e_shoff);
        const int dynsym_idx = sht.findByName(".dynsym");
        const int dynstr_idx = sht.findByName(".dynstr");
        const int versym_idx = sht.findByName(".gnu.version");
        const int gnu_hash_idx = sht.findByName(".gnu.hash");
        const int hash_idx = sht.findByName(".hash");

        auto patch_shdr = [&shdrs](int idx) -> Elf64_Shdr* {
            // idx<0 代表节不存在，返回 null。
            return idx >= 0 ? &shdrs[idx] : nullptr;
        };

        // 更新 .dynsym
        if (auto* sh = patch_shdr(dynsym_idx)) {
            sh->sh_offset = (Elf64_Off)dynsym_abs_off;
            sh->sh_addr = (Elf64_Addr)dynsym_abs_vaddr;
            sh->sh_size = (Elf64_Xword)new_dynsym_bytes.size();
            sh->sh_entsize = sizeof(Elf64_Sym);
            sh->sh_link = (Elf64_Word)dynstr_idx;
            sh->sh_info = 1;
        }
        // 更新 .dynstr
        if (auto* sh = patch_shdr(dynstr_idx)) {
            sh->sh_offset = (Elf64_Off)dynstr_abs_off;
            sh->sh_addr = (Elf64_Addr)dynstr_abs_vaddr;
            sh->sh_size = (Elf64_Xword)new_dynstr.size();
        }
        // 更新 .gnu.version
        if (auto* sh = patch_shdr(versym_idx)) {
            sh->sh_offset = (Elf64_Off)versym_abs_off;
            sh->sh_addr = (Elf64_Addr)versym_abs_vaddr;
            sh->sh_size = (Elf64_Xword)new_versym.size();
            sh->sh_entsize = 2;
            sh->sh_link = (Elf64_Word)dynsym_idx;
        }
        // 更新 .gnu.hash
        if (auto* sh = patch_shdr(gnu_hash_idx)) {
            sh->sh_offset = (Elf64_Off)gnu_hash_abs_off;
            sh->sh_addr = (Elf64_Addr)gnu_hash_abs_vaddr;
            sh->sh_size = (Elf64_Xword)new_gnu_hash.size();
            sh->sh_link = (Elf64_Word)dynsym_idx;
            sh->sh_addralign = 8;
        }
        // 可选更新 .hash（若存在且新 payload 非空）。
        if (hash_idx >= 0 && !new_sysv_hash.empty() && patch_hdr->sysvhash_cap > 0) {
            if (auto* sh = patch_shdr(hash_idx)) {
                sh->sh_offset = (Elf64_Off)sysv_hash_abs_off;
                sh->sh_addr = (Elf64_Addr)sysv_hash_abs_vaddr;
                sh->sh_size = (Elf64_Xword)new_sysv_hash.size();
                sh->sh_entsize = sizeof(uint32_t);
                sh->sh_link = (Elf64_Word)dynsym_idx;
                sh->sh_addralign = 4;
            }
        }
    }

    // 重新拿 patch_hdr 指针（防止上文操作后编译器别名优化问题）。
    patch_hdr = reinterpret_cast<PatchBayHeader*>(new_file.data() + patchbay->offset);
    // 首次 patch 时回填原始 DT 指针快照。
    if (patch_hdr->orig_dt_symtab == 0) {
        patch_hdr->orig_dt_symtab = old_symtab;
    }
    if (patch_hdr->orig_dt_strtab == 0) {
        patch_hdr->orig_dt_strtab = old_strtab;
    }
    if (patch_hdr->orig_dt_gnu_hash == 0) {
        patch_hdr->orig_dt_gnu_hash = old_gnuhash;
    }
    if (patch_hdr->orig_dt_hash == 0) {
        patch_hdr->orig_dt_hash = old_hash;
    }
    if (patch_hdr->orig_dt_versym == 0) {
        patch_hdr->orig_dt_versym = old_versym;
    }
    patch_hdr->used_dynsym = (uint32_t)new_dynsym_bytes.size();
    patch_hdr->used_dynstr = (uint32_t)new_dynstr.size();
    patch_hdr->used_gnuhash = (uint32_t)new_gnu_hash.size();
    patch_hdr->used_sysvhash = (uint32_t)new_sysv_hash.size();
    patch_hdr->used_versym = (uint32_t)new_versym.size();
    // 更新 takeover 槽位计数与位图。
    if (patch_hdr->takeover_slot_total > 0) {
        uint32_t slot_used = patch_hdr->takeover_slot_used;
        if (slot_used == 0 || slot_used > patch_hdr->takeover_slot_total) {
            slot_used = std::min<uint32_t>(patch_hdr->takeover_slot_total, slot_used_hint);
        }
        patch_hdr->takeover_slot_used = std::min<uint32_t>(slot_used, patch_hdr->takeover_slot_total);
        const uint32_t lo_count = std::min<uint32_t>(patch_hdr->takeover_slot_used, 64U);
        const uint32_t hi_count = patch_hdr->takeover_slot_used > 64U
                                  ? std::min<uint32_t>(patch_hdr->takeover_slot_used - 64U, 64U)
                                  : 0U;
        patch_hdr->takeover_slot_bitmap_lo = bitmask_for_count_u32(lo_count);
        patch_hdr->takeover_slot_bitmap_hi = bitmask_for_count_u32(hi_count);
    } else {
        patch_hdr->takeover_slot_used = 0;
        patch_hdr->takeover_slot_bitmap_lo = 0;
        patch_hdr->takeover_slot_bitmap_hi = 0;
    }
    // 标记“已写入新表/已更新 dynamic”。
    patch_hdr->flags |= 0x1U;
    patch_hdr->flags |= 0x2U;
    // 先清零，再重算 CRC。
    patch_hdr->crc32 = 0;

    std::string layout_error;
    uint32_t computed_crc = 0;
    // 基于“header(清零crc)+used子区”重算 crc32。
    if (!compute_patchbay_crc_from_file(new_file, patchbay->offset, *patch_hdr, &computed_crc, &layout_error)) {
        if (error) {
            *error = layout_error;
        }
        return false;
    }
    // 回填 CRC。
    patch_hdr->crc32 = computed_crc;

    // Android 关注的 ELF 布局一致性校验。
    if (!validate_elf_tables_for_android(new_file, &layout_error)) {
        if (error) {
            *error = "patchbay output layout invalid: " + layout_error;
        }
        return false;
    }
    // 保存输出文件。
    if (!save_file_bytes(output_path, new_file)) {
        if (error) {
            *error = "failed to write output file";
        }
        return false;
    }

    // 重新加载并执行工具内 validate。
    zElf patched(output_path);
    if (!patched.isLoaded()) {
        if (error) {
            *error = "failed to reload output elf";
        }
        return false;
    }
    std::string validate_error;
    if (!patched.validate(&validate_error)) {
        // allow_validate_fail 为 true 时仅告警不失败。
        if (!allow_validate_fail) {
            if (error) {
                *error = "validate failed: " + validate_error;
            }
            return false;
        }
        LOGW("patchbay validate warning: %s", validate_error.c_str());
    }
    LOGI("patchbay patch success: dynsym=%zu dynstr=%zu gnuhash=%zu sysvhash=%zu versym=%zu",
         new_dynsym_bytes.size(),
         new_dynstr.size(),
         new_gnu_hash.size(),
         new_sysv_hash.size(),
         new_versym.size());
    return true;
}

static bool export_alias_symbols_patchbay(const char* input_path,
                                          const char* output_path,
                                          const std::vector<AliasPair>& alias_pairs,
                                          bool allow_validate_fail,
                                          std::string* error) {
    // 入参校验：输入输出路径与别名列表都必须有效。
    if (!input_path || !output_path || alias_pairs.empty()) {
        if (error) {
            *error = "invalid input/output/alias list";
        }
        return false;
    }

    // 加载输入 ELF。
    zElf elf(input_path);
    if (!elf.isLoaded()) {
        if (error) {
            *error = "failed to load input elf";
        }
        return false;
    }

    // 获取必须节：dynsym/dynstr/versym/gnu.hash/dynamic。
    const auto* dynsym_sec = dynamic_cast<const zSymbolSection*>(elf.findSectionByName(".dynsym"));
    const auto* dynstr_sec = dynamic_cast<const zStrTabSection*>(elf.findSectionByName(".dynstr"));
    const auto* versym_sec = elf.findSectionByName(".gnu.version");
    const auto* gnu_hash_sec = elf.findSectionByName(".gnu.hash");
    const auto* dynamic_sec = dynamic_cast<const zDynamicSection*>(elf.findSectionByName(".dynamic"));
    const auto* hash_sec = elf.findSectionByName(".hash");
    if (!dynsym_sec || !dynstr_sec || !versym_sec || !gnu_hash_sec || !dynamic_sec) {
        if (error) {
            *error = "required sections missing (.dynsym/.dynstr/.gnu.version/.gnu.hash/.dynamic)";
        }
        return false;
    }
    // .gnu.version 必须按 2 字节对齐（Elf64_Half 数组）。
    if ((versym_sec->payload.size() % 2U) != 0U) {
        if (error) {
            *error = ".gnu.version size is not 2-byte aligned";
        }
        return false;
    }

    // 拷贝可修改副本。
    std::vector<Elf64_Sym> new_dynsym = dynsym_sec->symbols;
    std::vector<uint8_t> new_dynstr = dynstr_sec->payload;
    std::vector<uint8_t> new_versym = versym_sec->payload;
    // 先收集已有导出名，避免重复追加。
    std::unordered_set<std::string> existing_names;
    existing_names.reserve(new_dynsym.size() + alias_pairs.size());
    for (const Elf64_Sym& sym : dynsym_sec->symbols) {
        if (sym.st_name == 0) {
            continue;
        }
        const char* name = dynstr_sec->getStringAt(sym.st_name);
        if (!name || name[0] == '\0') {
            continue;
        }
        existing_names.insert(name);
    }

    // 统计信息：追加数量与跳过数量。
    uint32_t appended = 0;
    constexpr uint32_t kLogDetailLimit = 16;
    // 逐条处理 alias 对。
    for (const AliasPair& pair : alias_pairs) {
        // 同名导出视为硬错误：不允许“合并/覆盖”历史行为。
        if (existing_names.find(pair.export_name) != existing_names.end()) {
            if (error) {
                *error = "duplicate export detected (merge is forbidden): " + pair.export_name;
            }
            return false;
        }

        // 解析实现符号。
        FullSymbolInfo impl{};
        if (!resolve_impl_symbol(elf, pair.impl_name.c_str(), &impl) || !impl.found || impl.value == 0) {
            if (error) {
                *error = "impl symbol not found or invalid: " + pair.impl_name;
            }
            return false;
        }

        // 追加导出名到 dynstr，记录偏移供 st_name 使用。
        const uint32_t name_off = static_cast<uint32_t>(new_dynstr.size());
        new_dynstr.insert(new_dynstr.end(), pair.export_name.begin(), pair.export_name.end());
        new_dynstr.push_back('\0');

        // 追加 dynsym 条目：名字是 export_name，地址/尺寸来自 impl。
        Elf64_Sym sym{};
        sym.st_name = name_off;
        sym.st_info = static_cast<unsigned char>(((STB_GLOBAL & 0x0f) << 4) |
                                                 ((impl.type == STT_NOTYPE ? STT_FUNC : impl.type) & 0x0f));
        sym.st_other = 0;
        sym.st_shndx = impl.shndx;
        sym.st_value = impl.value;
        // slot/key 模式下把 key（donor st_value）写入 st_size，供运行时恢复 slot->fun_addr。
        sym.st_size = (pair.export_key != 0) ? static_cast<Elf64_Xword>(pair.export_key) : impl.size;
        new_dynsym.push_back(sym);

        // 同步追加版本条目（默认版本 1）。
        new_versym.push_back(1);
        new_versym.push_back(0);

        existing_names.insert(pair.export_name);
        ++appended;
        if (appended <= kLogDetailLimit) {
            LOGI("Append dyn export alias(patchbay): %s -> %s (addr=0x%llx key=0x%llx)",
                 pair.export_name.c_str(),
                 pair.impl_name.c_str(),
                 static_cast<unsigned long long>(impl.value),
                 static_cast<unsigned long long>(pair.export_key));
        }
    }

    LOGI("patchbay alias summary: requested=%zu appended=%u",
         alias_pairs.size(),
         appended);
    if (appended == 0) {
        if (error) {
            *error = "no new aliases were appended";
        }
        return false;
    }

    // 序列化新 dynsym。
    std::vector<uint8_t> new_dynsym_bytes(new_dynsym.size() * sizeof(Elf64_Sym));
    std::memcpy(new_dynsym_bytes.data(), new_dynsym.data(), new_dynsym_bytes.size());
    // 重建 gnu hash。
    std::vector<uint8_t> new_gnu_hash = build_gnu_hash_payload_from_bytes(new_dynsym, new_dynstr);
    if (new_gnu_hash.empty()) {
        if (error) {
            *error = "failed to build .gnu.hash payload";
        }
        return false;
    }
    // 若存在 .hash，重建 sysv hash。
    std::vector<uint8_t> new_sysv_hash;
    if (hash_sec) {
        new_sysv_hash = build_sysv_hash_payload_from_bytes(new_dynsym, new_dynstr);
        if (new_sysv_hash.empty()) {
            if (error) {
                *error = "failed to build .hash payload";
            }
            return false;
        }
    }

    // 优先尝试 patchbay 原地改写路径。
    bool handled_by_patchbay = false;
    if (!try_export_alias_symbols_patchbay(elf,
                                           input_path,
                                           output_path,
                                           dynamic_sec,
                                           new_dynsym_bytes,
                                           new_dynstr,
                                           new_versym,
                                           new_gnu_hash,
                                           new_sysv_hash,
                                           appended,
                                           allow_validate_fail,
                                           &handled_by_patchbay,
                                           error)) {
        return false;
    }
    // 若已由 patchbay 路径完成，直接成功返回。
    if (handled_by_patchbay) {
        return true;
    }

    // 当前版本已移除 legacy minimal injection 路径。
    if (error) {
        *error = "no .vmp_patchbay found; legacy minimal injection removed";
    }
    return false;
}

// 读取整文件字节。
static bool load_file_bytes(const char* path, std::vector<uint8_t>* out) {
    // 入参校验。
    if (!path || !out) {
        return false;
    }
    // 二进制只读打开文件。
    FILE* fp = std::fopen(path, "rb");
    if (!fp) {
        return false;
    }
    // 定位到文件尾获取总长度。
    if (std::fseek(fp, 0, SEEK_END) != 0) {
        std::fclose(fp);
        return false;
    }
    const long size = std::ftell(fp);
    // ftell 失败会返回负值。
    if (size < 0) {
        std::fclose(fp);
        return false;
    }
    // 回到文件起始位置准备读取。
    if (std::fseek(fp, 0, SEEK_SET) != 0) {
        std::fclose(fp);
        return false;
    }
    // 分配输出缓冲。
    out->assign((size_t)size, 0);
    // 一次性读取全部字节。
    const size_t nread = std::fread(out->data(), 1, out->size(), fp);
    std::fclose(fp);
    // 只有读满才算成功。
    return nread == out->size();
}

// 覆盖写回整文件字节。
static bool save_file_bytes(const char* path, const std::vector<uint8_t>& bytes) {
    // 路径不能为空。
    if (!path) {
        return false;
    }
    // 二进制写入模式打开（覆盖）。
    FILE* fp = std::fopen(path, "wb");
    if (!fp) {
        return false;
    }
    // 一次性写出全部字节。
    const size_t written = std::fwrite(bytes.data(), 1, bytes.size(), fp);
    std::fclose(fp);
    // 写满才成功。
    return written == bytes.size();
}

bool vmprotect_is_patchbay_command(const char* raw_cmd) {
    // 空命令不是 patchbay 子命令。
    if (raw_cmd == nullptr || raw_cmd[0] == '\0') {
        return false;
    }
    // 转成 std::string 便于比较。
    const std::string cmd(raw_cmd);
    // 当前仅支持生产链路使用的子命令。
    return cmd == "export_alias_from_patchbay";
}

int vmprotect_patchbay_entry(int argc, char* argv[]) {
    // 至少要有程序名 + 子命令。
    if (argc < 2) {
        const char* exe_name = (argc > 0 && argv && argv[0]) ? argv[0] : "VmProtect.exe";
        print_usage(exe_name);
        return 1;
    }

    const std::string cmd(argv[1]);

    if (cmd == "export_alias_from_patchbay") {
        // 语法：export_alias_from_patchbay <input> <donor> <output> <impl> [opts]
        if (argc < 6) {
            print_usage(argv[0]);
            return 1;
        }
        bool allow_validate_fail = false;
        bool only_fun_java = false;
        // 解析可选参数。
        for (int i = 6; i < argc; ++i) {
            if (std::strcmp(argv[i], "--allow-validate-fail") == 0) {
                allow_validate_fail = true;
                continue;
            }
            if (std::strcmp(argv[i], "--only-fun-java") == 0) {
                only_fun_java = true;
                continue;
            }
            LOGE("invalid option: %s", argv[i]);
            return 2;
        }

        // 加载 donor ELF 并收集 donor 导出集合。
        zElf donor(argv[3]);
        if (!donor.isLoaded()) {
            LOGE("failed to load donor ELF: %s", argv[3]);
            return 2;
        }
        std::vector<DynamicExportInfo> donor_exports;
        std::string collect_error;
        if (!collect_defined_dynamic_export_infos(donor, &donor_exports, &collect_error)) {
            LOGE("collect donor exports failed: %s", collect_error.empty() ? "(unknown)" : collect_error.c_str());
            return 2;
        }
        // 可选过滤：只保留 fun_* 和 Java_*。
        if (only_fun_java) {
            std::vector<DynamicExportInfo> filtered;
            filtered.reserve(donor_exports.size());
            for (const DynamicExportInfo& info : donor_exports) {
                if (is_fun_or_java_symbol(info.name)) {
                    filtered.push_back(info);
                }
            }
            donor_exports.swap(filtered);
        }
        if (donor_exports.empty()) {
            LOGE("donor has no defined dynamic exports: %s", argv[3]);
            return 2;
        }

        // 加载 input ELF 并收集已有导出。
        zElf input_elf(argv[2]);
        if (!input_elf.isLoaded()) {
            LOGE("failed to load input ELF: %s", argv[2]);
            return 2;
        }
        std::vector<std::string> input_exports;
        if (!collect_defined_dynamic_exports(input_elf, &input_exports, &collect_error)) {
            LOGE("collect input exports failed: %s", collect_error.empty() ? "(unknown)" : collect_error.c_str());
            return 2;
        }
        // 先执行 vmengine 导出命名规则校验，不满足直接终止流程。
        if (!validate_vmengine_export_naming_rules(input_exports, &collect_error)) {
            LOGE("invalid vmengine export naming: %s", collect_error.empty() ? "(unknown)" : collect_error.c_str());
            return 3;
        }

        // 转 set 提升 membership 查询效率。
        std::unordered_set<std::string> input_export_set;
        input_export_set.reserve(input_exports.size());
        for (const std::string& name : input_exports) {
            input_export_set.insert(name);
        }

        // 严格模式：donor 与 vmengine 导出重名即硬错误，直接终止加固。
        std::vector<std::string> duplicate_exports;
        duplicate_exports.reserve(donor_exports.size());
        for (const DynamicExportInfo& export_info : donor_exports) {
            if (input_export_set.find(export_info.name) != input_export_set.end()) {
                duplicate_exports.push_back(export_info.name);
            }
        }
        if (!duplicate_exports.empty()) {
            LOGE("export conflict detected between donor and vmengine: count=%zu", duplicate_exports.size());
            constexpr size_t kDetailLimit = 16;
            for (size_t i = 0; i < duplicate_exports.size() && i < kDetailLimit; ++i) {
                LOGE("conflict export[%zu]: %s", i, duplicate_exports[i].c_str());
            }
            if (duplicate_exports.size() > kDetailLimit) {
                LOGE("... and %zu more conflict exports", duplicate_exports.size() - kDetailLimit);
            }
            return 3;
        }

        // 构建 alias 列表：严格模式下 donor 导出都要补齐到 vmengine。
        std::vector<AliasPair> pairs;
        pairs.reserve(donor_exports.size());
        const bool use_slot_mode = is_takeover_slot_mode_impl(argv[5]);
        for (size_t i = 0; i < donor_exports.size(); ++i) {
            AliasPair pair;
            pair.export_name = donor_exports[i].name;
            pair.impl_name = use_slot_mode
                             ? build_takeover_slot_symbol_name(static_cast<uint32_t>(i))
                             : std::string(argv[5]);
            // key 承载 donor st_value（route4 key 语义）。
            pair.export_key = donor_exports[i].value;
            pairs.push_back(std::move(pair));
        }

        if (use_slot_mode) {
            LOGI("export_alias_from_patchbay slot mode enabled: slot_prefix=%s slot_needed=%zu",
                 argv[5],
                 pairs.size());
        }

        LOGI("export_alias_from_patchbay start: donor_exports=%zu input_exports=%zu to_append=%zu impl=%s only_fun_java=%d",
             donor_exports.size(),
             input_exports.size(),
             pairs.size(),
             argv[5],
             only_fun_java ? 1 : 0);

        // 有缺失导出时执行实际 patch。
        std::string patch_error;
        if (!export_alias_symbols_patchbay(argv[2], argv[4], pairs, allow_validate_fail, &patch_error)) {
            LOGE("export_alias_from_patchbay failed: %s", patch_error.empty() ? "(unknown)" : patch_error.c_str());
            return 3;
        }
        LOGI("export_alias_from_patchbay success: %s + %s -> %s (impl=%s)",
             argv[2],
             argv[3],
             argv[4],
             argv[5]);
        return 0;
    }

    // 未知子命令：打印帮助并返回参数错误。
    print_usage(argv[0]);
    return 1;
}
