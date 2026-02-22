/**
 * @file main.cpp
 * @brief 命令入口与示例流程。
 *
 * 该文件主要承担两类职责：
 * 1) 提供若干 demo/调试命令（merge_elf / patch_demo4 / validate 等）；
 * 2) 提供与 AArch64 指令补丁相关的辅助函数（BL 编解码、符号定位等）。
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

static bool file_exists(const std::string& path) {
    FILE* fp = std::fopen(path.c_str(), "rb");
    if (!fp) {
        return false;
    }
    std::fclose(fp);
    return true;
}

// 在当前目录与上级目录中解析 demo 文件路径，便于从不同工作目录执行。
static std::string resolve_demo_path(const char* filename) {
    const std::string direct = filename;
    if (file_exists(direct)) {
        return direct;
    }
    const std::string parent = std::string("..\\") + filename;
    if (file_exists(parent)) {
        return parent;
    }
    return direct;
}

// 打印命令行帮助。
static void print_usage(const char* exe_name) {
    std::printf("Usage:\n");
    std::printf("  %s fun_for_add\n", exe_name);
    std::printf("  %s regress\n", exe_name);
    std::printf("  %s test_step1\n", exe_name);
    std::printf("  %s patch_demo4 [input_demo3] [output_demo4]\n", exe_name);
    std::printf("  %s layout <elf_path>\n", exe_name);
    std::printf("  %s validate <elf_path>\n", exe_name);
    std::printf("  %s patchbay_info <elf_path>\n", exe_name);
    std::printf("  %s inject <target_elf> <donor_elf> <output_elf>\n", exe_name);
    std::printf("  %s relocate_pht <elf_path> <extra_entries> <output_elf>\n", exe_name);
    std::printf("  %s export_alias_patchbay <input_elf> <output_elf> [--allow-validate-fail] <export=impl> [export=impl ...]\n", exe_name);
    std::printf("  %s export_alias_from_patchbay <input_elf> <donor_elf> <output_elf> <impl_symbol> [--allow-validate-fail] [--only-fun-java]\n", exe_name);
}

struct SymbolInfo {
    Elf64_Addr value = 0;
    Elf64_Xword size = 0;
};

struct FullSymbolInfo {
    Elf64_Addr value = 0;
    Elf64_Xword size = 0;
    Elf64_Half shndx = SHN_UNDEF;
    unsigned type = STT_NOTYPE;
    bool found = false;
};

struct AliasPair {
    std::string export_name;
    std::string impl_name;
};

// Patch bay header layout is shared with VmEngine/app/src/main/cpp/zPatchBay.h.
#pragma pack(push, 1)
struct PatchBayHeader {
    uint32_t magic;
    uint16_t version;
    uint16_t flags;
    uint32_t total_size;
    uint32_t header_size;
    uint32_t payload_size;
    uint32_t dynsym_off;
    uint32_t dynsym_cap;
    uint32_t dynstr_off;
    uint32_t dynstr_cap;
    uint32_t gnuhash_off;
    uint32_t gnuhash_cap;
    uint32_t sysvhash_off;
    uint32_t sysvhash_cap;
    uint32_t versym_off;
    uint32_t versym_cap;
    uint32_t takeover_slot_total;
    uint32_t takeover_slot_used;
    uint64_t orig_dt_symtab;
    uint64_t orig_dt_strtab;
    uint64_t orig_dt_gnu_hash;
    uint64_t orig_dt_hash;
    uint64_t orig_dt_versym;
    uint32_t used_dynsym;
    uint32_t used_dynstr;
    uint32_t used_gnuhash;
    uint32_t used_sysvhash;
    uint32_t used_versym;
    uint64_t takeover_slot_bitmap_lo;
    uint64_t takeover_slot_bitmap_hi;
    uint32_t crc32;
};
#pragma pack(pop)

static_assert(sizeof(PatchBayHeader) == 148, "PatchBayHeader layout mismatch");
constexpr uint32_t kPatchBayMagic = 0x42504d56U;  // 'VMPB'
constexpr uint16_t kPatchBayVersion = 1;

static uint64_t bitmask_for_count_u32(uint32_t count) {
    if (count == 0) {
        return 0ULL;
    }
    if (count >= 64U) {
        return ~0ULL;
    }
    return (1ULL << count) - 1ULL;
}

static uint32_t crc32_ieee_update(uint32_t crc, const uint8_t* data, size_t size) {
    if (!data || size == 0) {
        return crc;
    }
    uint32_t c = crc;
    for (size_t i = 0; i < size; ++i) {
        c ^= data[i];
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
    if (!out_crc) {
        if (error) {
            *error = "crc output pointer is null";
        }
        return false;
    }
    if (hdr.header_size < sizeof(PatchBayHeader) ||
        hdr.total_size < hdr.header_size ||
        patchbay_off > file_bytes.size() ||
        hdr.total_size > file_bytes.size() - (size_t)patchbay_off) {
        if (error) {
            *error = "patchbay header/section bounds invalid for crc";
        }
        return false;
    }
    if (offsetof(PatchBayHeader, crc32) + sizeof(uint32_t) > hdr.header_size) {
        if (error) {
            *error = "patchbay header too small for crc field";
        }
        return false;
    }

    std::vector<uint8_t> header_blob((size_t)hdr.header_size, 0);
    std::memcpy(header_blob.data(), file_bytes.data() + patchbay_off, header_blob.size());
    std::memset(header_blob.data() + offsetof(PatchBayHeader, crc32), 0, sizeof(uint32_t));

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

    *out_crc = ~crc;
    return true;
}

static bool load_file_bytes(const char* path, std::vector<uint8_t>* out);
static bool save_file_bytes(const char* path, const std::vector<uint8_t>& bytes);

static uint32_t elf_sysv_hash(const char* name) {
    if (!name) {
        return 0;
    }
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
    static const uint32_t primes[] = {
        3, 5, 7, 11, 17, 29, 53, 97, 193, 389, 769, 1543, 3079, 6151,
        12289, 24593, 49157, 98317, 196613, 393241, 786433
    };
    const uint32_t target = (nchain < 8) ? 8U : (nchain / 2U + 1U);
    for (uint32_t p : primes) {
        if (p >= target) {
            return p;
        }
    }
    return primes[sizeof(primes) / sizeof(primes[0]) - 1];
}

static std::vector<uint8_t> build_sysv_hash_payload(const zSymbolSection* dynsym, const zStrTabSection* dynstr) {
    if (!dynsym || !dynstr || dynsym->symbols.empty()) {
        return {};
    }

    const uint32_t nchain = static_cast<uint32_t>(dynsym->symbols.size());
    const uint32_t nbucket = choose_bucket_count(nchain);
    std::vector<uint32_t> buckets(nbucket, 0);
    std::vector<uint32_t> chains(nchain, 0);

    for (uint32_t sym_index = 1; sym_index < nchain; ++sym_index) {
        const Elf64_Sym& sym = dynsym->symbols[sym_index];
        const char* name = dynstr->getStringAt(sym.st_name);
        if (!name || name[0] == '\0') {
            continue;
        }
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

    std::vector<uint8_t> payload;
    payload.resize(static_cast<size_t>(2 + nbucket + nchain) * sizeof(uint32_t));
    uint32_t* out = reinterpret_cast<uint32_t*>(payload.data());
    out[0] = nbucket;
    out[1] = nchain;
    std::memcpy(out + 2, buckets.data(), static_cast<size_t>(nbucket) * sizeof(uint32_t));
    std::memcpy(out + 2 + nbucket, chains.data(), static_cast<size_t>(nchain) * sizeof(uint32_t));
    return payload;
}

static bool parse_alias_pair(const std::string& spec, AliasPair* out_pair) {
    if (!out_pair) {
        return false;
    }
    const size_t pos = spec.find('=');
    if (pos == std::string::npos || pos == 0 || pos + 1 >= spec.size()) {
        return false;
    }
    out_pair->export_name = spec.substr(0, pos);
    out_pair->impl_name = spec.substr(pos + 1);
    return !out_pair->export_name.empty() && !out_pair->impl_name.empty();
}

static bool find_symbol_in_table(const zSymbolSection* symtab,
                                 const zStrTabSection* strtab,
                                 const char* symbol_name,
                                 FullSymbolInfo* out_info) {
    if (!symtab || !strtab || !symbol_name || !out_info) {
        return false;
    }
    for (size_t idx = 0; idx < symtab->symbols.size(); ++idx) {
        const Elf64_Sym& sym = symtab->symbols[idx];
        if (sym.st_name == 0) {
            continue;
        }
        const char* name = strtab->getStringAt(sym.st_name);
        if (!name) {
            continue;
        }
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
    if (!impl_name || !out_info) {
        return false;
    }
    *out_info = FullSymbolInfo{};

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

static bool has_dyn_export(const zSymbolSection* dynsym, const zStrTabSection* dynstr, const char* export_name) {
    FullSymbolInfo existing{};
    return find_symbol_in_table(dynsym, dynstr, export_name, &existing);
}

static bool collect_defined_dynamic_exports(const zElf& elf,
                                            std::vector<std::string>* out_exports,
                                            std::string* error) {
    if (!out_exports) {
        if (error) {
            *error = "invalid output list";
        }
        return false;
    }
    out_exports->clear();

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

    std::unordered_set<std::string> seen;
    seen.reserve(dynsym->symbols.size());
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
        out_exports->emplace_back(name);
    }

    return true;
}

static bool is_fun_or_java_symbol(const std::string& name) {
    if (name.rfind("fun_", 0) == 0) {
        return true;
    }
    if (name.rfind("Java_", 0) == 0) {
        return true;
    }
    return false;
}

static const char* dynstr_name_at(const std::vector<uint8_t>& dynstr_bytes, uint32_t off) {
    if (off >= dynstr_bytes.size()) {
        return nullptr;
    }
    return reinterpret_cast<const char*>(dynstr_bytes.data() + off);
}

static std::vector<uint8_t> build_sysv_hash_payload_from_bytes(const std::vector<Elf64_Sym>& dynsym_symbols,
                                                               const std::vector<uint8_t>& dynstr_bytes) {
    if (dynsym_symbols.empty()) {
        return {};
    }
    const uint32_t nchain = static_cast<uint32_t>(dynsym_symbols.size());
    const uint32_t nbucket = choose_bucket_count(nchain);
    std::vector<uint32_t> buckets(nbucket, 0);
    std::vector<uint32_t> chains(nchain, 0);

    for (uint32_t sym_index = 1; sym_index < nchain; ++sym_index) {
        const Elf64_Sym& sym = dynsym_symbols[sym_index];
        const char* name = dynstr_name_at(dynstr_bytes, sym.st_name);
        if (!name || name[0] == '\0') {
            continue;
        }
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
    if (!name) {
        return 0;
    }
    uint32_t h = 5381U;
    while (*name) {
        h = (h << 5) + h + static_cast<uint8_t>(*name++);
    }
    return h;
}

static std::vector<uint8_t> build_gnu_hash_payload_from_bytes(const std::vector<Elf64_Sym>& dynsym_symbols,
                                                              const std::vector<uint8_t>& dynstr_bytes) {
    if (dynsym_symbols.size() <= 1) {
        return {};
    }

    const uint32_t nchain = static_cast<uint32_t>(dynsym_symbols.size());
    const uint32_t symoffset = 1;
    // For patchbay mode we keep original dynsym order and only append new aliases.
    // Use a single bucket so the chain is one contiguous range and all symbols remain reachable
    // without requiring GNU-hash-compatible symbol reordering.
    const uint32_t nbuckets = 1;
    const uint32_t bloom_size = 1;
    const uint32_t bloom_shift = 6;

    std::vector<uint64_t> bloom(bloom_size, 0);
    std::vector<uint32_t> buckets(nbuckets, 0);
    std::vector<uint32_t> chain(nchain > symoffset ? (nchain - symoffset) : 0, 0);
    std::vector<uint32_t> last_in_bucket(nbuckets, 0);

    for (uint32_t idx = symoffset; idx < nchain; ++idx) {
        const Elf64_Sym& sym = dynsym_symbols[idx];
        const char* name = dynstr_name_at(dynstr_bytes, sym.st_name);
        if (!name || name[0] == '\0') {
            continue;
        }
        const uint32_t h = elf_gnu_hash(name);
        const uint32_t b = h % nbuckets;
        if (buckets[b] == 0) {
            buckets[b] = idx;
        }
        last_in_bucket[b] = idx;
        const uint32_t word = (h / 64U) % bloom_size;
        const uint32_t bit1 = h % 64U;
        const uint32_t bit2 = (h >> bloom_shift) % 64U;
        bloom[word] |= (1ULL << bit1) | (1ULL << bit2);
    }

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
            val |= 1U;
        }
        if (chain_idx < chain.size()) {
            chain[chain_idx] = val;
        }
    }

    std::vector<uint8_t> payload;
    payload.resize(sizeof(uint32_t) * 4 +
                   sizeof(uint64_t) * bloom.size() +
                   sizeof(uint32_t) * buckets.size() +
                   sizeof(uint32_t) * chain.size());

    uint8_t* out = payload.data();
    auto write_u32 = [&out](uint32_t v) {
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
    if (file_bytes.size() < sizeof(Elf64_Ehdr)) {
        if (error) {
            *error = "output image too small for ELF header";
        }
        return false;
    }
    const auto* ehdr = reinterpret_cast<const Elf64_Ehdr*>(file_bytes.data());

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
    return true;
}

static bool print_patchbay_info(const char* elf_path, std::string* error) {
    if (!elf_path) {
        if (error) {
            *error = "elf path is null";
        }
        return false;
    }

    zElf elf(elf_path);
    if (!elf.isLoaded()) {
        if (error) {
            *error = "failed to load elf";
        }
        return false;
    }
    const auto& sht = elf.sectionHeaderModel();
    const int patchbay_idx = sht.findByName(".vmp_patchbay");
    if (patchbay_idx < 0) {
        if (error) {
            *error = "no .vmp_patchbay section";
        }
        return false;
    }
    const zSectionTableElement* patchbay = sht.get((size_t)patchbay_idx);
    if (!patchbay) {
        if (error) {
            *error = "patchbay section is null";
        }
        return false;
    }

    std::vector<uint8_t> file_bytes;
    if (!load_file_bytes(elf_path, &file_bytes)) {
        if (error) {
            *error = "failed to read file bytes";
        }
        return false;
    }
    if (patchbay->offset > file_bytes.size() || patchbay->size > file_bytes.size() - (size_t)patchbay->offset) {
        if (error) {
            *error = "patchbay section range out of file";
        }
        return false;
    }
    if (patchbay->size < sizeof(PatchBayHeader)) {
        if (error) {
            *error = "patchbay section too small";
        }
        return false;
    }

    const auto* hdr = reinterpret_cast<const PatchBayHeader*>(file_bytes.data() + patchbay->offset);
    const bool header_ok = hdr->magic == kPatchBayMagic && hdr->version == kPatchBayVersion;

    uint32_t computed_crc = 0;
    std::string crc_error;
    const bool crc_ok = compute_patchbay_crc_from_file(file_bytes, patchbay->offset, *hdr, &computed_crc, &crc_error);
    const bool crc_match = crc_ok && (computed_crc == hdr->crc32);

    auto percent = [](uint32_t used, uint32_t cap) -> double {
        if (cap == 0) {
            return 0.0;
        }
        return (100.0 * (double)used) / (double)cap;
    };

    std::printf("patchbay_info: %s\n", elf_path);
    std::printf("  section: idx=%d off=0x%llx addr=0x%llx size=%llu\n",
                patchbay_idx,
                static_cast<unsigned long long>(patchbay->offset),
                static_cast<unsigned long long>(patchbay->addr),
                static_cast<unsigned long long>(patchbay->size));
    std::printf("  header: magic=0x%08x version=%u flags=0x%04x total=%u header=%u payload=%u valid=%s\n",
                hdr->magic,
                hdr->version,
                hdr->flags,
                hdr->total_size,
                hdr->header_size,
                hdr->payload_size,
                header_ok ? "yes" : "no");
    std::printf("  dynsym : used=%u cap=%u (%.2f%%)\n", hdr->used_dynsym, hdr->dynsym_cap, percent(hdr->used_dynsym, hdr->dynsym_cap));
    std::printf("  dynstr : used=%u cap=%u (%.2f%%)\n", hdr->used_dynstr, hdr->dynstr_cap, percent(hdr->used_dynstr, hdr->dynstr_cap));
    std::printf("  gnuhash: used=%u cap=%u (%.2f%%)\n", hdr->used_gnuhash, hdr->gnuhash_cap, percent(hdr->used_gnuhash, hdr->gnuhash_cap));
    std::printf("  sysvhash: used=%u cap=%u (%.2f%%)\n", hdr->used_sysvhash, hdr->sysvhash_cap, percent(hdr->used_sysvhash, hdr->sysvhash_cap));
    std::printf("  versym : used=%u cap=%u (%.2f%%)\n", hdr->used_versym, hdr->versym_cap, percent(hdr->used_versym, hdr->versym_cap));
    std::printf("  slots  : used=%u total=%u (%.2f%%) bitmap_lo=0x%016llx bitmap_hi=0x%016llx\n",
                hdr->takeover_slot_used,
                hdr->takeover_slot_total,
                percent(hdr->takeover_slot_used, hdr->takeover_slot_total),
                static_cast<unsigned long long>(hdr->takeover_slot_bitmap_lo),
                static_cast<unsigned long long>(hdr->takeover_slot_bitmap_hi));
    if (crc_ok) {
        std::printf("  crc32  : stored=0x%08x computed=0x%08x match=%s\n",
                    hdr->crc32,
                    computed_crc,
                    crc_match ? "yes" : "no");
    } else {
        std::printf("  crc32  : stored=0x%08x computed=(error) match=no reason=%s\n",
                    hdr->crc32,
                    crc_error.c_str());
    }
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
    if (handled) {
        *handled = false;
    }
    if (!input_path || !output_path || !dynamic_sec) {
        if (error) {
            *error = "invalid patchbay arguments";
        }
        return false;
    }

    const auto& sht = elf.sectionHeaderModel();
    const int patchbay_idx = sht.findByName(".vmp_patchbay");
    if (patchbay_idx < 0) {
        return true;
    }
    if (handled) {
        *handled = true;
    }

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

    std::vector<uint8_t> new_file;
    if (!load_file_bytes(input_path, &new_file)) {
        if (error) {
            *error = "failed to read input bytes";
        }
        return false;
    }
    if (patchbay->offset > new_file.size() || patchbay->size > (new_file.size() - (size_t)patchbay->offset)) {
        if (error) {
            *error = "patchbay section range out of file";
        }
        return false;
    }

    auto* patch_hdr = reinterpret_cast<PatchBayHeader*>(new_file.data() + patchbay->offset);
    if (patch_hdr->magic != kPatchBayMagic || patch_hdr->version != kPatchBayVersion) {
        if (error) {
            *error = "patchbay header magic/version mismatch";
        }
        return false;
    }
    if (patch_hdr->header_size < sizeof(PatchBayHeader) || patch_hdr->total_size > patchbay->size) {
        if (error) {
            *error = "patchbay header size/capacity invalid";
        }
        return false;
    }

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

    auto write_region = [&new_file, patchbay](uint32_t off, uint32_t cap, const std::vector<uint8_t>& payload) {
        const size_t abs_off = (size_t)(patchbay->offset + off);
        if (!payload.empty()) {
            std::memcpy(new_file.data() + abs_off, payload.data(), payload.size());
        }
        if (cap > payload.size()) {
            std::memset(new_file.data() + abs_off + payload.size(), 0, cap - payload.size());
        }
    };

    write_region(patch_hdr->dynsym_off, patch_hdr->dynsym_cap, new_dynsym_bytes);
    write_region(patch_hdr->dynstr_off, patch_hdr->dynstr_cap, new_dynstr);
    write_region(patch_hdr->gnuhash_off, patch_hdr->gnuhash_cap, new_gnu_hash);
    write_region(patch_hdr->versym_off, patch_hdr->versym_cap, new_versym);
    if (!new_sysv_hash.empty() && patch_hdr->sysvhash_cap > 0) {
        write_region(patch_hdr->sysvhash_off, patch_hdr->sysvhash_cap, new_sysv_hash);
    }

    const uint64_t dynsym_abs_off = patchbay->offset + patch_hdr->dynsym_off;
    const uint64_t dynstr_abs_off = patchbay->offset + patch_hdr->dynstr_off;
    const uint64_t gnu_hash_abs_off = patchbay->offset + patch_hdr->gnuhash_off;
    const uint64_t versym_abs_off = patchbay->offset + patch_hdr->versym_off;
    const uint64_t sysv_hash_abs_off = patchbay->offset + patch_hdr->sysvhash_off;

    const uint64_t dynsym_abs_vaddr = patchbay->addr + patch_hdr->dynsym_off;
    const uint64_t dynstr_abs_vaddr = patchbay->addr + patch_hdr->dynstr_off;
    const uint64_t gnu_hash_abs_vaddr = patchbay->addr + patch_hdr->gnuhash_off;
    const uint64_t versym_abs_vaddr = patchbay->addr + patch_hdr->versym_off;
    const uint64_t sysv_hash_abs_vaddr = patchbay->addr + patch_hdr->sysvhash_off;

    std::vector<Elf64_Dyn> dyn_entries = dynamic_sec->entries;
    auto get_dyn_ptr = [&dyn_entries](Elf64_Sxword tag, Elf64_Xword* out) -> bool {
        if (!out) {
            return false;
        }
        for (const Elf64_Dyn& ent : dyn_entries) {
            if (ent.d_tag == tag) {
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
        return false;
    };

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
    if (!new_sysv_hash.empty() && patch_hdr->sysvhash_cap > 0) {
        set_dyn_ptr(DT_HASH, (Elf64_Xword)sysv_hash_abs_vaddr);
    }

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
    std::memcpy(new_file.data() + dynamic_sec->offset, dyn_bytes.data(), dyn_bytes.size());

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
            return idx >= 0 ? &shdrs[idx] : nullptr;
        };

        if (auto* sh = patch_shdr(dynsym_idx)) {
            sh->sh_offset = (Elf64_Off)dynsym_abs_off;
            sh->sh_addr = (Elf64_Addr)dynsym_abs_vaddr;
            sh->sh_size = (Elf64_Xword)new_dynsym_bytes.size();
            sh->sh_entsize = sizeof(Elf64_Sym);
            sh->sh_link = (Elf64_Word)dynstr_idx;
            sh->sh_info = 1;
        }
        if (auto* sh = patch_shdr(dynstr_idx)) {
            sh->sh_offset = (Elf64_Off)dynstr_abs_off;
            sh->sh_addr = (Elf64_Addr)dynstr_abs_vaddr;
            sh->sh_size = (Elf64_Xword)new_dynstr.size();
        }
        if (auto* sh = patch_shdr(versym_idx)) {
            sh->sh_offset = (Elf64_Off)versym_abs_off;
            sh->sh_addr = (Elf64_Addr)versym_abs_vaddr;
            sh->sh_size = (Elf64_Xword)new_versym.size();
            sh->sh_entsize = 2;
            sh->sh_link = (Elf64_Word)dynsym_idx;
        }
        if (auto* sh = patch_shdr(gnu_hash_idx)) {
            sh->sh_offset = (Elf64_Off)gnu_hash_abs_off;
            sh->sh_addr = (Elf64_Addr)gnu_hash_abs_vaddr;
            sh->sh_size = (Elf64_Xword)new_gnu_hash.size();
            sh->sh_link = (Elf64_Word)dynsym_idx;
            sh->sh_addralign = 8;
        }
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

    patch_hdr = reinterpret_cast<PatchBayHeader*>(new_file.data() + patchbay->offset);
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
    patch_hdr->flags |= 0x1U;
    patch_hdr->flags |= 0x2U;
    patch_hdr->crc32 = 0;

    std::string layout_error;
    uint32_t computed_crc = 0;
    if (!compute_patchbay_crc_from_file(new_file, patchbay->offset, *patch_hdr, &computed_crc, &layout_error)) {
        if (error) {
            *error = layout_error;
        }
        return false;
    }
    patch_hdr->crc32 = computed_crc;

    if (!validate_elf_tables_for_android(new_file, &layout_error)) {
        if (error) {
            *error = "patchbay output layout invalid: " + layout_error;
        }
        return false;
    }
    if (!save_file_bytes(output_path, new_file)) {
        if (error) {
            *error = "failed to write output file";
        }
        return false;
    }

    zElf patched(output_path);
    if (!patched.isLoaded()) {
        if (error) {
            *error = "failed to reload output elf";
        }
        return false;
    }
    std::string validate_error;
    if (!patched.validate(&validate_error)) {
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
    if (!input_path || !output_path || alias_pairs.empty()) {
        if (error) {
            *error = "invalid input/output/alias list";
        }
        return false;
    }

    zElf elf(input_path);
    if (!elf.isLoaded()) {
        if (error) {
            *error = "failed to load input elf";
        }
        return false;
    }

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
    if ((versym_sec->payload.size() % 2U) != 0U) {
        if (error) {
            *error = ".gnu.version size is not 2-byte aligned";
        }
        return false;
    }

    std::vector<Elf64_Sym> new_dynsym = dynsym_sec->symbols;
    std::vector<uint8_t> new_dynstr = dynstr_sec->payload;
    std::vector<uint8_t> new_versym = versym_sec->payload;
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

    uint32_t appended = 0;
    uint32_t skipped_existing = 0;
    constexpr uint32_t kLogDetailLimit = 16;
    for (const AliasPair& pair : alias_pairs) {
        if (existing_names.find(pair.export_name) != existing_names.end()) {
            ++skipped_existing;
            if (skipped_existing <= kLogDetailLimit) {
                LOGI("Skip existing export(patchbay): %s", pair.export_name.c_str());
            }
            continue;
        }

        FullSymbolInfo impl{};
        if (!resolve_impl_symbol(elf, pair.impl_name.c_str(), &impl) || !impl.found || impl.value == 0) {
            if (error) {
                *error = "impl symbol not found or invalid: " + pair.impl_name;
            }
            return false;
        }

        const uint32_t name_off = static_cast<uint32_t>(new_dynstr.size());
        new_dynstr.insert(new_dynstr.end(), pair.export_name.begin(), pair.export_name.end());
        new_dynstr.push_back('\0');

        Elf64_Sym sym{};
        sym.st_name = name_off;
        sym.st_info = static_cast<unsigned char>(((STB_GLOBAL & 0x0f) << 4) |
                                                 ((impl.type == STT_NOTYPE ? STT_FUNC : impl.type) & 0x0f));
        sym.st_other = 0;
        sym.st_shndx = impl.shndx;
        sym.st_value = impl.value;
        sym.st_size = impl.size;
        new_dynsym.push_back(sym);

        new_versym.push_back(1);
        new_versym.push_back(0);

        existing_names.insert(pair.export_name);
        ++appended;
        if (appended <= kLogDetailLimit) {
            LOGI("Append dyn export alias(patchbay): %s -> %s (addr=0x%llx)",
                 pair.export_name.c_str(),
                 pair.impl_name.c_str(),
                 static_cast<unsigned long long>(impl.value));
        }
    }

    LOGI("export_alias_patchbay summary: requested=%zu appended=%u skipped_existing=%u",
         alias_pairs.size(),
         appended,
         skipped_existing);
    if (appended == 0) {
        if (error) {
            *error = "no new aliases were appended";
        }
        return false;
    }

    std::vector<uint8_t> new_dynsym_bytes(new_dynsym.size() * sizeof(Elf64_Sym));
    std::memcpy(new_dynsym_bytes.data(), new_dynsym.data(), new_dynsym_bytes.size());
    std::vector<uint8_t> new_gnu_hash = build_gnu_hash_payload_from_bytes(new_dynsym, new_dynstr);
    if (new_gnu_hash.empty()) {
        if (error) {
            *error = "failed to build .gnu.hash payload";
        }
        return false;
    }
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
    if (handled_by_patchbay) {
        return true;
    }

    if (error) {
        *error = "no .vmp_patchbay found; legacy minimal injection removed";
    }
    return false;
}

// 从静态符号表中查找指定符号的地址与大小。
static bool find_symbol_info(const zElf& elf, const char* symbol_name, SymbolInfo* out) {
    if (!symbol_name || !out) {
        return false;
    }
    const auto& sht = elf.sectionHeaderModel();
    const int symtab_idx = sht.findByName(".symtab");
    const int strtab_idx = sht.findByName(".strtab");
    if (symtab_idx < 0 || strtab_idx < 0) {
        return false;
    }
    const auto* symtab = dynamic_cast<const zSymbolSection*>(sht.get((size_t)symtab_idx));
    const auto* strtab = dynamic_cast<const zStrTabSection*>(sht.get((size_t)strtab_idx));
    if (!symtab || !strtab || (symtab->symbols.empty() && symtab->size > 0)) {
        return false;
    }
    for (size_t idx = 0; idx < symtab->symbols.size(); ++idx) {
        const Elf64_Sym& sym = symtab->symbols[idx];
        if (sym.st_name == 0) {
            continue;
        }
        const char* name = strtab->getStringAt(sym.st_name);
        if (!name) {
            continue;
        }
        if (std::strcmp(name, symbol_name) == 0) {
            out->value = sym.st_value;
            out->size = sym.st_size;
            return true;
        }
    }
    return false;
}

// 使用 PT_LOAD 映射将虚拟地址转换为文件偏移（用于二进制打补丁）。
static bool vaddr_to_file_offset_for_patch(const zElf& elf, Elf64_Addr vaddr, Elf64_Off* out) {
    if (!out || vaddr == 0) {
        return false;
    }
    for (const auto& ph : elf.programHeaderModel().elements) {
        if (ph.type != PT_LOAD || ph.filesz == 0) {
            continue;
        }
        if (vaddr >= ph.vaddr && vaddr < ph.vaddr + ph.filesz) {
            *out = (Elf64_Off)(ph.offset + (vaddr - ph.vaddr));
            return true;
        }
    }
    return false;
}

// 读取整文件字节。
static bool load_file_bytes(const char* path, std::vector<uint8_t>* out) {
    if (!path || !out) {
        return false;
    }
    FILE* fp = std::fopen(path, "rb");
    if (!fp) {
        return false;
    }
    if (std::fseek(fp, 0, SEEK_END) != 0) {
        std::fclose(fp);
        return false;
    }
    const long size = std::ftell(fp);
    if (size < 0) {
        std::fclose(fp);
        return false;
    }
    if (std::fseek(fp, 0, SEEK_SET) != 0) {
        std::fclose(fp);
        return false;
    }
    out->assign((size_t)size, 0);
    const size_t nread = std::fread(out->data(), 1, out->size(), fp);
    std::fclose(fp);
    return nread == out->size();
}

// 覆盖写回整文件字节。
static bool save_file_bytes(const char* path, const std::vector<uint8_t>& bytes) {
    if (!path) {
        return false;
    }
    FILE* fp = std::fopen(path, "wb");
    if (!fp) {
        return false;
    }
    const size_t written = std::fwrite(bytes.data(), 1, bytes.size(), fp);
    std::fclose(fp);
    return written == bytes.size();
}

// 小端读取 32 位整数（调用方保证偏移合法）。
static uint32_t read_u32_le(const std::vector<uint8_t>& bytes, size_t off) {
    return (uint32_t)bytes[off] |
           ((uint32_t)bytes[off + 1] << 8) |
           ((uint32_t)bytes[off + 2] << 16) |
           ((uint32_t)bytes[off + 3] << 24);
}

// 小端写入 32 位整数（调用方保证偏移合法）。
static void write_u32_le(std::vector<uint8_t>* bytes, size_t off, uint32_t value) {
    (*bytes)[off] = (uint8_t)(value & 0xff);
    (*bytes)[off + 1] = (uint8_t)((value >> 8) & 0xff);
    (*bytes)[off + 2] = (uint8_t)((value >> 16) & 0xff);
    (*bytes)[off + 3] = (uint8_t)((value >> 24) & 0xff);
}

// 解码 AArch64 `BL imm26` 指令，得到目标地址。
static bool decode_bl_target(Elf64_Addr pc, uint32_t insn, Elf64_Addr* out_target) {
    if (!out_target) {
        return false;
    }
    if ((insn & 0xfc000000U) != 0x94000000U) {
        return false;
    }
    int64_t imm26 = (int64_t)(insn & 0x03ffffffU);
    if ((imm26 & (1LL << 25)) != 0) {
        imm26 |= ~((1LL << 26) - 1);
    }
    const int64_t delta = imm26 << 2;
    *out_target = (Elf64_Addr)((int64_t)pc + delta);
    return true;
}

// 根据 pc 与目标地址编码 AArch64 `BL imm26` 指令。
static bool encode_bl_target(Elf64_Addr pc, Elf64_Addr target, uint32_t* out_insn) {
    if (!out_insn) {
        return false;
    }
    const int64_t delta = (int64_t)target - (int64_t)pc;
    if ((delta & 0x3LL) != 0) {
        return false;
    }
    const int64_t imm26 = delta >> 2;
    if (imm26 < -(1LL << 25) || imm26 > ((1LL << 25) - 1)) {
        return false;
    }
    *out_insn = 0x94000000U | ((uint32_t)imm26 & 0x03ffffffU);
    return true;
}

// 在 demo4 场景中将 main 内对 test2 的调用改写为 test1。
static bool patch_demo4_call_test2_to_test1(const char* input_path,
                                            const char* output_path,
                                            std::string* error) {
    if (!input_path || !output_path) {
        if (error) {
            *error = "invalid input or output path";
        }
        return false;
    }

    zElf elf(input_path);
    if (!elf.isLoaded()) {
        if (error) {
            *error = "failed to load input elf";
        }
        return false;
    }

    SymbolInfo main_sym;
    SymbolInfo test1_sym;
    SymbolInfo test2_sym;
    if (!find_symbol_info(elf, "main", &main_sym) ||
        !find_symbol_info(elf, "test1", &test1_sym) ||
        !find_symbol_info(elf, "test2", &test2_sym)) {
        if (error) {
            *error = "required symbols (main/test1/test2) not found";
        }
        return false;
    }

    if (main_sym.size == 0 || (main_sym.size % 4) != 0) {
        if (error) {
            *error = "invalid main symbol size";
        }
        return false;
    }

    Elf64_Off main_off = 0;
    if (!vaddr_to_file_offset_for_patch(elf, main_sym.value, &main_off)) {
        if (error) {
            *error = "cannot map main vaddr to file offset";
        }
        return false;
    }

    std::vector<uint8_t> bytes;
    if (!load_file_bytes(input_path, &bytes)) {
        if (error) {
            *error = "failed to read input bytes";
        }
        return false;
    }

    const uint64_t patch_end = (uint64_t)main_off + main_sym.size;
    if (patch_end > bytes.size()) {
        if (error) {
            *error = "main range exceeds file size";
        }
        return false;
    }

    size_t patched_count = 0;
    for (uint64_t off = main_off; off + 4 <= patch_end; off += 4) {
        const uint32_t insn = read_u32_le(bytes, (size_t)off);
        Elf64_Addr old_target = 0;
        const Elf64_Addr pc = (Elf64_Addr)(main_sym.value + (off - (uint64_t)main_off));
        if (!decode_bl_target(pc, insn, &old_target)) {
            continue;
        }
        if (old_target != test2_sym.value) {
            continue;
        }

        uint32_t new_insn = 0;
        if (!encode_bl_target(pc, test1_sym.value, &new_insn)) {
            if (error) {
                *error = "failed to encode patched BL";
            }
            return false;
        }
        write_u32_le(&bytes, (size_t)off, new_insn);
        ++patched_count;
    }

    if (patched_count != 1) {
        if (error) {
            *error = "expected exactly one call patch in main, actual=" + std::to_string(patched_count);
        }
        return false;
    }

    if (!save_file_bytes(output_path, bytes)) {
        if (error) {
            *error = "failed to write output bytes";
        }
        return false;
    }

    zElf patched(output_path);
    if (!patched.isLoaded()) {
        if (error) {
            *error = "failed to reload patched output";
        }
        return false;
    }
    std::string validate_error;
    if (!patched.validate(&validate_error)) {
        if (error) {
            *error = "patched output validate failed: " + validate_error;
        }
        return false;
    }
    return true;
}

// 统一记录 validate 失败日志，便于命令分支复用。
static void log_validation_failure(const char* command,
                                   const char* elf_path,
                                   const std::string& detail) {
    const char* cmd = command ? command : "unknown";
    const char* path = elf_path ? elf_path : "(null)";
    const char* reason = detail.empty() ? "(no detail)" : detail.c_str();
    LOGE("[%s] Validate failed: elf=%s detail=%s", cmd, path, reason);
}

static std::string basename_from_path(const std::string& path) {
    const size_t pos = path.find_last_of("\\/");
    if (pos == std::string::npos) {
        return path;
    }
    return path.substr(pos + 1);
}

static bool run_device_regression(const std::string& local_demo3_path) {
    LOGI("Device regression start: local=%s", local_demo3_path.c_str());
    const std::string base = basename_from_path(local_demo3_path);
    const std::string device_path = "/data/local/tmp/" + base;
    std::string cmd;

    cmd = "adb push \"" + local_demo3_path + "\" " + device_path;
    LOGI("Device regression: %s", cmd.c_str());
    if (std::system(cmd.c_str()) != 0) {
        LOGE("Device regression failed: adb push");
        return false;
    }

    cmd = "adb shell \"su -c chmod 777 " + device_path + "\"";
    LOGI("Device regression: %s", cmd.c_str());
    if (std::system(cmd.c_str()) != 0) {
        LOGE("Device regression failed: chmod");
        return false;
    }

    cmd = "adb shell \"su -c " + device_path + "\"";
    LOGI("Device regression: %s", cmd.c_str());
    const int run_ret = std::system(cmd.c_str());
    if (run_ret != 0) {
        LOGE("Device regression failed: run (exit=%d)", run_ret);
        std::string exit_cmd = "adb shell \"su -c " + device_path + "; echo EXIT:$?\"";
        (void)std::system(exit_cmd.c_str());
        return false;
    }

    LOGI("Device regression done: %s", device_path.c_str());
    return true;
}

bool vmprotect_is_patchbay_command(const char* raw_cmd) {
    if (raw_cmd == nullptr || raw_cmd[0] == '\0') {
        return false;
    }
    const std::string cmd(raw_cmd);
    return cmd == "export_alias_patchbay" ||
           cmd == "export_alias_from_patchbay";
}

int vmprotect_patchbay_entry(int argc, char* argv[]) {

    // 支持命令行选择流程；未指定时走默认 demo3 生成流程。
    const std::string cmd = (argc >= 2) ? std::string(argv[1]) : "demo3";
    if (cmd == "test_step1") {
        LOGI("test_step1 start");
        const std::string demo1 = resolve_demo_path("demo1");
        const std::string demo1_add_segment = resolve_demo_path("demo1_add_segment");
        const std::string demo1_add_section = resolve_demo_path("demo1_add_section");
        const std::string demo1_add_section_segment = resolve_demo_path("demo1_add_section_segment");

        LOGI("test_step1 input: %s", demo1.c_str());
        zElf elf(demo1.c_str());
        if (!elf.isLoaded()) {
            LOGE("Failed to load target ELF: %s", demo1.c_str());
            return 2;
        }

        LOGI("test_step1: add_segment -> %s", demo1_add_segment.c_str());
        if (!elf.add_segment(PT_LOAD, "RW_")) {
            LOGE("Failed to add segment");
            return 3;
        }
        if (!elf.relocate(demo1_add_segment)) {
            LOGE("Failed to relocate output: %s", demo1_add_segment.c_str());
            return 4;
        }

        LOGI("test_step1: backup after add_segment");
        if (!elf.backup()) {
            LOGE("Failed to restore original demo1");
            return 5;
        }

        const int first_load_segment = elf.get_first_load_segment();
        const int last_load_segment = elf.get_last_load_segment();
        if (first_load_segment < 0 || last_load_segment < 0) {
            LOGE("Missing PT_LOAD segments");
            return 6;
        }
        LOGI("test_step1: add_section -> %s", demo1_add_section.c_str());
        if (!elf.add_section("test_add_section1", (size_t)first_load_segment)) {
            LOGE("Failed to add section on first PT_LOAD");
            return 7;
        }
        if (!elf.add_section("test_add_section2", (size_t)last_load_segment)) {
            LOGE("Failed to add section on last PT_LOAD");
            return 7;
        }
        if (!elf.relocate(demo1_add_section)) {
            LOGE("Failed to relocate output: %s", demo1_add_section.c_str());
            return 4;
        }

        LOGI("test_step1: backup after add_section");
        if (!elf.backup()) {
            LOGE("Failed to restore original demo1");
            return 5;
        }

        LOGI("test_step1: add_section_segment -> %s", demo1_add_section_segment.c_str());
        if (!elf.add_section("add_section_segment")) {
            LOGE("Failed to add default section");
            return 7;
        }
        if (!elf.relocate(demo1_add_section_segment)) {
            LOGE("Failed to relocate output: %s", demo1_add_section_segment.c_str());
            return 4;
        }
        // 设备回归测试：依次验证三个输出
        LOGI("test_step1: device regression -> %s", demo1_add_segment.c_str());
        if (!run_device_regression(demo1_add_segment)) {
            return 6;
        }
        LOGI("test_step1: device regression -> %s", demo1_add_section.c_str());
        if (!run_device_regression(demo1_add_section)) {
            return 6;
        }
        LOGI("test_step1: device regression -> %s", demo1_add_section_segment.c_str());
        if (!run_device_regression(demo1_add_section_segment)) {
            return 6;
        }

        LOGI("test_step1 done");
        return 0;
    }

    if (cmd == "patch_demo4") {
        const std::string input = argc >= 3 ? std::string(argv[2]) : resolve_demo_path("demo3");
        const std::string output = argc >= 4 ? std::string(argv[3]) :
                                   (file_exists("..\\demo3") ? "..\\demo4" : "demo4");
        std::string patch_error;
        if (!patch_demo4_call_test2_to_test1(input.c_str(), output.c_str(), &patch_error)) {
            LOGE("patch_demo4 failed: input=%s output=%s error=%s",
                 input.c_str(),
                 output.c_str(),
                 patch_error.empty() ? "(unknown)" : patch_error.c_str());
            return 5;
        }
        LOGI("patch_demo4 success: %s -> %s (main: test2 -> test1)", input.c_str(), output.c_str());
        return 0;
    }

    if (cmd == "layout") {
        const std::string donor = resolve_demo_path("demo1");
        zElf elf(donor.c_str());
        if (!elf.isLoaded()) {
            LOGE("Failed to load ELF: %s", donor.c_str());
            return 2;
        }
        elf.print_layout();
        return 0;
    }

    if (cmd == "validate") {
        if (argc < 3) {
            print_usage(argv[0]);
            return 1;
        }
        zElf elf(argv[2]);
        if (!elf.isLoaded()) {
            LOGE("Failed to load ELF: %s", argv[2]);
            return 2;
        }
        std::string error;
        if (!elf.validate(&error)) {
            log_validation_failure(cmd.c_str(), argv[2], error);
            return 3;
        }
        LOGI("Validate success: %s", argv[2]);
        return 0;
    }

    if (cmd == "patchbay_info") {
        if (argc < 3) {
            print_usage(argv[0]);
            return 1;
        }
        std::string info_error;
        if (!print_patchbay_info(argv[2], &info_error)) {
            LOGE("patchbay_info failed: %s", info_error.empty() ? "(unknown)" : info_error.c_str());
            return 3;
        }
        return 0;
    }

    if (cmd == "inject") {
        if (argc < 5) {
            print_usage(argv[0]);
            return 1;
        }
        zElf elf(argv[2]);
        if (!elf.isLoaded()) {
            LOGE("Failed to load target ELF: %s", argv[2]);
            return 2;
        }
        if (!elf.inject_vmp_segments(argv[3], argv[4])) {
            LOGE("Inject failed");
            return 3;
        }
        LOGI("Inject success: %s + %s -> %s", argv[2], argv[3], argv[4]);
        return 0;
    }

    if (cmd == "relocate_pht") {
        if (argc < 5) {
            print_usage(argv[0]);
            return 1;
        }
        const int extra_entries = std::atoi(argv[3]);
        zElf elf(argv[2]);
        if (!elf.isLoaded()) {
            LOGE("Failed to load ELF: %s", argv[2]);
            return 2;
        }
        if (!elf.relocate_and_expand_pht(extra_entries, argv[4])) {
            LOGE("relocate_pht failed");
            return 3;
        }
        LOGI("relocate_pht success: %s -> %s", argv[2], argv[4]);
        return 0;
    }

    if (cmd == "export_alias_patchbay") {
        if (argc < 6) {
            print_usage(argv[0]);
            return 1;
        }
        int spec_begin = 4;
        bool allow_validate_fail = false;
        if (std::strcmp(argv[4], "--allow-validate-fail") == 0) {
            allow_validate_fail = true;
            spec_begin = 5;
        }
        if (argc <= spec_begin) {
            print_usage(argv[0]);
            return 1;
        }
        std::vector<AliasPair> pairs;
        pairs.reserve((size_t)(argc - spec_begin));
        for (int i = spec_begin; i < argc; ++i) {
            AliasPair pair;
            if (!parse_alias_pair(argv[i], &pair)) {
                LOGE("invalid alias spec: %s (expected export=impl)", argv[i]);
                return 2;
            }
            pairs.push_back(std::move(pair));
        }

        std::string patch_error;
        if (!export_alias_symbols_patchbay(argv[2], argv[3], pairs, allow_validate_fail, &patch_error)) {
            LOGE("export_alias_patchbay failed: %s", patch_error.empty() ? "(unknown)" : patch_error.c_str());
            return 3;
        }
        LOGI("export_alias_patchbay success: %s -> %s", argv[2], argv[3]);
        return 0;
    }

    if (cmd == "export_alias_from_patchbay") {
        if (argc < 6) {
            print_usage(argv[0]);
            return 1;
        }
        bool allow_validate_fail = false;
        bool only_fun_java = false;
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

        zElf donor(argv[3]);
        if (!donor.isLoaded()) {
            LOGE("failed to load donor ELF: %s", argv[3]);
            return 2;
        }
        std::vector<std::string> donor_exports;
        std::string collect_error;
        if (!collect_defined_dynamic_exports(donor, &donor_exports, &collect_error)) {
            LOGE("collect donor exports failed: %s", collect_error.empty() ? "(unknown)" : collect_error.c_str());
            return 2;
        }
        if (only_fun_java) {
            std::vector<std::string> filtered;
            filtered.reserve(donor_exports.size());
            for (const std::string& name : donor_exports) {
                if (is_fun_or_java_symbol(name)) {
                    filtered.push_back(name);
                }
            }
            donor_exports.swap(filtered);
        }
        if (donor_exports.empty()) {
            LOGE("donor has no defined dynamic exports: %s", argv[3]);
            return 2;
        }

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
        std::unordered_set<std::string> input_export_set;
        input_export_set.reserve(input_exports.size());
        for (const std::string& name : input_exports) {
            input_export_set.insert(name);
        }

        std::vector<AliasPair> pairs;
        pairs.reserve(donor_exports.size());
        for (const std::string& export_name : donor_exports) {
            if (input_export_set.find(export_name) != input_export_set.end()) {
                continue;
            }
            AliasPair pair;
            pair.export_name = export_name;
            pair.impl_name = argv[5];
            pairs.push_back(std::move(pair));
        }

        LOGI("export_alias_from_patchbay start: donor_exports=%zu input_exports=%zu missing=%zu impl=%s only_fun_java=%d",
             donor_exports.size(),
             input_exports.size(),
             pairs.size(),
             argv[5],
             only_fun_java ? 1 : 0);

        if (pairs.empty()) {
            if (std::strcmp(argv[2], argv[4]) != 0) {
                std::vector<uint8_t> src_bytes;
                if (!load_file_bytes(argv[2], &src_bytes) || !save_file_bytes(argv[4], src_bytes)) {
                    LOGE("export_alias_from_patchbay no-op copy failed: %s -> %s", argv[2], argv[4]);
                    return 3;
                }
            }
            LOGI("export_alias_from_patchbay no-op: no missing exports");
            return 0;
        }

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

    print_usage(argv[0]);
    return 1;
}
