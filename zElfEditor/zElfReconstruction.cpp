/**
 * @file zElfReconstruction.cpp
 * @brief ELF 文件重构实现 - 核心模块
 *
 * 本文件实现完整的 ELF 文件重构功能，包括：
 * 1. Program Header Table (PHT) 和 Section Header Table (SHT) 的重新布局
 * 2. Section 到 LOAD 段的映射和地址分配
 * 3. 关键约束的维护：offset/vaddr 模运算同余、段间无冲突等
 * 4. NOBITS 节（.bss）的特殊处理
 * 5. Pending blobs（注入数据）的空间分配
 *
 * 重要约束（Android linker 要求）：
 * - PT_LOAD 段: p_offset % PAGE_SIZE == p_vaddr % PAGE_SIZE
 * - LOAD 段之间不能在文件或虚拟地址空间重叠
 * - Section 的标志位必须与所属 LOAD 段的标志位匹配
 *
 * @version 2.0 (2026-02-10) - 修复了 offset/vaddr 同余、NOBITS offset 和冲突检测问题
 */
#include "zElf.h"
#include "zElfUtils.h"
#include "zLog.h"
#include "zElfPcRelativePatcher.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <string>
#include <unordered_map>

namespace {

// 将 offset 调整到与 vaddr 在模 page_size 下同余的位置
// 这是 ELF 加载的关键约束: (p_offset % page_size) == (p_vaddr % page_size)
uint64_t align_to_congruent(uint64_t offset, uint64_t vaddr, uint64_t page_size) {
    if (page_size == 0 || page_size == 1) {
        return offset;
    }
    const uint64_t offset_mod = offset % page_size;
    const uint64_t vaddr_mod = vaddr % page_size;

    if (offset_mod == vaddr_mod) {
        return offset;  // 已经同余
    }

    // 计算需要调整的偏移量
    uint64_t delta = 0;
    if (vaddr_mod > offset_mod) {
        delta = vaddr_mod - offset_mod;
    } else {
        delta = page_size - (offset_mod - vaddr_mod);
    }

    return offset + delta;
}

// 检查 LOAD 段扩展是否与其他 LOAD 段冲突
bool check_load_expansion_safe(const std::vector<zProgramTableElement>& all_loads,
                               size_t expanding_idx,
                               uint64_t new_filesz,
                               uint64_t new_memsz) {
    const auto& expanding = all_loads[expanding_idx];

    for (size_t i = 0; i < all_loads.size(); ++i) {
        if (i == expanding_idx) {
            continue;
        }
        const auto& other = all_loads[i];
        if (other.type != PT_LOAD) {
            continue;
        }

        // 检查文件偏移冲突
        if (ranges_overlap_u64(expanding.offset, new_filesz,
                               other.offset, other.filesz)) {
            return false;
        }

        // 检查虚拟地址冲突
        if (ranges_overlap_u64(expanding.vaddr, new_memsz,
                               other.vaddr, other.memsz)) {
            return false;
        }
    }
    return true;
}

} // namespace

bool zElf::reconstructionImpl() {

    if (file_image_.empty()) {
        LOGE("Reconstruction failed: empty file image");
        return false;
    }

    {
        std::unordered_map<int64_t, uint64_t> dynamic_tags;
        std::string tag_error;
        if (!collect_dynamic_tags(*this, &dynamic_tags, &tag_error)) {
            LOGE("Reconstruction failed: cannot collect dynamic tags: %s", tag_error.c_str());
            return false;
        }
        const auto android_rel_it = dynamic_tags.find(DT_ANDROID_REL_TAG);
        if (android_rel_it != dynamic_tags.end() && android_rel_it->second != 0) {
            const auto android_relsz_it = dynamic_tags.find(DT_ANDROID_RELSZ_TAG);
            if (android_relsz_it == dynamic_tags.end() || android_relsz_it->second == 0) {
                LOGE("Reconstruction failed: DT_ANDROID_REL exists but DT_ANDROID_RELSZ is missing/zero");
                return false;
            }
        }
    }

    const Elf64_Off PAGE_SIZE = (Elf64_Off)infer_runtime_page_size_from_phdrs(ph_table_model_.elements);
    const Elf64_Off FILE_ALIGN = 0x10;

    if (header_model_.raw.e_ehsize != sizeof(Elf64_Ehdr)) {
        header_model_.raw.e_ehsize = sizeof(Elf64_Ehdr);
    }
    if (header_model_.raw.e_phentsize != sizeof(Elf64_Phdr)) {
        header_model_.raw.e_phentsize = sizeof(Elf64_Phdr);
    }
    if (header_model_.raw.e_shentsize != sizeof(Elf64_Shdr)) {
        header_model_.raw.e_shentsize = sizeof(Elf64_Shdr);
    }

    const Elf64_Off old_phoff = header_model_.raw.e_phoff;
    const uint64_t old_pht_size_bytes =
            (uint64_t)header_model_.raw.e_phnum *
            (uint64_t)(header_model_.raw.e_phentsize ? header_model_.raw.e_phentsize : sizeof(Elf64_Phdr));

    auto rebuild_pht = [this]() -> uint64_t {
        header_model_.raw.e_phnum = (Elf64_Half)ph_table_model_.elements.size();
        return (uint64_t)ph_table_model_.elements.size() * sizeof(Elf64_Phdr);
    };

    uint64_t pht_size_bytes = rebuild_pht();

    const Elf64_Off default_phoff = align_up_off((Elf64_Off)header_model_.raw.e_ehsize, 8);
    auto is_phdr_range_mapped = [this, pht_size_bytes](Elf64_Off phoff) -> bool {
        if (pht_size_bytes == 0) {
            return true;
        }
        const uint64_t ph_begin = (uint64_t)phoff;
        const uint64_t ph_end = ph_begin + pht_size_bytes;
        for (const auto& load : ph_table_model_.elements) {
            if (load.type != PT_LOAD || load.filesz == 0) {
                continue;
            }
            const uint64_t seg_begin = load.offset;
            const uint64_t seg_end = load.offset + load.filesz;
            if (ph_begin >= seg_begin && ph_end <= seg_end) {
                return true;
            }
        }
        return false;
    };

    auto is_phdr_range_safe = [this, old_phoff, old_pht_size_bytes, pht_size_bytes](Elf64_Off phoff) -> bool {
        if (pht_size_bytes == 0) {
            return true;
        }
        const uint64_t ph_begin = (uint64_t)phoff;

        if (ph_begin > std::numeric_limits<uint64_t>::max() - pht_size_bytes) {
            return false;
        }

        auto overlap_is_old_phdr = [old_phoff, old_pht_size_bytes](uint64_t begin, uint64_t size) -> bool {
            if (old_pht_size_bytes == 0) {
                return false;
            }
            return ranges_overlap_u64(begin, size, (uint64_t)old_phoff, old_pht_size_bytes);
        };

        for (const auto& section : sh_table_model_.elements) {
            if (!section || section->type == SHT_NULL || section->type == SHT_NOBITS || section->size == 0) {
                continue;
            }
            const uint64_t sec_begin = section->offset;
            const uint64_t sec_size = section->size;
            if (ranges_overlap_u64(ph_begin, pht_size_bytes, sec_begin, sec_size) &&
                !overlap_is_old_phdr(sec_begin, sec_size)) {
                return false;
            }
        }

        for (const auto& blob : pending_blobs_) {
            if (blob.bytes.empty()) {
                continue;
            }
            const uint64_t blob_begin = blob.offset;
            const uint64_t blob_size = blob.bytes.size();
            if (ranges_overlap_u64(ph_begin, pht_size_bytes, blob_begin, blob_size) &&
                !overlap_is_old_phdr(blob_begin, blob_size)) {
                return false;
            }
        }

        return true;
    };

    Elf64_Off selected_phoff = header_model_.raw.e_phoff;
    if (selected_phoff < default_phoff) {
        selected_phoff = default_phoff;
    }
    selected_phoff = align_up_off(selected_phoff, 8);
    if (!is_phdr_range_mapped(selected_phoff) || !is_phdr_range_safe(selected_phoff)) {
        selected_phoff = default_phoff;
        if (!is_phdr_range_mapped(selected_phoff) || !is_phdr_range_safe(selected_phoff)) {
            for (const auto& load : ph_table_model_.elements) {
                if (load.type != PT_LOAD || load.filesz == 0) {
                    continue;
                }
                const uint64_t candidate_begin = align_up_u64(
                        std::max<uint64_t>((uint64_t)default_phoff, load.offset),
                        8);
                if (candidate_begin + pht_size_bytes <= load.offset + load.filesz &&
                    is_phdr_range_safe((Elf64_Off)candidate_begin)) {
                    selected_phoff = (Elf64_Off)candidate_begin;
                    break;
                }
            }
        }
    }
    header_model_.raw.e_phoff = selected_phoff;
    if (pht_size_bytes > 0 &&
        (!is_phdr_range_mapped(header_model_.raw.e_phoff) || !is_phdr_range_safe(header_model_.raw.e_phoff))) {
        uint64_t data_end = file_image_.size();
        for (const auto& blob : pending_blobs_) {
            if (!blob.bytes.empty()) {
                data_end = std::max<uint64_t>(data_end, blob.offset + blob.bytes.size());
            }
        }
        for (const auto& section : sh_table_model_.elements) {
            if (!section || section->type == SHT_NOBITS || section->size == 0) {
                continue;
            }
            data_end = std::max<uint64_t>(data_end, section->offset + section->size);
        }

        const Elf64_Off min_phoff = 0x3000;
        const Elf64_Off fixed_phoff = align_up_off((Elf64_Off)std::max<uint64_t>(data_end, (uint64_t)min_phoff),
                                                   PAGE_SIZE);

        // 预留 4 个新 PHT 槽位：3 个 PT_NULL + 1 个自救 PT_LOAD。
        for (int i = 0; i < 3; ++i) {
            zProgramTableElement null_ph;
            null_ph.type = PT_NULL;
            ph_table_model_.elements.push_back(null_ph);
        }
        zProgramTableElement rescue;
        rescue.type = PT_LOAD;
        rescue.flags = PF_R;
        rescue.offset = fixed_phoff;
        rescue.vaddr = (Elf64_Addr)fixed_phoff;
        rescue.paddr = (Elf64_Addr)fixed_phoff;
        rescue.align = PAGE_SIZE;
        ph_table_model_.elements.push_back(rescue);

        pht_size_bytes = rebuild_pht();
        header_model_.raw.e_phoff = fixed_phoff;

        auto& last_load = ph_table_model_.elements.back();
        last_load.offset = fixed_phoff;
        last_load.vaddr = (Elf64_Addr)fixed_phoff;
        last_load.paddr = (Elf64_Addr)fixed_phoff;
        last_load.filesz = (Elf64_Xword)pht_size_bytes;
        last_load.memsz = (Elf64_Xword)pht_size_bytes;
        last_load.align = PAGE_SIZE;

        if (!is_phdr_range_mapped(header_model_.raw.e_phoff) || !is_phdr_range_safe(header_model_.raw.e_phoff)) {
            LOGE("Reconstruction failed: PHT relocation invalid, phoff=0x%llx size=0x%llx",
                 (unsigned long long)header_model_.raw.e_phoff,
                 (unsigned long long)pht_size_bytes);
            return false;
        }
        LOGW("PHT relocated to 0x%llx, rescue PT_LOAD added (phnum=%u)",
             (unsigned long long)header_model_.raw.e_phoff,
             header_model_.raw.e_phnum);
    }

    Elf64_Off next_file_off = header_model_.raw.e_phoff +
                              (Elf64_Off)header_model_.raw.e_phnum * (Elf64_Off)sizeof(Elf64_Phdr);
    next_file_off = align_up_off(next_file_off, FILE_ALIGN);

    // 重建 .gnu.hash / .hash（若存在 dynsym/dynstr）
    auto rebuild_dynamic_hash_tables = [this](Elf64_Off file_align) -> bool {
        const int dynsym_idx = sh_table_model_.findByName(".dynsym");
        if (dynsym_idx < 0) {
            return true;
        }
        const auto* dynsym = dynamic_cast<const zSymbolSection*>(sh_table_model_.get((size_t)dynsym_idx));
        if (!dynsym || dynsym->symbols.empty()) {
            return true;
        }
        if (dynsym->link >= sh_table_model_.elements.size()) {
            return false;
        }
        const auto* dynstr = dynamic_cast<const zStrTabSection*>(sh_table_model_.get((size_t)dynsym->link));
        if (!dynstr) {
            return false;
        }

        auto elf_hash = [](const char* name) -> uint32_t {
            uint32_t h = 0;
            while (*name) {
                h = (h << 4) + (uint8_t)(*name++);
                uint32_t g = h & 0xf0000000U;
                if (g) {
                    h ^= g >> 24;
                }
                h &= ~g;
            }
            return h;
        };
        auto gnu_hash = [](const char* name) -> uint32_t {
            uint32_t h = 5381U;
            while (*name) {
                h = (h << 5) + h + (uint8_t)(*name++);
            }
            return h;
        };

        const uint32_t nchain = (uint32_t)dynsym->symbols.size();
        const uint32_t nbucket = nchain > 0 ? nchain : 1;

        std::vector<uint32_t> buckets(nbucket, 0);
        std::vector<uint32_t> chains(nchain, 0);
        for (uint32_t idx = 1; idx < nchain; ++idx) {
            const auto& sym = dynsym->symbols[idx];
            const char* name = dynstr->getStringAt(sym.st_name);
            if (!name) {
                continue;
            }
            const uint32_t h = elf_hash(name);
            const uint32_t b = h % nbucket;
            if (buckets[b] == 0) {
                buckets[b] = idx;
            } else {
                uint32_t cur = buckets[b];
                while (chains[cur] != 0) {
                    cur = chains[cur];
                }
                chains[cur] = idx;
            }
        }

        std::vector<uint8_t> hash_payload;
        hash_payload.resize(sizeof(uint32_t) * (2 + nbucket + nchain));
        uint32_t* hash_words = reinterpret_cast<uint32_t*>(hash_payload.data());
        hash_words[0] = nbucket;
        hash_words[1] = nchain;
        std::memcpy(hash_words + 2, buckets.data(), nbucket * sizeof(uint32_t));
        std::memcpy(hash_words + 2 + nbucket, chains.data(), nchain * sizeof(uint32_t));

        const uint32_t symoffset = 1;
        const uint32_t nbuckets_gnu = std::max<uint32_t>(1, nchain / 4);
        const uint32_t bloom_size = 1;
        const uint32_t bloom_shift = 6;

        std::vector<uint64_t> bloom(bloom_size, 0);
        std::vector<uint32_t> gnu_buckets(nbuckets_gnu, 0);
        std::vector<uint32_t> gnu_chain;
        if (nchain > symoffset) {
            gnu_chain.resize(nchain - symoffset, 0);
        }
        std::vector<uint32_t> last_in_bucket(nbuckets_gnu, 0);

        for (uint32_t idx = symoffset; idx < nchain; ++idx) {
            const auto& sym = dynsym->symbols[idx];
            const char* name = dynstr->getStringAt(sym.st_name);
            if (!name) {
                continue;
            }
            const uint32_t h = gnu_hash(name);
            const uint32_t b = h % nbuckets_gnu;
            if (gnu_buckets[b] == 0) {
                gnu_buckets[b] = idx;
            }
            last_in_bucket[b] = idx;
            const uint32_t word = (h / 64) % bloom_size;
            const uint32_t bit1 = h % 64;
            const uint32_t bit2 = (h >> bloom_shift) % 64;
            bloom[word] |= (1ULL << bit1) | (1ULL << bit2);
        }

        for (uint32_t idx = symoffset; idx < nchain; ++idx) {
            const auto& sym = dynsym->symbols[idx];
            const char* name = dynstr->getStringAt(sym.st_name);
            if (!name) {
                continue;
            }
            const uint32_t h = gnu_hash(name);
            const uint32_t b = h % nbuckets_gnu;
            const uint32_t chain_idx = idx - symoffset;
            uint32_t val = h & ~1U;
            if (idx == last_in_bucket[b]) {
                val |= 1U;
            }
            if (chain_idx < gnu_chain.size()) {
                gnu_chain[chain_idx] = val;
            }
        }

        std::vector<uint8_t> gnu_payload;
        gnu_payload.resize(sizeof(uint32_t) * 4 +
                           sizeof(uint64_t) * bloom_size +
                           sizeof(uint32_t) * nbuckets_gnu +
                           sizeof(uint32_t) * gnu_chain.size());
        uint8_t* out = gnu_payload.data();
        auto write_u32 = [&out](uint32_t value) {
            std::memcpy(out, &value, sizeof(uint32_t));
            out += sizeof(uint32_t);
        };
        write_u32(nbuckets_gnu);
        write_u32(symoffset);
        write_u32(bloom_size);
        write_u32(bloom_shift);
        std::memcpy(out, bloom.data(), bloom_size * sizeof(uint64_t));
        out += bloom_size * sizeof(uint64_t);
        std::memcpy(out, gnu_buckets.data(), nbuckets_gnu * sizeof(uint32_t));
        out += nbuckets_gnu * sizeof(uint32_t);
        if (!gnu_chain.empty()) {
            std::memcpy(out, gnu_chain.data(), gnu_chain.size() * sizeof(uint32_t));
        }

        auto find_existing_section = [this](const std::string& name) -> zSectionTableElement* {
            const int idx = sh_table_model_.findByName(name);
            return idx >= 0 ? sh_table_model_.get((size_t)idx) : nullptr;
        };

        auto* hash_sec = find_existing_section(".hash");
        auto* gnu_sec = find_existing_section(".gnu.hash");
        if (!gnu_sec) {
            return false;
        }

        auto select_ro_load = [this]() -> int {
            int ro_idx = -1;
            for (size_t idx = 0; idx < ph_table_model_.elements.size(); ++idx) {
                const auto& ph = ph_table_model_.elements[idx];
                if (ph.type != PT_LOAD) {
                    continue;
                }
                if ((ph.flags & PF_W) == 0 && (ph.flags & PF_R) != 0) {
                    ro_idx = (int)idx;
                    break;
                }
            }
            if (ro_idx < 0) {
                ro_idx = ph_table_model_.findFirstByType(PT_LOAD);
            }
            return ro_idx;
        };

        auto place_at_ro_end = [this, file_align, &select_ro_load](zSectionTableElement* sec,
                                                  const std::vector<uint8_t>& payload,
                                                  Elf64_Word type,
                                                  Elf64_Xword entsize,
                                                  Elf64_Word link,
                                                  Elf64_Off* io_cursor) -> bool {
            if (!sec || !io_cursor) {
                return false;
            }
            auto try_place = [&](size_t idx) -> bool {
                auto& ph = ph_table_model_.elements[idx];
                uint64_t next_load_off = std::numeric_limits<uint64_t>::max();
                for (const auto& other : ph_table_model_.elements) {
                    if (other.type != PT_LOAD || other.offset <= ph.offset) {
                        continue;
                    }
                    next_load_off = std::min<uint64_t>(next_load_off, other.offset);
                }

                Elf64_Off cur = *io_cursor;
                if (cur < (Elf64_Off)(ph.offset + ph.filesz)) {
                    cur = (Elf64_Off)(ph.offset + ph.filesz);
                }
                cur = align_up_off(cur, file_align);
                const uint64_t new_end = (uint64_t)cur + payload.size();
                if (next_load_off != std::numeric_limits<uint64_t>::max() && new_end > next_load_off) {
                    return false;
                }

                sec->type = type;
                sec->flags |= SHF_ALLOC;
                sec->payload = payload;
                sec->size = (Elf64_Xword)payload.size();
                sec->addralign = file_align;
                sec->entsize = entsize;
                sec->link = link;
                sec->offset = cur;
                sec->addr = (Elf64_Addr)(ph.vaddr + (sec->offset - ph.offset));
                sec->syncHeader();

                const Elf64_Off sec_end = sec->offset + (Elf64_Off)sec->size;
                if (sec_end > ph.offset + ph.filesz) {
                    ph.filesz = (Elf64_Xword)(sec_end - ph.offset);
                }
                if (ph.memsz < ph.filesz) {
                    ph.memsz = ph.filesz;
                }
                *io_cursor = sec_end;
                return true;
            };

            const int ro_idx = select_ro_load();
            if (ro_idx >= 0 && try_place((size_t)ro_idx)) {
                return true;
            }

            // 回退：放到最后一个 PT_LOAD，避免与后续段重叠。
            int last_load = -1;
            for (size_t idx = 0; idx < ph_table_model_.elements.size(); ++idx) {
                if (ph_table_model_.elements[idx].type == PT_LOAD) {
                    last_load = (int)idx;
                }
            }
            if (last_load >= 0) {
                return try_place((size_t)last_load);
            }
            return false;
        };

        Elf64_Off ro_cursor = 0;

        if (hash_sec) {
            if (hash_payload.size() <= hash_sec->size) {
                hash_sec->type = SHT_HASH;
                hash_sec->flags |= SHF_ALLOC;
                hash_sec->payload = hash_payload;
                hash_sec->addralign = 4;
                hash_sec->entsize = sizeof(uint32_t);
                hash_sec->link = (Elf64_Word)dynsym_idx;
                hash_sec->syncHeader();
            } else {
                if (!place_at_ro_end(hash_sec,
                                     hash_payload,
                                     SHT_HASH,
                                     sizeof(uint32_t),
                                     (Elf64_Word)dynsym_idx,
                                     &ro_cursor)) {
                    return false;
                }
            }
        }

        if (gnu_payload.size() <= gnu_sec->size) {
            gnu_sec->type = SHT_GNU_HASH;
            gnu_sec->flags |= SHF_ALLOC;
            gnu_sec->payload = gnu_payload;
            gnu_sec->addralign = 8;
            gnu_sec->entsize = 0;
            gnu_sec->link = (Elf64_Word)dynsym_idx;
            gnu_sec->syncHeader();
        } else {
            if (!place_at_ro_end(gnu_sec,
                                 gnu_payload,
                                 SHT_GNU_HASH,
                                 0,
                                 (Elf64_Word)dynsym_idx,
                                 &ro_cursor)) {
                return false;
            }
        }

        auto* dynamic_sec = dynamic_cast<zDynamicSection*>(sh_table_model_.get((size_t)sh_table_model_.findByName(".dynamic")));
        if (!dynamic_sec) {
            return false;
        }
        auto upsert_dyn = [dynamic_sec](Elf64_Sxword tag, Elf64_Xword value) {
            for (auto& entry : dynamic_sec->entries) {
                if (entry.d_tag == tag) {
                    entry.d_un.d_ptr = value;
                    return;
                }
            }
            Elf64_Dyn dyn{};
            dyn.d_tag = tag;
            dyn.d_un.d_ptr = value;
            if (!dynamic_sec->entries.empty() && dynamic_sec->entries.back().d_tag == DT_NULL) {
                dynamic_sec->entries.insert(dynamic_sec->entries.end() - 1, dyn);
            } else {
                dynamic_sec->entries.push_back(dyn);
            }
        };

        if (hash_sec) {
            upsert_dyn(DT_HASH, hash_sec->addr);
        }
        upsert_dyn(DT_GNU_HASH, gnu_sec->addr);
        if (!hash_sec) {
            dynamic_sec->entries.erase(
                    std::remove_if(dynamic_sec->entries.begin(),
                                   dynamic_sec->entries.end(),
                                   [](const Elf64_Dyn& dyn) { return dyn.d_tag == DT_HASH; }),
                    dynamic_sec->entries.end());
        }
        dynamic_sec->syncHeader();
        return true;
    };

    if (!rebuild_dynamic_hash_tables(FILE_ALIGN)) {
        LOGE("Reconstruction failed: rebuild hash tables");
        return false;
    }

    for (auto& blob : pending_blobs_) {
        if (blob.bytes.empty()) {
            continue;
        }
        if (blob.offset == 0) {
            blob.offset = next_file_off;
            next_file_off = align_up_off(next_file_off + (Elf64_Off)blob.bytes.size(), PAGE_SIZE);
        } else {
            next_file_off = std::max(next_file_off,
                                     align_up_off(blob.offset + (Elf64_Off)blob.bytes.size(), PAGE_SIZE));
        }
    }

    struct SectionSnapshot {
        size_t index = 0;
        Elf64_Addr addr = 0;
        Elf64_Xword size = 0;
    };

    struct ExecSectionSnapshot {
        size_t index = 0;
        std::string name;
        Elf64_Addr old_addr = 0;
        std::vector<uint8_t> payload;
    };

    std::vector<SectionSnapshot> old_sections;
    std::vector<ExecSectionSnapshot> exec_sections;

    auto load_section_payload = [this](const zSectionTableElement& section,
                                       std::vector<uint8_t>* out) -> bool {
        if (!out) {
            return false;
        }
        out->clear();
        if (!section.payload.empty()) {
            *out = section.payload;
            return true;
        }
        if (section.type == SHT_NOBITS || section.size == 0) {
            return true;
        }
        const uint64_t begin = section.offset;
        const uint64_t end = begin + section.size;
        if (end > file_image_.size()) {
            LOGE("Reconstruction failed: section payload out of range name=%s offset=0x%llx size=0x%llx",
                 section.resolved_name.c_str(),
                 (unsigned long long)section.offset,
                 (unsigned long long)section.size);
            return false;
        }
        out->assign(file_image_.begin() + (size_t)begin, file_image_.begin() + (size_t)end);
        return true;
    };

    for (size_t idx = 0; idx < sh_table_model_.elements.size(); ++idx) {
        const auto* section = sh_table_model_.elements[idx].get();
        if (!section || section->size == 0) {
            continue;
        }
        if ((section->flags & SHF_ALLOC) != 0 && section->addr != 0) {
            SectionSnapshot snap;
            snap.index = idx;
            snap.addr = section->addr;
            snap.size = section->size;
            old_sections.push_back(snap);
        }
        if ((section->flags & SHF_EXECINSTR) != 0 &&
            section->type != SHT_NOBITS &&
            section->addr != 0) {
            ExecSectionSnapshot exec;
            exec.index = idx;
            exec.name = section->resolved_name;
            exec.old_addr = section->addr;
            if (!load_section_payload(*section, &exec.payload)) {
                return false;
            }
            if (!exec.payload.empty()) {
                exec_sections.push_back(std::move(exec));
            }
        }
    }

    // PC-relative prepass deferred: only expand sections that actually need to move.
    // The prepass is applied AFTER layout determines which sections changed address.

    for (auto& ph : ph_table_model_.elements) {
        if (ph.type != PT_LOAD) {
            continue;
        }
        if (ph.align == 0) {
            ph.align = PAGE_SIZE;
        }
        if (ph.filesz > 0 && ph.memsz < ph.filesz) {
            ph.memsz = ph.filesz;
        }
    }

    // Section-first layout: allocate SHF_ALLOC sections inside PT_LOAD using a "dot" cursor.
    std::vector<zSectionTableElement*> alloc_sections;
    alloc_sections.reserve(sh_table_model_.elements.size());
    for (auto& sec_ptr : sh_table_model_.elements) {
        auto& sec = *sec_ptr;
        sec.syncHeader();
        if (sec.type == SHT_NULL) {
            sec.offset = 0;
            sec.addr = 0;
            continue;
        }
        if (sec.type == SHT_NOBITS) {
            continue;
        }
        if ((sec.flags & SHF_ALLOC) == 0) {
            continue;
        }
        if (sec.size == 0) {
            continue;
        }
        alloc_sections.push_back(sec_ptr.get());
    }

    auto section_sort_key = [](const zSectionTableElement* a, const zSectionTableElement* b) {
        const uint64_t ao = a->offset ? a->offset : (uint64_t)a->addr;
        const uint64_t bo = b->offset ? b->offset : (uint64_t)b->addr;
        if (ao != bo) {
            return ao < bo;
        }
        return a->name < b->name;
    };
    std::sort(alloc_sections.begin(), alloc_sections.end(), section_sort_key);

    std::unordered_map<const zSectionTableElement*, uint64_t> next_alloc_file_offset;
    for (size_t idx = 0; idx + 1 < alloc_sections.size(); ++idx) {
        const auto* current = alloc_sections[idx];
        const auto* next = alloc_sections[idx + 1];
        if (!current || !next) {
            continue;
        }
        next_alloc_file_offset[current] = (uint64_t)next->offset;
    }

    auto overlaps_next_alloc_section = [&next_alloc_file_offset](const zSectionTableElement& section,
                                                                 uint64_t section_file_end) -> bool {
        const auto it = next_alloc_file_offset.find(&section);
        if (it == next_alloc_file_offset.end()) {
            return false;
        }
        const uint64_t next_off = it->second;
        if (next_off == 0) {
            return false;
        }
        return section_file_end > next_off;
    };

    struct LoadCursor {
        size_t ph_idx;
        uint64_t cursor;
    };
    std::vector<LoadCursor> load_cursors;
    load_cursors.reserve(ph_table_model_.elements.size());
    for (size_t idx = 0; idx < ph_table_model_.elements.size(); ++idx) {
        const auto& ph = ph_table_model_.elements[idx];
        if (ph.type != PT_LOAD) {
            continue;
        }
        uint64_t start = std::max<uint64_t>(ph.offset, (uint64_t)next_file_off);
        start = align_up_u64(start, FILE_ALIGN);
        load_cursors.push_back({idx, start});
    }

    auto find_load_cursor = [&load_cursors](size_t ph_idx) -> LoadCursor* {
        for (auto& cur : load_cursors) {
            if (cur.ph_idx == ph_idx) {
                return &cur;
            }
        }
        return nullptr;
    };

    for (size_t idx = 0; idx < alloc_sections.size(); ++idx) {
        auto& section = *alloc_sections[idx];
        bool mapped = false;

        // Prefer keeping the section inside an already matching PT_LOAD range.
        for (size_t ph_idx = 0; ph_idx < ph_table_model_.elements.size(); ++ph_idx) {
            auto& ph = ph_table_model_.elements[ph_idx];
            if (!load_segment_matches_section_flags(ph, section)) {
                continue;
            }
            const uint64_t file_start = ph.offset;
            const uint64_t file_end = ph.offset + ph.filesz;
            if (section.offset >= file_start && section.offset < file_end) {
                section.addr = (Elf64_Addr)(ph.vaddr + (section.offset - ph.offset));
                const uint64_t section_file_end = section.offset + section.size;
                if (overlaps_next_alloc_section(section, section_file_end)) {
                    LOGW("Section '%s' grows into next alloc section, will relocate via cursor",
                         section.resolved_name.c_str());
                    break;
                }
                const uint64_t section_mem_end = section.addr + section.size;
                uint64_t new_filesz = ph.filesz;
                uint64_t new_memsz = ph.memsz;
                if (section_file_end > file_end) {
                    new_filesz = (Elf64_Xword)(section_file_end - ph.offset);
                }
                if (section_mem_end > ph.vaddr + ph.memsz) {
                    new_memsz = (Elf64_Xword)(section_mem_end - ph.vaddr);
                }
                if (new_filesz != ph.filesz || new_memsz != ph.memsz) {
                    if (!check_load_expansion_safe(ph_table_model_.elements, ph_idx,
                                                   new_filesz, new_memsz)) {
                        // Expansion would conflict - fall through to cursor-based allocation.
                        LOGW("Section '%s' grew beyond LOAD[%zu] boundary, will relocate via cursor",
                             section.resolved_name.c_str(), ph_idx);
                        break;
                    }
                }
                ph.filesz = new_filesz;
                ph.memsz = new_memsz;
                mapped = true;
                break;
            }
        }

        if (!mapped) {
            for (size_t ph_idx = 0; ph_idx < ph_table_model_.elements.size(); ++ph_idx) {
                auto& ph = ph_table_model_.elements[ph_idx];
                if (!load_segment_matches_section_flags(ph, section)) {
                    continue;
                }
                LoadCursor* cursor = find_load_cursor(ph_idx);
                if (!cursor) {
                    continue;
                }

                const uint64_t section_align =
                        std::max<uint64_t>(section.addralign > 0 ? section.addralign : 1,
                                           ph.align > 0 ? ph.align : PAGE_SIZE);
                uint64_t aligned_off = align_up_u64(cursor->cursor, section_align);
                if (aligned_off < ph.offset + ph.filesz) {
                    aligned_off = align_up_u64(ph.offset + ph.filesz, section_align);
                }

                uint64_t tentative_vaddr = ph.vaddr + (aligned_off - ph.offset);
                const uint64_t page_size = ph.align > 0 ? ph.align : PAGE_SIZE;
                if ((aligned_off % page_size) != (tentative_vaddr % page_size)) {
                    aligned_off = align_to_congruent(aligned_off, tentative_vaddr, page_size);
                    if (aligned_off < ph.offset + ph.filesz) {
                        aligned_off = align_up_u64(aligned_off, page_size);
                        aligned_off = align_to_congruent(aligned_off, tentative_vaddr, page_size);
                    }
                    tentative_vaddr = ph.vaddr + (aligned_off - ph.offset);
                }

                if ((aligned_off % page_size) != (tentative_vaddr % page_size)) {
                    LOGE("Reconstruction failed: cannot satisfy offset/vaddr congruence constraint at section index %zu, "
                         "offset=0x%llx (mod 0x%llx = 0x%llx), vaddr=0x%llx (mod 0x%llx = 0x%llx)",
                         idx,
                         (unsigned long long)aligned_off, (unsigned long long)page_size,
                         (unsigned long long)(aligned_off % page_size),
                         (unsigned long long)tentative_vaddr, (unsigned long long)page_size,
                         (unsigned long long)(tentative_vaddr % page_size));
                    return false;
                }

                const uint64_t section_file_end = aligned_off + section.size;
                const uint64_t section_mem_end = tentative_vaddr + section.size;
                const uint64_t new_filesz = std::max<uint64_t>(ph.filesz, section_file_end - ph.offset);
                const uint64_t new_memsz = std::max<uint64_t>(ph.memsz, section_mem_end - ph.vaddr);

                if (!check_load_expansion_safe(ph_table_model_.elements, ph_idx, new_filesz, new_memsz)) {
                    continue;
                }

                section.offset = (Elf64_Off)aligned_off;
                section.addr = (Elf64_Addr)tentative_vaddr;
                ph.filesz = (Elf64_Xword)new_filesz;
                ph.memsz = (Elf64_Xword)new_memsz;
                cursor->cursor = section_file_end;
                mapped = true;
                break;
            }
        }

        if (!mapped && section.size > 0) {
            // Create a new LOAD segment to accommodate this section.
            const uint64_t seg_align = PAGE_SIZE;
            uint64_t data_max = file_image_.size();
            for (const auto& p : ph_table_model_.elements) {
                if (p.type == PT_LOAD && p.filesz > 0) {
                    data_max = std::max<uint64_t>(data_max, p.offset + p.filesz);
                }
            }
            for (const auto& s : sh_table_model_.elements) {
                if (s && s->type != SHT_NOBITS && s->size > 0 && s->offset > 0) {
                    data_max = std::max<uint64_t>(data_max, s->offset + s->size);
                }
            }
            const Elf64_Off new_load_off = align_up_off((Elf64_Off)data_max, (Elf64_Off)seg_align);
            uint64_t vaddr_max = 0;
            for (const auto& p : ph_table_model_.elements) {
                if (p.type == PT_LOAD) {
                    vaddr_max = std::max<uint64_t>(vaddr_max, p.vaddr + p.memsz);
                }
            }
            const Elf64_Addr new_load_vaddr = (Elf64_Addr)align_up_u64(vaddr_max, seg_align);

            // Determine flags from section flags.
            Elf32_Word seg_flags = PF_R;
            if (section.flags & SHF_EXECINSTR) {
                seg_flags |= PF_X;
            }
            if (section.flags & SHF_WRITE) {
                seg_flags |= PF_W;
            }

            const Elf64_Off sec_off = new_load_off;
            const Elf64_Addr sec_addr = new_load_vaddr;

            zProgramTableElement new_load;
            new_load.type = PT_LOAD;
            new_load.flags = seg_flags;
            new_load.offset = new_load_off;
            new_load.vaddr = new_load_vaddr;
            new_load.paddr = new_load_vaddr;
            new_load.filesz = (Elf64_Xword)section.size;
            new_load.memsz = (Elf64_Xword)section.size;
            new_load.align = seg_align;
            ph_table_model_.elements.push_back(new_load);
            header_model_.raw.e_phnum = (Elf64_Half)ph_table_model_.elements.size();

            section.offset = sec_off;
            section.addr = sec_addr;
            mapped = true;

            LOGW("Created new LOAD segment for section '%s': off=0x%llx vaddr=0x%llx size=0x%llx flags=0x%x",
                 section.resolved_name.c_str(),
                 (unsigned long long)new_load_off,
                 (unsigned long long)new_load_vaddr,
                 (unsigned long long)section.size,
                 seg_flags);
        }

        if (!mapped) {
            section.addr = 0;
            section.offset = 0;
        }
    }

    // Non-ALLOC sections are laid out after all alloc sections using a file "dot".
    for (auto& sec_ptr : sh_table_model_.elements) {
        auto& section = *sec_ptr;
        if (section.type == SHT_NULL || section.type == SHT_NOBITS) {
            continue;
        }
        if ((section.flags & SHF_ALLOC) != 0) {
            if (section.offset > 0) {
                next_file_off = std::max(next_file_off,
                                         align_up_off(section.offset + (Elf64_Off)section.payload.size(), FILE_ALIGN));
            }
            continue;
        }
        if (section.payload.empty()) {
            continue;
        }
        const Elf64_Off section_align = section.addralign > 1 ? (Elf64_Off)section.addralign : FILE_ALIGN;
        const Elf64_Off required_start = align_up_off(next_file_off, section_align);
        if (section.offset == 0 || section.offset < required_start) {
            section.offset = required_start;
        }
        next_file_off = align_up_off(section.offset + (Elf64_Off)section.payload.size(), FILE_ALIGN);
    }

    for (size_t idx = 0; idx < sh_table_model_.elements.size(); ++idx) {
        auto& section = *sh_table_model_.elements[idx];
        if (section.type == SHT_NULL) {
            continue;
        }

        if (section.type == SHT_NOBITS) {
            if ((section.flags & SHF_ALLOC) == 0) {
                continue;
            }
            bool mapped_nobits = false;
            for (auto& ph : ph_table_model_.elements) {
                if (!load_segment_matches_section_flags(ph, section)) {
                    continue;
                }

                if (section.addr >= ph.vaddr && section.addr <= ph.vaddr + ph.memsz) {
                    // NOBITS must be placed at or after file-backed end of the segment.
                    // If current addr falls into file-backed range due segment expansion,
                    // keep it in this segment and slide it behind p_filesz.
                    uint64_t target_addr = section.addr;
                    if (target_addr < ph.vaddr + ph.filesz) {
                        target_addr = align_up_u64(ph.vaddr + ph.filesz,
                                                   std::max<uint64_t>(1, section.addralign));
                    }
                    section.addr = (Elf64_Addr)target_addr;
                    const uint64_t section_mem_end = target_addr + section.size;
                    if (section_mem_end > ph.vaddr + ph.memsz) {
                        ph.memsz = (Elf64_Xword)(section_mem_end - ph.vaddr);
                    }
                    // 修复: NOBITS 节的 offset 应该指向它在 LOAD 段中对应的"虚拟"文件位置
                    // 即使 NOBITS 不占文件空间，offset 仍需满足 vaddr-offset 映射关系
                    section.offset = (Elf64_Off)(ph.offset + (section.addr - ph.vaddr));
                    mapped_nobits = true;
                    break;
                }
            }
            if (!mapped_nobits) {
                for (auto& ph : ph_table_model_.elements) {
                    if (!load_segment_matches_section_flags(ph, section)) {
                        continue;
                    }
                    const uint64_t aligned_addr = align_up_u64(ph.vaddr + ph.memsz,
                                                               std::max<uint64_t>(1, section.addralign));
                    section.addr = (Elf64_Addr)aligned_addr;
                    const uint64_t section_mem_end = aligned_addr + section.size;
                    ph.memsz = std::max<Elf64_Xword>(ph.memsz,
                                                     (Elf64_Xword)(section_mem_end - ph.vaddr));
                    // 修复: 设置 NOBITS 的 offset，使其与 addr 保持一致的映射关系
                    // offset 指向段末尾的文件位置（即 filesz 的位置）
                    section.offset = (Elf64_Off)(ph.offset + (section.addr - ph.vaddr));
                    mapped_nobits = true;
                    break;
                }
            }
            if (!mapped_nobits) {
                section.addr = 0;
                section.offset = 0;  // 修复: 如果未映射，offset 也应该清零
            }
            continue;
        }

        if (section.payload.empty()) {
            continue;
        }

        if ((section.flags & SHF_ALLOC) == 0) {
            section.addr = 0;
            continue;
        }

        bool mapped = false;
        for (size_t ph_idx = 0; ph_idx < ph_table_model_.elements.size(); ++ph_idx) {
            auto& ph = ph_table_model_.elements[ph_idx];
            if (!load_segment_matches_section_flags(ph, section)) {
                continue;
            }
            const uint64_t file_start = ph.offset;
            uint64_t file_end = ph.offset + ph.filesz;
            if (section.offset >= file_start && section.offset < file_end) {
                section.addr = (Elf64_Addr)(ph.vaddr + (section.offset - ph.offset));
                const uint64_t section_file_end = section.offset + section.size;
                const uint64_t section_mem_end = section.addr + section.size;

                // 修复: 在扩展 LOAD 段之前，检查是否会与其他 LOAD 段冲突
                uint64_t new_filesz = ph.filesz;
                uint64_t new_memsz = ph.memsz;

                if (section_file_end > file_end) {
                    new_filesz = (Elf64_Xword)(section_file_end - ph.offset);
                }
                if (section_mem_end > ph.vaddr + ph.memsz) {
                    new_memsz = (Elf64_Xword)(section_mem_end - ph.vaddr);
                }

                // 检查扩展是否安全
                if (new_filesz != ph.filesz || new_memsz != ph.memsz) {
                    if (!check_load_expansion_safe(ph_table_model_.elements, ph_idx,
                                                   new_filesz, new_memsz)) {
                        LOGE("Reconstruction failed: extending LOAD segment would conflict with other segments at section index %zu",
                             idx);
                        return false;
                    }
                }

                // 安全后才执行扩展
                ph.filesz = new_filesz;
                ph.memsz = new_memsz;
                mapped = true;
                break;
            }
        }

        if (!mapped) {
            for (size_t ph_idx = 0; ph_idx < ph_table_model_.elements.size(); ++ph_idx) {
                auto& ph = ph_table_model_.elements[ph_idx];
                if (!load_segment_matches_section_flags(ph, section)) {
                    continue;
                }

                // 第一步：对齐到段对齐边界
                uint64_t aligned_off = align_up_u64(section.offset, std::max<uint64_t>(1, ph.align));

                // 必须在段的 filesz 之后
                if (aligned_off < ph.offset + ph.filesz) {
                    continue;
                }

                // 第二步：计算初步的虚拟地址
                uint64_t tentative_vaddr = ph.vaddr + (aligned_off - ph.offset);

                // 修复: 关键约束 - 确保 (offset % page_size) == (vaddr % page_size)
                // 这是 ELF 加载器的硬性要求，Android linker 严格检查此约束
                const uint64_t page_size = ph.align > 0 ? ph.align : PAGE_SIZE;

                // 检查是否满足模运算同余
                const uint64_t off_mod = aligned_off % page_size;
                const uint64_t vaddr_mod = tentative_vaddr % page_size;

                if (off_mod != vaddr_mod) {
                    // 不满足同余条件，需要调整 offset
                    // 策略：保持 vaddr 不变，调整 offset 使其与 vaddr 同余
                    aligned_off = align_to_congruent(aligned_off, tentative_vaddr, page_size);

                    // 重新验证调整后的 offset 是否仍然在段末尾之后
                    if (aligned_off < ph.offset + ph.filesz) {
                        // 如果调整后反而冲突，则向上对齐一个页面后再试
                        aligned_off = align_up_u64(aligned_off, page_size);
                        aligned_off = align_to_congruent(aligned_off, tentative_vaddr, page_size);

                        if (aligned_off < ph.offset + ph.filesz) {
                            // 仍然冲突，跳过这个段，尝试下一个
                            continue;
                        }
                    }

                    // 重新计算 vaddr
                    tentative_vaddr = ph.vaddr + (aligned_off - ph.offset);
                }

                // 第三步：验证调整后的参数是否有效
                const uint64_t final_off_mod = aligned_off % page_size;
                const uint64_t final_vaddr_mod = tentative_vaddr % page_size;

                if (final_off_mod != final_vaddr_mod) {
                    // 理论上不应该到这里，但作为安全检查
                    LOGE("Reconstruction failed: cannot satisfy offset/vaddr congruence constraint at section index %zu, "
                         "offset=0x%llx (mod 0x%llx = 0x%llx), vaddr=0x%llx (mod 0x%llx = 0x%llx)",
                         idx,
                         (unsigned long long)aligned_off, (unsigned long long)page_size, (unsigned long long)final_off_mod,
                         (unsigned long long)tentative_vaddr, (unsigned long long)page_size, (unsigned long long)final_vaddr_mod);
                    return false;
                }

                // 第四步：计算扩展后的段大小
                const uint64_t section_file_end = aligned_off + section.size;
                const uint64_t section_mem_end = tentative_vaddr + section.size;
                const uint64_t new_filesz = std::max<uint64_t>(ph.filesz, section_file_end - ph.offset);
                const uint64_t new_memsz = std::max<uint64_t>(ph.memsz, section_mem_end - ph.vaddr);

                // 第五步：检查扩展是否会与其他 LOAD 段冲突
                if (!check_load_expansion_safe(ph_table_model_.elements, ph_idx, new_filesz, new_memsz)) {
                    // 冲突，尝试下一个段
                    continue;
                }

                // 第六步：所有检查通过，提交修改
                section.offset = (Elf64_Off)aligned_off;
                section.addr = (Elf64_Addr)tentative_vaddr;
                ph.filesz = (Elf64_Xword)new_filesz;
                ph.memsz = (Elf64_Xword)new_memsz;
                mapped = true;
                break;
            }
        }

        if (!mapped) {
            section.addr = 0;
        }
    }

    for (auto& ph : ph_table_model_.elements) {
        if (ph.type != PT_PHDR) {
            continue;
        }
        ph.offset = header_model_.raw.e_phoff;
        ph.filesz = (Elf64_Xword)((uint64_t)header_model_.raw.e_phnum * sizeof(Elf64_Phdr));
        ph.memsz = ph.filesz;
        ph.vaddr = 0;
        ph.paddr = 0;
        const uint64_t phdr_begin = ph.offset;
        const uint64_t phdr_end = phdr_begin + ph.filesz;
        bool mapped = false;
        for (auto& load : ph_table_model_.elements) {
            if (load.type != PT_LOAD || load.filesz == 0) {
                continue;
            }
            const uint64_t load_begin = load.offset;
            uint64_t load_end = load.offset + load.filesz;
            if (phdr_begin < load_begin || phdr_begin >= load_end) {
                continue;
            }
            if (phdr_end > load_end) {
                load.filesz = (Elf64_Xword)(phdr_end - load.offset);
                load_end = phdr_end;
                const uint64_t load_mem_end = (uint64_t)load.vaddr + load.memsz;
                const uint64_t required_mem_end = (uint64_t)load.vaddr + (load_end - load.offset);
                if (required_mem_end > load_mem_end) {
                    load.memsz = (Elf64_Xword)(required_mem_end - load.vaddr);
                }
            }
            if (phdr_end <= load_end) {
                ph.vaddr = (Elf64_Addr)(load.vaddr + (ph.offset - load.offset));
                ph.paddr = ph.vaddr;
                mapped = true;
                break;
            }
        }
        if (!mapped) {
            LOGE("Reconstruction failed: PT_PHDR is not mapped by PT_LOAD, phoff=0x%llx size=0x%llx",
                 (unsigned long long)ph.offset,
                 (unsigned long long)ph.filesz);
            return false;
        }
        break;
    }

    // Check if any alloc sections actually changed their virtual address.
    bool any_section_moved = false;
    for (const auto& snap : old_sections) {
        const auto* cur_sec = sh_table_model_.elements[snap.index].get();
        if (!cur_sec) {
            continue;
        }
        if (cur_sec->addr != snap.addr) {
            any_section_moved = true;
            break;
        }
    }

    if (any_section_moved && !exec_sections.empty()) {
        auto relocate_old_addr = [this, &old_sections](uint64_t old_addr) -> uint64_t {
            for (const auto& snap : old_sections) {
                if (snap.size == 0) {
                    continue;
                }
                if (old_addr < snap.addr || old_addr >= snap.addr + snap.size) {
                    continue;
                }
                const auto* new_sec = sh_table_model_.elements[snap.index].get();
                if (!new_sec || new_sec->addr == 0) {
                    return old_addr;
                }
                return (uint64_t)new_sec->addr + (old_addr - snap.addr);
            }
            return old_addr;
        };

        // Apply PC-relative patching only when sections actually moved.
        // First, expand (prepass) to determine sizes, then re-patch with new addresses.
        for (const auto& exec : exec_sections) {
            auto* section = sh_table_model_.elements[exec.index].get();
            if (!section) {
                continue;
            }

            // Check if this specific section moved.
            if ((uint64_t)section->addr == exec.old_addr) {
                // Section didn't move, no patching needed.
                continue;
            }

            std::vector<uint8_t> patched;
            PatchStats stats;
            if (!patch_aarch64_pc_relative_payload(exec.payload,
                                                   exec.old_addr,
                                                   relocate_old_addr,
                                                   &patched,
                                                   &stats,
                                                   exec.name.c_str())) {
                LOGE("Reconstruction failed: pc-relative patching section=%s", exec.name.c_str());
                return false;
            }
            // Patched output may differ in size from original (expansion).
            // Update section payload and size accordingly.
            section->payload.swap(patched);
            section->syncHeader();
        }
    }

    auto* dynamic_sec = dynamic_cast<zDynamicSection*>(
            sh_table_model_.get((size_t)sh_table_model_.findByName(".dynamic")));
    if (dynamic_sec) {
        auto set_dyn_if_present = [dynamic_sec](Elf64_Sxword tag, Elf64_Xword value) {
            for (auto& entry : dynamic_sec->entries) {
                if (entry.d_tag == tag) {
                    entry.d_un.d_ptr = value;
                    return;
                }
            }
        };
        auto find_sec = [this](const char* name) -> const zSectionTableElement* {
            const int idx = sh_table_model_.findByName(name);
            return idx >= 0 ? sh_table_model_.get((size_t)idx) : nullptr;
        };

        if (const auto* dynsym = find_sec(".dynsym")) {
            set_dyn_if_present(DT_SYMTAB, dynsym->addr);
            set_dyn_if_present(DT_SYMENT, dynsym->entsize ? dynsym->entsize : sizeof(Elf64_Sym));
        }
        if (const auto* dynstr = find_sec(".dynstr")) {
            set_dyn_if_present(DT_STRTAB, dynstr->addr);
            set_dyn_if_present(DT_STRSZ, dynstr->size);
        }
        if (const auto* versym = find_sec(".gnu.version")) {
            set_dyn_if_present(DT_VERSYM, versym->addr);
        }
        if (const auto* verneed = find_sec(".gnu.version_r")) {
            set_dyn_if_present(DT_VERNEED, verneed->addr);
            if (verneed->info != 0) {
                set_dyn_if_present(DT_VERNEEDNUM, verneed->info);
            }
        }
        if (const auto* gnu_hash = find_sec(".gnu.hash")) {
            set_dyn_if_present(DT_GNU_HASH, gnu_hash->addr);
        }
        if (const auto* sysv_hash = find_sec(".hash")) {
            set_dyn_if_present(DT_HASH, sysv_hash->addr);
        }
        if (const auto* rela_dyn = find_sec(".rela.dyn")) {
            set_dyn_if_present(DT_RELA, rela_dyn->addr);
            set_dyn_if_present(DT_RELASZ, rela_dyn->size);
            set_dyn_if_present(DT_RELAENT, rela_dyn->entsize ? rela_dyn->entsize : sizeof(Elf64_Rela));
        }
        if (const auto* rela_plt = find_sec(".rela.plt")) {
            set_dyn_if_present(DT_JMPREL, rela_plt->addr);
            set_dyn_if_present(DT_PLTRELSZ, rela_plt->size);
            set_dyn_if_present(DT_PLTREL, DT_RELA);
        }
        dynamic_sec->syncHeader();
    }

    uint64_t data_end = next_file_off;
    for (const auto& blob : pending_blobs_) {
        data_end = std::max<uint64_t>(data_end, blob.offset + blob.bytes.size());
    }
    for (const auto& section : sh_table_model_.elements) {
        if (section->type == SHT_NOBITS) {
            continue;
        }
        data_end = std::max<uint64_t>(data_end, section->offset + section->size);
    }
    next_file_off = (Elf64_Off)data_end;

    next_file_off = align_up_off(next_file_off, (Elf64_Off)header_model_.raw.e_shentsize);
    header_model_.raw.e_shoff = next_file_off;
    header_model_.raw.e_shnum = (Elf64_Half)sh_table_model_.elements.size();
    if (header_model_.raw.e_shstrndx >= header_model_.raw.e_shnum) {
        header_model_.raw.e_shstrndx = SHN_UNDEF;
    }

    std::vector<Elf64_Phdr> raw_pht = ph_table_model_.toRaw();

    uint64_t new_size = std::max<uint64_t>(file_image_.size(), header_model_.raw.e_shoff);
    new_size += (uint64_t)header_model_.raw.e_shentsize * sh_table_model_.elements.size();

    for (const auto& blob : pending_blobs_) {
        new_size = std::max<uint64_t>(new_size, blob.offset + blob.bytes.size());
    }
    for (const auto& section : sh_table_model_.elements) {
        if (section->type == SHT_NOBITS) {
            continue;
        }
        new_size = std::max<uint64_t>(new_size, section->offset + section->payload.size());
    }
    new_size = std::max<uint64_t>(new_size,
                                  header_model_.raw.e_phoff +
                                  (uint64_t)raw_pht.size() * sizeof(Elf64_Phdr));

    if (new_size > std::numeric_limits<size_t>::max()) {
        LOGE("Reconstruction failed: size overflow");
        return false;
    }

    std::vector<uint8_t> new_image((size_t)new_size, 0);
    std::memcpy(new_image.data(), file_image_.data(), std::min(new_image.size(), file_image_.size()));

    for (const auto& blob : pending_blobs_) {
        if (blob.offset + blob.bytes.size() > new_image.size()) {
            LOGE("Reconstruction failed: blob out of range");
            return false;
        }
        std::memcpy(new_image.data() + blob.offset, blob.bytes.data(), blob.bytes.size());
    }

    for (const auto& section : sh_table_model_.elements) {
        if (section->type == SHT_NOBITS || section->payload.empty()) {
            continue;
        }
        if (section->offset + section->payload.size() > new_image.size()) {
            LOGE("Reconstruction failed: section out of range");
            return false;
        }
        std::memcpy(new_image.data() + section->offset, section->payload.data(), section->payload.size());
    }

    std::memcpy(new_image.data(), &header_model_.raw, sizeof(Elf64_Ehdr));
    if (!raw_pht.empty()) {
        std::memcpy(new_image.data() + header_model_.raw.e_phoff,
                    raw_pht.data(),
                    raw_pht.size() * sizeof(Elf64_Phdr));
    }

    std::vector<Elf64_Shdr> raw_sht = sh_table_model_.toRaw();
    if (!raw_sht.empty()) {
        std::memcpy(new_image.data() + header_model_.raw.e_shoff,
                    raw_sht.data(),
                    raw_sht.size() * sizeof(Elf64_Shdr));
    }

    file_image_.swap(new_image);
    pending_blobs_.clear();
    reconstruction_dirty_ = false;

    return true;
}
