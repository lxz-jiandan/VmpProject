#include "zPatchbayPatchApply.h"

// 引入字节区域读写与边界校验工具。
#include "zBytes.h"
// 引入 patchbay CRC 计算工具。
#include "zPatchbayCrc.h"
// 引入文件读写工具。
#include "zPatchbayIo.h"
// 引入 ELF 布局校验工具。
#include "zPatchbayLayout.h"
// 引入节结构定义。
#include "zSectionEntry.h"
// 引入日志接口。
#include "zLog.h"

// 引入 std::min。
#include <algorithm>
// 引入固定宽度整型。
#include <cstdint>
// 引入 memcpy。
#include <cstring>
// 引入字符串类型。
#include <string>
// 引入字节数组容器。
#include <vector>

// 进入匿名命名空间，封装内部辅助结构与函数。
namespace {

// patch 后新表的文件偏移与虚拟地址映射。
struct PatchLayout {
    // .dynsym 在文件中的绝对偏移。
    uint64_t dynsymFileOffset = 0;
    // .dynstr 在文件中的绝对偏移。
    uint64_t dynstrFileOffset = 0;
    // .gnu.hash 在文件中的绝对偏移。
    uint64_t gnuHashFileOffset = 0;
    // .gnu.version 在文件中的绝对偏移。
    uint64_t versymFileOffset = 0;
    // .hash 在文件中的绝对偏移（可选）。
    uint64_t sysvHashFileOffset = 0;

    // .dynsym 在内存映射中的虚拟地址。
    uint64_t dynsymVaddr = 0;
    // .dynstr 在内存映射中的虚拟地址。
    uint64_t dynstrVaddr = 0;
    // .gnu.hash 在内存映射中的虚拟地址。
    uint64_t gnuHashVaddr = 0;
    // .gnu.version 在内存映射中的虚拟地址。
    uint64_t versymVaddr = 0;
    // .hash 在内存映射中的虚拟地址（可选）。
    uint64_t sysvHashVaddr = 0;
};

// 校验 patchbay header 中各子区布局是否合法。
bool validatePatchbayRegions(const PatchBayHeader& header, std::string* error) {
    // 保存具体子区错误信息。
    std::string regionError;
    // 校验 dynsym 区域。
    if (!vmp::base::bytes::validateRegionAllowEmpty(header.headerSize,
                                                    header.totalSize,
                                                    header.dynsymOffset,
                                                    header.dynsymCapacity,
                                                    "dynsym",
                                                    &regionError) ||
        // 校验 dynstr 区域。
        !vmp::base::bytes::validateRegionAllowEmpty(header.headerSize,
                                                    header.totalSize,
                                                    header.dynstrOffset,
                                                    header.dynstrCapacity,
                                                    "dynstr",
                                                    &regionError) ||
        // 校验 gnu hash 区域。
        !vmp::base::bytes::validateRegionAllowEmpty(header.headerSize,
                                                    header.totalSize,
                                                    header.gnuHashOffset,
                                                    header.gnuHashCapacity,
                                                    "gnu_hash",
                                                    &regionError) ||
        // 校验 versym 区域。
        !vmp::base::bytes::validateRegionAllowEmpty(header.headerSize,
                                                    header.totalSize,
                                                    header.versymOffset,
                                                    header.versymCapacity,
                                                    "versym",
                                                    &regionError) ||
        // 校验 sysv hash 区域。
        !vmp::base::bytes::validateRegionAllowEmpty(header.headerSize,
                                                    header.totalSize,
                                                    header.sysvHashOffset,
                                                    header.sysvHashCapacity,
                                                    "sysv_hash",
                                                    &regionError)) {
        if (error != nullptr) {
            *error = "patchbay layout invalid: " + regionError;
        }
        return false;
    }
    return true;
}

// 校验新 payload 是否超出 patchbay 预留容量。
bool checkPatchbayCapacity(const PatchBayHeader& header,
                           size_t dynsymSize,
                           size_t dynstrSize,
                           size_t gnuHashSize,
                           size_t versymSize,
                           size_t sysvHashSize,
                           std::string* error) {
    // 任一子区超过 capacity 都直接失败。
    if (dynsymSize > header.dynsymCapacity ||
        dynstrSize > header.dynstrCapacity ||
        gnuHashSize > header.gnuHashCapacity ||
        versymSize > header.versymCapacity ||
        (sysvHashSize > 0 && sysvHashSize > header.sysvHashCapacity)) {
        if (error != nullptr) {
            *error = "patchbay capacity exceeded";
        }
        return false;
    }
    return true;
}

// 将各子区新 payload 写入 patchbay 区域（按容量填充）。
bool writePatchbayRegions(std::vector<uint8_t>* fileBytes,
                          uint64_t patchbayOffset,
                          const PatchBayHeader& header,
                          const std::vector<uint8_t>& dynsymBytes,
                          const std::vector<uint8_t>& dynstrBytes,
                          const std::vector<uint8_t>& gnuHashBytes,
                          const std::vector<uint8_t>& versymBytes,
                          const std::vector<uint8_t>& sysvHashBytes,
                          std::string* error) {
    // 输出缓冲区不能为空。
    if (fileBytes == nullptr) {
        if (error != nullptr) {
            *error = "patchbay write region failed: null file buffer";
        }
        return false;
    }

    // 保存具体写入错误信息。
    std::string regionError;
    // 依次写入 dynsym/dynstr/gnu hash/versym。
    if (!vmp::base::bytes::writeRegionPadded(fileBytes,
                                             patchbayOffset,
                                             header.dynsymOffset,
                                             header.dynsymCapacity,
                                             dynsymBytes,
                                             &regionError) ||
        !vmp::base::bytes::writeRegionPadded(fileBytes,
                                             patchbayOffset,
                                             header.dynstrOffset,
                                             header.dynstrCapacity,
                                             dynstrBytes,
                                             &regionError) ||
        !vmp::base::bytes::writeRegionPadded(fileBytes,
                                             patchbayOffset,
                                             header.gnuHashOffset,
                                             header.gnuHashCapacity,
                                             gnuHashBytes,
                                             &regionError) ||
        !vmp::base::bytes::writeRegionPadded(fileBytes,
                                             patchbayOffset,
                                             header.versymOffset,
                                             header.versymCapacity,
                                             versymBytes,
                                             &regionError)) {
        if (error != nullptr) {
            *error = "patchbay write region failed: " + regionError;
        }
        return false;
    }

    // sysv hash 可选：仅在 payload 非空且容量非 0 时写入。
    if (!sysvHashBytes.empty() && header.sysvHashCapacity > 0) {
        if (!vmp::base::bytes::writeRegionPadded(fileBytes,
                                                 patchbayOffset,
                                                 header.sysvHashOffset,
                                                 header.sysvHashCapacity,
                                                 sysvHashBytes,
                                                 &regionError)) {
            if (error != nullptr) {
                *error = "patchbay write region failed: " + regionError;
            }
            return false;
        }
    }

    return true;
}

// 根据 patchbay 节位置和 header 偏移关系构建绝对布局。
PatchLayout buildPatchLayout(const zSectionTableElement& patchbay, const PatchBayHeader& header) {
    PatchLayout layout;

    // 计算各表在文件中的绝对偏移。
    layout.dynsymFileOffset = patchbay.offset + header.dynsymOffset;
    layout.dynstrFileOffset = patchbay.offset + header.dynstrOffset;
    layout.gnuHashFileOffset = patchbay.offset + header.gnuHashOffset;
    layout.versymFileOffset = patchbay.offset + header.versymOffset;
    layout.sysvHashFileOffset = patchbay.offset + header.sysvHashOffset;

    // 计算各表在虚拟地址空间中的绝对地址。
    layout.dynsymVaddr = patchbay.addr + header.dynsymOffset;
    layout.dynstrVaddr = patchbay.addr + header.dynstrOffset;
    layout.gnuHashVaddr = patchbay.addr + header.gnuHashOffset;
    layout.versymVaddr = patchbay.addr + header.versymOffset;
    layout.sysvHashVaddr = patchbay.addr + header.sysvHashOffset;
    return layout;
}

// 读取某个 DT_* 指针值。
bool getDynPtr(const std::vector<Elf64_Dyn>& dynEntries, Elf64_Sxword tag, Elf64_Xword* out) {
    // 输出指针不能为空。
    if (out == nullptr) {
        return false;
    }
    // 遍历 dynamic 条目查找目标 tag。
    for (const Elf64_Dyn& ent : dynEntries) {
        if (ent.d_tag == tag) {
            *out = ent.d_un.d_ptr;
            return true;
        }
    }
    return false;
}

// 设置某个 DT_* 指针值。
bool setDynPtr(std::vector<Elf64_Dyn>* dynEntries, Elf64_Sxword tag, Elf64_Xword value) {
    // 输入数组不能为空。
    if (dynEntries == nullptr) {
        return false;
    }
    // 遍历 dynamic 条目查找目标 tag 并改写。
    for (Elf64_Dyn& ent : *dynEntries) {
        if (ent.d_tag == tag) {
            ent.d_un.d_ptr = value;
            return true;
        }
    }
    return false;
}

// 结束匿名命名空间。
} // namespace

// patchbay 主落盘流程。
bool applyPatchbayAliasPayload(const vmp::elfkit::PatchRequiredSections& required,
                               const char* inputPath,
                               const char* outputPath,
                               const std::vector<uint8_t>& newDynsymBytes,
                               const std::vector<uint8_t>& newDynstr,
                               const std::vector<uint8_t>& newVersym,
                               const std::vector<uint8_t>& newGnuHash,
                               const std::vector<uint8_t>& newSysvHash,
                               uint32_t slotUsedHint,
                               bool allowValidateFail,
                               bool* handled,
                               std::string* error) {
    // [阶段 0] 基础入参与路径预检。
    // 默认“未处理”，只有命中 patchbay 节才置为 true。
    if (handled != nullptr) {
        *handled = false;
    }

    // input/output/dynamic 必须有效。
    if (inputPath == nullptr || outputPath == nullptr || required.dynamic == nullptr) {
        if (error != nullptr) {
            *error = "invalid patchbay arguments";
        }
        return false;
    }

    // 缓存 dynamic 节指针。
    const auto* dynamicSection = required.dynamic;

    // 只有存在 .vmp_patchbay 节时才走该快速路径。
    const auto* patchbay = required.patchbay;
    if (patchbay == nullptr) {
        // 返回 true 表示“非错误，未处理”，上层可走其他策略。
        return true;
    }

    // 命中 patchbay 路径，标记 handled=true。
    if (handled != nullptr) {
        *handled = true;
    }

    // [阶段 1] 读取 patchbay header 并校验容量/区间。
    // patchbay 节至少要容纳一个 header。
    if (patchbay->size < sizeof(PatchBayHeader)) {
        if (error != nullptr) {
            *error = "patchbay section too small";
        }
        return false;
    }

    // 读取输入文件原始字节，后续在内存中原地修改。
    std::vector<uint8_t> newFile;
    if (!loadFileBytes(inputPath, &newFile)) {
        if (error != nullptr) {
            *error = "failed to read input bytes";
        }
        return false;
    }

    // patchbay 节范围必须完整落在文件内。
    if (patchbay->offset > newFile.size() ||
        patchbay->size > (newFile.size() - static_cast<size_t>(patchbay->offset))) {
        if (error != nullptr) {
            *error = "patchbay section range out of file";
        }
        return false;
    }

    // 解释 patchbay header。
    auto* patchHeader = reinterpret_cast<PatchBayHeader*>(newFile.data() + patchbay->offset);

    // 校验 magic/version。
    if (patchHeader->magic != kPatchBayMagic || patchHeader->version != kPatchBayVersion) {
        if (error != nullptr) {
            *error = "patchbay header magic/version mismatch";
        }
        return false;
    }

    // 校验 headerSize 和 totalSize 基本约束。
    if (patchHeader->headerSize < sizeof(PatchBayHeader) || patchHeader->totalSize > patchbay->size) {
        if (error != nullptr) {
            *error = "patchbay header size/capacity invalid";
        }
        return false;
    }

    // 校验各子区 off/cap 在 patchbay 总范围内。
    if (!validatePatchbayRegions(*patchHeader, error)) {
        return false;
    }

    // 校验新 payload 是否超过预留容量。
    if (!checkPatchbayCapacity(*patchHeader,
                               newDynsymBytes.size(),
                               newDynstr.size(),
                               newGnuHash.size(),
                               newVersym.size(),
                               newSysvHash.size(),
                               error)) {
        return false;
    }

    // [阶段 2] 回写 patchbay 子区 payload（dynsym/dynstr/hash/versym）。
    if (!writePatchbayRegions(&newFile,
                              patchbay->offset,
                              *patchHeader,
                              newDynsymBytes,
                              newDynstr,
                              newGnuHash,
                              newVersym,
                              newSysvHash,
                              error)) {
        return false;
    }

    // 计算新表的绝对偏移与虚拟地址。
    const PatchLayout layout = buildPatchLayout(*patchbay, *patchHeader);

    // [阶段 3] 改写 .dynamic 的 DT_* 指针，指向 patchbay 新表。
    // 拷贝 dynamic 条目到可修改数组。
    std::vector<Elf64_Dyn> dynEntries = dynamicSection->entries;

    // 读取旧 DT 指针，供 originalDt* 字段留痕。
    Elf64_Xword oldSymtab = 0;
    Elf64_Xword oldStrtab = 0;
    Elf64_Xword oldGnuHash = 0;
    Elf64_Xword oldHash = 0;
    Elf64_Xword oldVersym = 0;
    getDynPtr(dynEntries, DT_SYMTAB, &oldSymtab);
    getDynPtr(dynEntries, DT_STRTAB, &oldStrtab);
    getDynPtr(dynEntries, DT_GNU_HASH, &oldGnuHash);
    getDynPtr(dynEntries, DT_HASH, &oldHash);
    getDynPtr(dynEntries, DT_VERSYM, &oldVersym);

    // 更新关键动态指针到新表地址。
    if (!setDynPtr(&dynEntries, DT_SYMTAB, static_cast<Elf64_Xword>(layout.dynsymVaddr)) ||
        !setDynPtr(&dynEntries, DT_STRTAB, static_cast<Elf64_Xword>(layout.dynstrVaddr)) ||
        !setDynPtr(&dynEntries, DT_STRSZ, static_cast<Elf64_Xword>(newDynstr.size())) ||
        !setDynPtr(&dynEntries, DT_SYMENT, sizeof(Elf64_Sym)) ||
        !setDynPtr(&dynEntries, DT_GNU_HASH, static_cast<Elf64_Xword>(layout.gnuHashVaddr)) ||
        !setDynPtr(&dynEntries, DT_VERSYM, static_cast<Elf64_Xword>(layout.versymVaddr))) {
        if (error != nullptr) {
            *error = "required DT_* tag missing for patchbay";
        }
        return false;
    }

    // .hash 存在且 payload 非空时更新 DT_HASH。
    if (!newSysvHash.empty() && patchHeader->sysvHashCapacity > 0) {
        setDynPtr(&dynEntries, DT_HASH, static_cast<Elf64_Xword>(layout.sysvHashVaddr));
    }

    // 将更新后的 dynamic 条目序列化为原始字节。
    std::vector<uint8_t> dynBytes(dynEntries.size() * sizeof(Elf64_Dyn), 0);
    if (!dynBytes.empty()) {
        std::memcpy(dynBytes.data(), dynEntries.data(), dynBytes.size());
    }

    // 校验 .dynamic 回写范围。
    if (dynamicSection->offset + dynBytes.size() > newFile.size()) {
        if (error != nullptr) {
            *error = "dynamic section patch range out of file";
        }
        return false;
    }

    // 回写 .dynamic。
    std::memcpy(newFile.data() + dynamicSection->offset, dynBytes.data(), dynBytes.size());

    // [阶段 4] 同步 section headers，保持静态视图一致。
    // 文件长度至少应覆盖 ELF 头。
    if (newFile.size() < sizeof(Elf64_Ehdr)) {
        if (error != nullptr) {
            *error = "output image too small";
        }
        return false;
    }

    // 解释 ELF 头。
    auto* ehdr = reinterpret_cast<Elf64_Ehdr*>(newFile.data());
    if (ehdr->e_shnum > 0) {
        // 计算 section header 表总字节数。
        const uint64_t shdrSize = static_cast<uint64_t>(ehdr->e_shnum) *
                                  static_cast<uint64_t>(ehdr->e_shentsize);
        // 校验 section header 表范围。
        if (ehdr->e_shoff == 0 || ehdr->e_shoff + shdrSize > newFile.size()) {
            if (error != nullptr) {
                *error = "section headers out of range";
            }
            return false;
        }

        // 获取 section header 表指针。
        auto* shdrs = reinterpret_cast<Elf64_Shdr*>(newFile.data() + ehdr->e_shoff);

        // 获取相关节索引。
        const int dynsymIndex = required.dynsym_index;
        const int dynstrIndex = required.dynstr_index;
        const int versymIndex = required.versym_index;
        const int gnuHashIndex = required.gnu_hash_index;
        const int hashIndex = required.hash_index;

        // 索引到节头指针的辅助函数。
        auto patchShdr = [&shdrs](int idx) -> Elf64_Shdr* {
            // idx<0 表示该节不存在。
            return idx >= 0 ? &shdrs[idx] : nullptr;
        };

        // 更新 .dynsym 节头。
        if (auto* sh = patchShdr(dynsymIndex)) {
            sh->sh_offset = static_cast<Elf64_Off>(layout.dynsymFileOffset);
            sh->sh_addr = static_cast<Elf64_Addr>(layout.dynsymVaddr);
            sh->sh_size = static_cast<Elf64_Xword>(newDynsymBytes.size());
            sh->sh_entsize = sizeof(Elf64_Sym);
            sh->sh_link = static_cast<Elf64_Word>(dynstrIndex);
            sh->sh_info = 1;
        }

        // 更新 .dynstr 节头。
        if (auto* sh = patchShdr(dynstrIndex)) {
            sh->sh_offset = static_cast<Elf64_Off>(layout.dynstrFileOffset);
            sh->sh_addr = static_cast<Elf64_Addr>(layout.dynstrVaddr);
            sh->sh_size = static_cast<Elf64_Xword>(newDynstr.size());
        }

        // 更新 .gnu.version 节头。
        if (auto* sh = patchShdr(versymIndex)) {
            sh->sh_offset = static_cast<Elf64_Off>(layout.versymFileOffset);
            sh->sh_addr = static_cast<Elf64_Addr>(layout.versymVaddr);
            sh->sh_size = static_cast<Elf64_Xword>(newVersym.size());
            sh->sh_entsize = 2;
            sh->sh_link = static_cast<Elf64_Word>(dynsymIndex);
        }

        // 更新 .gnu.hash 节头。
        if (auto* sh = patchShdr(gnuHashIndex)) {
            sh->sh_offset = static_cast<Elf64_Off>(layout.gnuHashFileOffset);
            sh->sh_addr = static_cast<Elf64_Addr>(layout.gnuHashVaddr);
            sh->sh_size = static_cast<Elf64_Xword>(newGnuHash.size());
            sh->sh_link = static_cast<Elf64_Word>(dynsymIndex);
            sh->sh_addralign = 8;
        }

        // 可选更新 .hash 节头。
        if (hashIndex >= 0 && !newSysvHash.empty() && patchHeader->sysvHashCapacity > 0) {
            if (auto* sh = patchShdr(hashIndex)) {
                sh->sh_offset = static_cast<Elf64_Off>(layout.sysvHashFileOffset);
                sh->sh_addr = static_cast<Elf64_Addr>(layout.sysvHashVaddr);
                sh->sh_size = static_cast<Elf64_Xword>(newSysvHash.size());
                sh->sh_entsize = sizeof(uint32_t);
                sh->sh_link = static_cast<Elf64_Word>(dynsymIndex);
                sh->sh_addralign = 4;
            }
        }
    }

    // [阶段 5] 更新 patchbay header used 字段、slot 位图与 CRC。
    // 重新获取 header 指针，保证引用最新文件缓冲。
    patchHeader = reinterpret_cast<PatchBayHeader*>(newFile.data() + patchbay->offset);

    // 首次 patch 时写入 originalDt* 快照。
    if (patchHeader->originalDtSymtab == 0) {
        patchHeader->originalDtSymtab = oldSymtab;
    }
    if (patchHeader->originalDtStrtab == 0) {
        patchHeader->originalDtStrtab = oldStrtab;
    }
    if (patchHeader->originalDtGnuHash == 0) {
        patchHeader->originalDtGnuHash = oldGnuHash;
    }
    if (patchHeader->originalDtHash == 0) {
        patchHeader->originalDtHash = oldHash;
    }
    if (patchHeader->originalDtVersym == 0) {
        patchHeader->originalDtVersym = oldVersym;
    }

    // 写入“已使用字节”统计字段。
    patchHeader->usedDynsym = static_cast<uint32_t>(newDynsymBytes.size());
    patchHeader->usedDynstr = static_cast<uint32_t>(newDynstr.size());
    patchHeader->usedGnuHash = static_cast<uint32_t>(newGnuHash.size());
    patchHeader->usedSysvHash = static_cast<uint32_t>(newSysvHash.size());
    patchHeader->usedVersym = static_cast<uint32_t>(newVersym.size());

    // 更新 takeover 槽位计数与位图。
    if (patchHeader->takeoverSlotTotal > 0) {
        // 优先使用 header 里现有值；异常时用 hint 修正。
        uint32_t slotUsed = patchHeader->takeoverSlotUsed;
        if (slotUsed == 0 || slotUsed > patchHeader->takeoverSlotTotal) {
            slotUsed = std::min<uint32_t>(patchHeader->takeoverSlotTotal, slotUsedHint);
        }
        // 最终 used 不得超过 total。
        patchHeader->takeoverSlotUsed = std::min<uint32_t>(slotUsed, patchHeader->takeoverSlotTotal);
        // 低 64 位位图数量。
        const uint32_t lowCount = std::min<uint32_t>(patchHeader->takeoverSlotUsed, 64U);
        // 高 64 位位图数量。
        const uint32_t highCount = patchHeader->takeoverSlotUsed > 64U
                                  ? std::min<uint32_t>(patchHeader->takeoverSlotUsed - 64U, 64U)
                                  : 0U;
        // 生成位图。
        patchHeader->takeoverSlotBitmapLo = bitmaskForCountU32(lowCount);
        patchHeader->takeoverSlotBitmapHi = bitmaskForCountU32(highCount);
    } else {
        // 无槽位模型时清零。
        patchHeader->takeoverSlotUsed = 0;
        patchHeader->takeoverSlotBitmapLo = 0;
        patchHeader->takeoverSlotBitmapHi = 0;
    }

    // 标记“已写新表”。
    patchHeader->flags |= 0x1U;
    // 标记“已改 dynamic”。
    patchHeader->flags |= 0x2U;
    // 先清零 CRC，再重算。
    patchHeader->crc32 = 0;

    // 保存布局/CRC 计算错误信息。
    std::string layoutError;
    // 保存重算得到的 CRC。
    uint32_t computedCrc = 0;
    // 基于 header(清零crc)+used 子区计算 CRC。
    if (!computePatchbayCrcFromFile(newFile, patchbay->offset, *patchHeader, &computedCrc, &layoutError)) {
        if (error != nullptr) {
            *error = layoutError;
        }
        return false;
    }
    // 回填最终 CRC。
    patchHeader->crc32 = computedCrc;

    // [阶段 6] 最终布局校验、落盘并做二次 validate。
    // 先做 Android 视角布局校验。
    if (!validateElfTablesForAndroid(newFile, &layoutError)) {
        if (error != nullptr) {
            *error = "patchbay output layout invalid: " + layoutError;
        }
        return false;
    }

    // 写出 output 文件。
    if (!saveFileBytes(outputPath, newFile)) {
        if (error != nullptr) {
            *error = "failed to write output file";
        }
        return false;
    }

    // 重新加载输出 ELF 并执行模型校验。
    vmp::elfkit::PatchElfImage patched(outputPath);
    if (!patched.loaded()) {
        if (error != nullptr) {
            *error = "failed to reload output elf";
        }
        return false;
    }

    // 执行 validate。
    std::string validateError;
    if (!patched.validate(&validateError)) {
        // allowValidateFail=true 时记录告警后继续。
        if (!allowValidateFail) {
            if (error != nullptr) {
                *error = "validate failed: " + validateError;
            }
            return false;
        }
        LOGW("patchbay validate warning: %s", validateError.c_str());
    }

    // 输出 patch 成功摘要。
    LOGI("patchbay patch success: dynsym=%zu dynstr=%zu gnuhash=%zu sysvhash=%zu versym=%zu",
         newDynsymBytes.size(),
         newDynstr.size(),
         newGnuHash.size(),
         newSysvHash.size(),
         newVersym.size());
    return true;
}

