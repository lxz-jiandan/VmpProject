#include "zPatchbayPatchApply.h"

// 引入 embedded payload 尾部协议工具。
#include "zEmbeddedPayloadTail.h"
// 引入基础文件读写工具。
#include "zFile.h"
// 引入 ELF 布局校验工具。
#include "zPatchbayLayout.h"
// 引入日志接口。
#include "zLog.h"
// 引入 ELF 只读 facade（用于输出文件复验）。
#include "zElfReadFacade.h"

// 引入 std::min。
#include <algorithm>
// 引入固定宽度整型。
#include <cstdint>
// 引入 memcpy。
#include <cstring>
// 引入数值边界。
#include <limits>
// 引入字符串类型。
#include <string>
// 引入哈希容器。
#include <unordered_map>
// 引入去重集合。
#include <unordered_set>
// 引入字节数组容器。
#include <vector>

// 进入匿名命名空间，封装内部辅助结构与函数。
namespace {

// 前置声明：解析并校验 ELF Header + Program Header 表，返回可写视图。
bool parseElfHeaderAndPhdr(std::vector<uint8_t>* fileBytes,
                           Elf64_Ehdr** outEhdr,
                           Elf64_Phdr** outPhdrs,
                           std::string* error);

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

// 向上对齐（align=0 时返回原值）。
uint64_t alignUpU64(uint64_t value, uint64_t align) {
    if (align == 0) {
        return value;
    }
    return ((value + align - 1) / align) * align;
}

// 2 的幂判断。
bool isPowerOfTwoU64(uint64_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

// 安全加法：检测 uint64 溢出。
bool addU64Checked(uint64_t a, uint64_t b, uint64_t* out) {
    if (out == nullptr) {
        return false;
    }
    if (std::numeric_limits<uint64_t>::max() - a < b) {
        return false;
    }
    *out = a + b;
    return true;
}

// 半开区间重叠判断：[aBegin, aEnd) 与 [bBegin, bEnd)。
bool rangesOverlapOpenU64(uint64_t aBegin, uint64_t aEnd, uint64_t bBegin, uint64_t bEnd) {
    if (aBegin >= aEnd || bBegin >= bEnd) {
        return false;
    }
    return aBegin < bEnd && bBegin < aEnd;
}

// 收口流程：把可写 PT_LOAD 的 p_memsz 至少扩展到 relro_end，确保字节级覆盖。
bool closeRelroCoverageByMemsz(std::vector<uint8_t>* fileBytes, std::string* error) {
    Elf64_Ehdr* ehdr = nullptr;
    Elf64_Phdr* phdrs = nullptr;
    if (!parseElfHeaderAndPhdr(fileBytes, &ehdr, &phdrs, error)) {
        return false;
    }

    bool updated = false;
    for (uint16_t relroIndex = 0; relroIndex < ehdr->e_phnum; ++relroIndex) {
        const Elf64_Phdr& relroPhdr = phdrs[relroIndex];
        if (relroPhdr.p_type != PT_GNU_RELRO || relroPhdr.p_memsz == 0) {
            continue;
        }

        const uint64_t relroBegin = static_cast<uint64_t>(relroPhdr.p_vaddr);
        uint64_t relroEnd = 0;
        if (!addU64Checked(relroBegin, static_cast<uint64_t>(relroPhdr.p_memsz), &relroEnd)) {
            if (error != nullptr) {
                *error = "PT_GNU_RELRO range overflow";
            }
            return false;
        }

        int writableLoadIndex = -1;
        uint64_t writableLoadBegin = 0;
        uint64_t writableLoadEnd = 0;

        // 选择“覆盖 relro 起点”的可写 PT_LOAD，优先起点更靠后的段。
        for (uint16_t loadIndex = 0; loadIndex < ehdr->e_phnum; ++loadIndex) {
            const Elf64_Phdr& loadPhdr = phdrs[loadIndex];
            if (loadPhdr.p_type != PT_LOAD || (loadPhdr.p_flags & PF_W) == 0) {
                continue;
            }

            const uint64_t loadBegin = static_cast<uint64_t>(loadPhdr.p_vaddr);
            uint64_t loadEnd = 0;
            if (!addU64Checked(loadBegin, static_cast<uint64_t>(loadPhdr.p_memsz), &loadEnd)) {
                if (error != nullptr) {
                    *error = "PT_LOAD range overflow at index " + std::to_string(loadIndex);
                }
                return false;
            }
            if (!(relroBegin >= loadBegin && relroBegin < loadEnd)) {
                continue;
            }
            if (writableLoadIndex < 0 || loadBegin > writableLoadBegin) {
                writableLoadIndex = static_cast<int>(loadIndex);
                writableLoadBegin = loadBegin;
                writableLoadEnd = loadEnd;
            }
        }

        if (writableLoadIndex < 0) {
            if (error != nullptr) {
                *error = "cannot find writable PT_LOAD covering PT_GNU_RELRO begin";
            }
            return false;
        }
        if (relroEnd <= writableLoadEnd) {
            continue;
        }

        // 仅阻止“新增重叠”；已有重叠保持原样不扩大风险。
        for (uint16_t otherIndex = 0; otherIndex < ehdr->e_phnum; ++otherIndex) {
            if (static_cast<int>(otherIndex) == writableLoadIndex) {
                continue;
            }
            const Elf64_Phdr& otherPhdr = phdrs[otherIndex];
            if (otherPhdr.p_type != PT_LOAD) {
                continue;
            }

            const uint64_t otherBegin = static_cast<uint64_t>(otherPhdr.p_vaddr);
            uint64_t otherEnd = 0;
            if (!addU64Checked(otherBegin, static_cast<uint64_t>(otherPhdr.p_memsz), &otherEnd)) {
                if (error != nullptr) {
                    *error = "PT_LOAD range overflow at index " + std::to_string(otherIndex);
                }
                return false;
            }

            const bool oldOverlap = rangesOverlapOpenU64(
                writableLoadBegin, writableLoadEnd, otherBegin, otherEnd);
            const bool newOverlap = rangesOverlapOpenU64(
                writableLoadBegin, relroEnd, otherBegin, otherEnd);
            if (!oldOverlap && newOverlap) {
                if (error != nullptr) {
                    *error = "close RELRO by memsz would overlap PT_LOAD index " +
                             std::to_string(otherIndex);
                }
                return false;
            }
        }

        const uint64_t newMemsz = relroEnd - writableLoadBegin;
        phdrs[writableLoadIndex].p_memsz = static_cast<Elf64_Xword>(newMemsz);
        updated = true;
        LOGI("close RELRO coverage: load_index=%d old_memsz=0x%llx new_memsz=0x%llx relro_end=0x%llx",
             writableLoadIndex,
             static_cast<unsigned long long>(writableLoadEnd - writableLoadBegin),
             static_cast<unsigned long long>(newMemsz),
             static_cast<unsigned long long>(relroEnd));
    }

    if (updated) {
        LOGI("close RELRO coverage by p_memsz finished");
    }
    return true;
}

// 是否属于当前已知的 RELRO 覆盖校验告警（历史镜像常见，非本次补丁引入）。
bool isKnownRelroCoverageValidateError(const std::string& validateError) {
    return validateError.find("PT_GNU_RELRO") != std::string::npos &&
           validateError.find("writable PT_LOAD") != std::string::npos;
}

// 解析并校验 ELF Header + Program Header 表，返回可写视图。
bool parseElfHeaderAndPhdr(std::vector<uint8_t>* fileBytes,
                           Elf64_Ehdr** outEhdr,
                           Elf64_Phdr** outPhdrs,
                           std::string* error) {
    if (fileBytes == nullptr || outEhdr == nullptr || outPhdrs == nullptr) {
        if (error != nullptr) {
            *error = "invalid elf parse input";
        }
        return false;
    }
    if (fileBytes->size() < sizeof(Elf64_Ehdr)) {
        if (error != nullptr) {
            *error = "output image too small for ELF header";
        }
        return false;
    }

    auto* ehdr = reinterpret_cast<Elf64_Ehdr*>(fileBytes->data());
    if (ehdr->e_phnum == 0 || ehdr->e_phentsize != sizeof(Elf64_Phdr)) {
        if (error != nullptr) {
            *error = "invalid or unsupported program header layout";
        }
        return false;
    }

    const uint64_t phdrTableSize = static_cast<uint64_t>(ehdr->e_phnum) *
                                   static_cast<uint64_t>(ehdr->e_phentsize);
    if (ehdr->e_phoff > fileBytes->size() ||
        phdrTableSize > (fileBytes->size() - static_cast<size_t>(ehdr->e_phoff))) {
        if (error != nullptr) {
            *error = "program header table out of range";
        }
        return false;
    }

    *outEhdr = ehdr;
    *outPhdrs = reinterpret_cast<Elf64_Phdr*>(fileBytes->data() + ehdr->e_phoff);
    return true;
}

// 推断页对齐：优先使用 PT_LOAD 的 p_align，否则回退 4KB。
uint64_t inferLoadPageAlign(const Elf64_Phdr* phdrs, uint16_t phnum) {
    uint64_t best = 0;
    for (uint16_t i = 0; i < phnum; ++i) {
        const Elf64_Phdr& ph = phdrs[i];
        if (ph.p_type != PT_LOAD || ph.p_align <= 1) {
            continue;
        }
        if (!isPowerOfTwoU64(ph.p_align)) {
            continue;
        }
        best = std::max<uint64_t>(best, ph.p_align);
    }
    return best == 0 ? 0x1000ULL : best;
}

// 返回第一个 PT_NULL 索引，不存在则 -1。
int findFirstPtNullIndex(const Elf64_Phdr* phdrs, uint16_t phnum) {
    for (uint16_t i = 0; i < phnum; ++i) {
        if (phdrs[i].p_type == PT_NULL) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

// 返回可复用为“新 PT_LOAD”的程序头索引。
// 优先 PT_NULL；若无 PT_NULL，则回退复用 PT_NOTE。
int findReusablePhdrIndexForNewLoad(const Elf64_Phdr* phdrs, uint16_t phnum) {
    const int ptNullIndex = findFirstPtNullIndex(phdrs, phnum);
    if (ptNullIndex >= 0) {
        return ptNullIndex;
    }
    for (uint16_t i = 0; i < phnum; ++i) {
        if (phdrs[i].p_type == PT_NOTE) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

// 返回“文件末尾最靠后”的 PT_LOAD 索引，不存在则 -1。
int findTailLoadIndex(const Elf64_Phdr* phdrs, uint16_t phnum) {
    int bestIndex = -1;
    uint64_t bestFileEnd = 0;
    for (uint16_t i = 0; i < phnum; ++i) {
        const Elf64_Phdr& ph = phdrs[i];
        if (ph.p_type != PT_LOAD) {
            continue;
        }
        const uint64_t fileEnd = static_cast<uint64_t>(ph.p_offset) +
                                 static_cast<uint64_t>(ph.p_filesz);
        if (bestIndex < 0 || fileEnd > bestFileEnd) {
            bestIndex = static_cast<int>(i);
            bestFileEnd = fileEnd;
        }
    }
    return bestIndex;
}

// 计算所有 PT_LOAD 的最大虚拟地址末尾。
uint64_t maxLoadVaddrEnd(const Elf64_Phdr* phdrs, uint16_t phnum) {
    uint64_t maxEnd = 0;
    for (uint16_t i = 0; i < phnum; ++i) {
        const Elf64_Phdr& ph = phdrs[i];
        if (ph.p_type != PT_LOAD) {
            continue;
        }
        const uint64_t end = static_cast<uint64_t>(ph.p_vaddr) +
                             static_cast<uint64_t>(ph.p_memsz);
        maxEnd = std::max<uint64_t>(maxEnd, end);
    }
    return maxEnd;
}

// 重构模式下的新表落位结果。
struct RebuildLayout {
    // 是否复用了 PT_NULL 创建独立 PT_LOAD。
    bool usedNewLoadSegment = false;
    // 承载新数据的段索引。
    int loadSegmentIndex = -1;
    // 新数据 blob 起点（文件偏移）。
    uint64_t blobFileOffset = 0;
    // 新数据 blob 起点（虚拟地址）。
    uint64_t blobVaddr = 0;
    // 新数据 blob 末尾（开区间，文件偏移）。
    uint64_t blobFileEnd = 0;
    // 可选：合成槽位跳板 blob 起点（文件偏移）。
    uint64_t stubFileOffset = 0;
    // 可选：合成槽位跳板 blob 起点（虚拟地址）。
    uint64_t stubVaddr = 0;
    // 可选：合成槽位跳板字节数。
    uint64_t stubSize = 0;

    // 各表文件偏移。
    uint64_t dynsymFileOffset = 0;
    uint64_t dynstrFileOffset = 0;
    uint64_t gnuHashFileOffset = 0;
    uint64_t versymFileOffset = 0;
    uint64_t sysvHashFileOffset = 0;

    // 各表虚拟地址。
    uint64_t dynsymVaddr = 0;
    uint64_t dynstrVaddr = 0;
    uint64_t gnuHashVaddr = 0;
    uint64_t versymVaddr = 0;
    uint64_t sysvHashVaddr = 0;
};

// 把 dyn 表整体追加到文件尾，并保证由 PT_LOAD 覆盖。
bool appendTablesWithRebuild(std::vector<uint8_t>* fileBytes,
                             RebuildLayout* layout,
                             const std::vector<uint8_t>& syntheticStubBytes,
                             const std::vector<uint8_t>& dynsymBytes,
                             const std::vector<uint8_t>& dynstrBytes,
                             const std::vector<uint8_t>& gnuHashBytes,
                             const std::vector<uint8_t>& versymBytes,
                             const std::vector<uint8_t>& sysvHashBytes,
                             std::string* error) {
    if (fileBytes == nullptr || layout == nullptr) {
        if (error != nullptr) {
            *error = "invalid rebuild append arguments";
        }
        return false;
    }

    Elf64_Ehdr* ehdr = nullptr;
    Elf64_Phdr* phdrs = nullptr;
    if (!parseElfHeaderAndPhdr(fileBytes, &ehdr, &phdrs, error)) {
        return false;
    }

    const uint64_t pageAlign = inferLoadPageAlign(phdrs, ehdr->e_phnum);
    const int reusableLoadIndex = findReusablePhdrIndexForNewLoad(phdrs, ehdr->e_phnum);
    const int tailLoadIndex = findTailLoadIndex(phdrs, ehdr->e_phnum);
    if (tailLoadIndex < 0) {
        if (error != nullptr) {
            *error = "no PT_LOAD found for rebuild append";
        }
        return false;
    }

    const uint64_t blobStart = alignUpU64(static_cast<uint64_t>(fileBytes->size()), pageAlign);
    const bool useNewLoad = (reusableLoadIndex >= 0);
    const int targetLoadIndex = useNewLoad ? reusableLoadIndex : tailLoadIndex;

    // 若需要合成可执行槽位跳板，必须有可复用程序头创建独立 PT_LOAD；
    // 否则会落到既有 RW 段并产生 Android 禁止的 W+E 段。
    if (!syntheticStubBytes.empty() && !useNewLoad) {
        if (error != nullptr) {
            *error = "no reusable program header for executable takeover stubs";
        }
        return false;
    }

    // 计算 blob 起始虚拟地址。
    uint64_t blobVaddr = 0;
    if (useNewLoad) {
        const uint64_t vaddrBase = alignUpU64(maxLoadVaddrEnd(phdrs, ehdr->e_phnum), pageAlign);
        blobVaddr = vaddrBase + (blobStart % pageAlign);
    } else {
        const Elf64_Phdr& tail = phdrs[tailLoadIndex];
        if (blobStart < tail.p_offset) {
            if (error != nullptr) {
                *error = "rebuild append offset is before tail PT_LOAD offset";
            }
            return false;
        }
        blobVaddr = static_cast<uint64_t>(tail.p_vaddr) + (blobStart - static_cast<uint64_t>(tail.p_offset));
    }

    // 在 blob 内按“可选跳板 + 各表”顺序放置。
    uint64_t cursor = blobStart;
    auto placeRegion = [&cursor, blobStart, blobVaddr](const std::vector<uint8_t>& payload,
                                                       uint64_t align,
                                                       uint64_t* outOff,
                                                       uint64_t* outAddr) -> bool {
        if (outOff == nullptr || outAddr == nullptr) {
            return false;
        }
        if (payload.empty()) {
            *outOff = 0;
            *outAddr = 0;
            return true;
        }
        cursor = alignUpU64(cursor, align);
        const uint64_t off = cursor;
        cursor += payload.size();
        const uint64_t addr = blobVaddr + (off - blobStart);
        *outOff = off;
        *outAddr = addr;
        return true;
    };

    if (!placeRegion(syntheticStubBytes, 16, &layout->stubFileOffset, &layout->stubVaddr) ||
        !placeRegion(dynsymBytes, 8, &layout->dynsymFileOffset, &layout->dynsymVaddr) ||
        !placeRegion(dynstrBytes, 1, &layout->dynstrFileOffset, &layout->dynstrVaddr) ||
        !placeRegion(gnuHashBytes, 8, &layout->gnuHashFileOffset, &layout->gnuHashVaddr) ||
        !placeRegion(versymBytes, 2, &layout->versymFileOffset, &layout->versymVaddr) ||
        !placeRegion(sysvHashBytes, 4, &layout->sysvHashFileOffset, &layout->sysvHashVaddr)) {
        if (error != nullptr) {
            *error = "failed to place rebuild regions";
        }
        return false;
    }

    // 扩展文件到 blob 末尾并写入 payload。
    if (cursor > static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
        if (error != nullptr) {
            *error = "rebuild blob size overflow";
        }
        return false;
    }
    fileBytes->resize(static_cast<size_t>(cursor), 0);

    auto writeRegion = [fileBytes](uint64_t off, const std::vector<uint8_t>& payload) -> bool {
        if (payload.empty()) {
            return true;
        }
        if (off > fileBytes->size() || payload.size() > (fileBytes->size() - static_cast<size_t>(off))) {
            return false;
        }
        std::memcpy(fileBytes->data() + off, payload.data(), payload.size());
        return true;
    };
    if (!writeRegion(layout->stubFileOffset, syntheticStubBytes) ||
        !writeRegion(layout->dynsymFileOffset, dynsymBytes) ||
        !writeRegion(layout->dynstrFileOffset, dynstrBytes) ||
        !writeRegion(layout->gnuHashFileOffset, gnuHashBytes) ||
        !writeRegion(layout->versymFileOffset, versymBytes) ||
        !writeRegion(layout->sysvHashFileOffset, sysvHashBytes)) {
        if (error != nullptr) {
            *error = "failed to write rebuild regions";
        }
        return false;
    }

    // 重新取 header/phdr 指针（resize 后地址可能变化）。
    if (!parseElfHeaderAndPhdr(fileBytes, &ehdr, &phdrs, error)) {
        return false;
    }

    // 更新（或创建）承载段。
    Elf64_Phdr& targetLoad = phdrs[targetLoadIndex];
    if (useNewLoad) {
        targetLoad.p_type = PT_LOAD;
        // 独立段策略：
        // - 含合成跳板：R|X（避免 W+E）；
        // - 无跳板：R|W（仅承载数据）。
        targetLoad.p_flags = !syntheticStubBytes.empty() ? (PF_R | PF_X) : (PF_R | PF_W);
        targetLoad.p_offset = static_cast<Elf64_Off>(blobStart);
        targetLoad.p_vaddr = static_cast<Elf64_Addr>(blobVaddr);
        targetLoad.p_paddr = static_cast<Elf64_Addr>(blobVaddr);
        targetLoad.p_filesz = static_cast<Elf64_Xword>(cursor - blobStart);
        targetLoad.p_memsz = static_cast<Elf64_Xword>(cursor - blobStart);
        targetLoad.p_align = static_cast<Elf64_Xword>(pageAlign);
    } else {
        // 走“扩展末尾 PT_LOAD”路径，保持原 offset/vaddr 不动。
        const uint64_t oldFilesz = targetLoad.p_filesz;
        const uint64_t oldMemsz = targetLoad.p_memsz;
        const uint64_t oldBssTail = oldMemsz > oldFilesz ? (oldMemsz - oldFilesz) : 0;
        const uint64_t requiredFilesz = cursor - static_cast<uint64_t>(targetLoad.p_offset);
        if (requiredFilesz > targetLoad.p_filesz) {
            targetLoad.p_filesz = static_cast<Elf64_Xword>(requiredFilesz);
        }
        uint64_t requiredMemsz = static_cast<uint64_t>(targetLoad.p_filesz) + oldBssTail;
        if (requiredMemsz < targetLoad.p_filesz) {
            requiredMemsz = targetLoad.p_filesz;
        }
        if (requiredMemsz > targetLoad.p_memsz) {
            targetLoad.p_memsz = static_cast<Elf64_Xword>(requiredMemsz);
        }
        // 确保新动态表所在段具备 R/W（便于动态重定位写入）。
        targetLoad.p_flags |= (PF_R | PF_W);
        // 注意：本分支已在前面保证 syntheticStubBytes 为空，
        // 因此不会把已有 RW 段升级为 RWE。
    }

    layout->usedNewLoadSegment = useNewLoad;
    layout->loadSegmentIndex = targetLoadIndex;
    layout->blobFileOffset = blobStart;
    layout->blobVaddr = blobVaddr;
    layout->blobFileEnd = cursor;
    layout->stubSize = syntheticStubBytes.size();
    return true;
}

// 以小端追加 u32。
void appendU32Le(std::vector<uint8_t>* out, uint32_t value) {
    out->push_back(static_cast<uint8_t>(value & 0xffU));
    out->push_back(static_cast<uint8_t>((value >> 8) & 0xffU));
    out->push_back(static_cast<uint8_t>((value >> 16) & 0xffU));
    out->push_back(static_cast<uint8_t>((value >> 24) & 0xffU));
}

// 以小端追加 u64。
void appendU64Le(std::vector<uint8_t>* out, uint64_t value) {
    for (int i = 0; i < 8; ++i) {
        out->push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xffULL));
    }
}

// 生成 ARM64 槽位跳板（24 bytes）：
// movz w2, #lo16
// movk w2, #hi16, lsl #16
// ldr  x16, #8
// br   x16
// .quad dispatch_addr
void appendTakeoverTrampolineArm64(uint32_t entryId,
                                   uint64_t dispatchAddr,
                                   std::vector<uint8_t>* out) {
    const uint32_t lo16 = entryId & 0xffffU;
    const uint32_t hi16 = (entryId >> 16) & 0xffffU;

    const uint32_t movzW2 = 0x52800000U | (lo16 << 5) | 2U;
    const uint32_t movkW2 = 0x72A00000U | (hi16 << 5) | 2U;
    const uint32_t ldrX16LiteralPlus8 = 0x58000000U | (2U << 5) | 16U;
    const uint32_t brX16 = 0xD61F0000U | (16U << 5);

    appendU32Le(out, movzW2);
    appendU32Le(out, movkW2);
    appendU32Le(out, ldrX16LiteralPlus8);
    appendU32Le(out, brX16);
    appendU64Le(out, dispatchAddr);
}

// 根据 pending 绑定构建“entryId -> stub 相对偏移”与 stub blob。
bool buildSyntheticTakeoverStubBlob(
        const std::vector<PendingTakeoverSymbolBinding>& pendingBindings,
        uint64_t dispatchAddr,
        std::vector<uint8_t>* outStubBytes,
        std::unordered_map<uint32_t, uint64_t>* outStubOffBySlot,
        std::string* error) {
    if (outStubBytes == nullptr || outStubOffBySlot == nullptr) {
        if (error != nullptr) {
            *error = "invalid synthetic stub output";
        }
        return false;
    }
    outStubBytes->clear();
    outStubOffBySlot->clear();

    if (pendingBindings.empty()) {
        return true;
    }
    if (dispatchAddr == 0) {
        if (error != nullptr) {
            *error = "invalid dispatch address for synthetic takeover stubs";
        }
        return false;
    }

    std::unordered_set<uint32_t> seenSlotIds;
    seenSlotIds.reserve(pendingBindings.size());
    outStubOffBySlot->reserve(pendingBindings.size());

    for (const PendingTakeoverSymbolBinding& binding : pendingBindings) {
        if (seenSlotIds.find(binding.entryId) != seenSlotIds.end()) {
            continue;
        }
        seenSlotIds.insert(binding.entryId);
        const uint64_t relOff = outStubBytes->size();
        appendTakeoverTrampolineArm64(binding.entryId, dispatchAddr, outStubBytes);
        (*outStubOffBySlot)[binding.entryId] = relOff;
    }
    return true;
}

// 按 pending 绑定回填 dynsym 中的 st_value（指向合成跳板地址）。
bool patchDynsymTakeoverValuesInFile(std::vector<uint8_t>* fileBytes,
                                     const RebuildLayout& layout,
                                     const std::vector<PendingTakeoverSymbolBinding>& pendingBindings,
                                     const std::unordered_map<uint32_t, uint64_t>& stubOffBySlot,
                                     std::string* error) {
    if (pendingBindings.empty()) {
        return true;
    }
    if (fileBytes == nullptr) {
        if (error != nullptr) {
            *error = "null output file buffer when patch dynsym takeover values";
        }
        return false;
    }

    // 先校验 dynsym 区间与元素对齐。
    if (layout.dynsymFileOffset > fileBytes->size() ||
        layout.dynsymFileOffset + (layout.blobFileEnd - layout.dynsymFileOffset) > fileBytes->size()) {
        if (error != nullptr) {
            *error = "dynsym range out of file for takeover patch";
        }
        return false;
    }
    if ((layout.dynsymFileOffset % alignof(Elf64_Sym)) != 0) {
        if (error != nullptr) {
            *error = "dynsym offset alignment invalid for takeover patch";
        }
        return false;
    }

    // dynsym 大小无法从 layout 直接得到，依赖 section patch 时写入的新 size；
    // 这里通过 .blob 中下一个区偏移推导不稳定，因此直接按 Pending 索引做边界防护：
    // 最大 symbolIndex 需要能够落在文件内。
    uint32_t maxSymbolIndex = 0;
    for (const PendingTakeoverSymbolBinding& binding : pendingBindings) {
        maxSymbolIndex = std::max<uint32_t>(maxSymbolIndex, binding.symbolIndex);
    }
    const uint64_t requiredBytes = static_cast<uint64_t>(maxSymbolIndex + 1) * sizeof(Elf64_Sym);
    if (layout.dynsymFileOffset > fileBytes->size() ||
        requiredBytes > (fileBytes->size() - static_cast<size_t>(layout.dynsymFileOffset))) {
        if (error != nullptr) {
            *error = "pending takeover symbol index out of dynsym range";
        }
        return false;
    }

    auto* syms = reinterpret_cast<Elf64_Sym*>(fileBytes->data() + layout.dynsymFileOffset);
    for (const PendingTakeoverSymbolBinding& binding : pendingBindings) {
        const auto slotIt = stubOffBySlot.find(binding.entryId);
        if (slotIt == stubOffBySlot.end()) {
            if (error != nullptr) {
                *error = "missing synthetic stub for entry id " + std::to_string(binding.entryId);
            }
            return false;
        }
        const uint64_t symAddr = layout.stubVaddr + slotIt->second;
        Elf64_Sym& sym = syms[binding.symbolIndex];
        sym.st_value = static_cast<Elf64_Addr>(symAddr);
        // 占位条目统一改为 ABS，避免未定义节索引导致运行时过滤。
        if (sym.st_shndx == SHN_UNDEF || sym.st_shndx == SHN_ABS) {
            sym.st_shndx = SHN_ABS;
        }
    }
    return true;
}

// ELF 重构路径：直接重建 dyn 表并回写 DT_*。
bool applyRebuildAliasPayload(const vmp::elfkit::PatchRequiredSections& required,
                              const char* inputPath,
                              const char* outputPath,
                              const std::vector<uint8_t>& newDynsymBytes,
                              const std::vector<uint8_t>& newDynstr,
                              const std::vector<uint8_t>& newVersym,
                              const std::vector<uint8_t>& newGnuHash,
                              const std::vector<uint8_t>& newSysvHash,
                              const std::vector<PendingTakeoverSymbolBinding>& pendingTakeoverBindings,
                              uint64_t takeoverDispatchAddr,
                              bool allowValidateFail,
                              std::string* error) {
    if (inputPath == nullptr || outputPath == nullptr || required.dynamic.index < 0) {
        if (error != nullptr) {
            *error = "invalid rebuild arguments";
        }
        return false;
    }

    // 读取输入镜像。
    std::vector<uint8_t> newFile;
    if (!vmp::base::file::readFileBytes(inputPath, &newFile)) {
        if (error != nullptr) {
            *error = "failed to read input bytes";
        }
        return false;
    }

    // [阶段 1] 若文件末尾存在 embedded payload，先摘除并暂存。
    // 目的：避免后续重构把 dyn 表追加到 payload 之后，导致 footer 不在文件末尾。
    vmp::base::embedded::EmbeddedPayloadTailInfo embeddedTailInfo;
    std::string embeddedTailError;
    if (!vmp::base::embedded::parseEmbeddedPayloadTail(newFile,
                                                       &embeddedTailInfo,
                                                       &embeddedTailError)) {
        if (error != nullptr) {
            *error = embeddedTailError.empty()
                         ? "failed to parse embedded payload tail"
                         : ("failed to parse embedded payload tail: " + embeddedTailError);
        }
        return false;
    }
    if (embeddedTailInfo.hasTail) {
        newFile.resize(embeddedTailInfo.baseSize);
    }

    // [阶段 2] 根据 pending 槽位绑定生成合成跳板（可选）。
    std::vector<uint8_t> syntheticStubBytes;
    std::unordered_map<uint32_t, uint64_t> stubOffBySlot;
    if (!buildSyntheticTakeoverStubBlob(pendingTakeoverBindings,
                                        takeoverDispatchAddr,
                                        &syntheticStubBytes,
                                        &stubOffBySlot,
                                        error)) {
        return false;
    }

    // [阶段 3] 追加“可选跳板 + 新 dyn 表”并确保 PT_LOAD 覆盖。
    RebuildLayout layout;
    if (!appendTablesWithRebuild(&newFile,
                                 &layout,
                                 syntheticStubBytes,
                                 newDynsymBytes,
                                 newDynstr,
                                 newGnuHash,
                                 newVersym,
                                 newSysvHash,
                                  error)) {
        return false;
    }

    // [阶段 4] 将 pending 符号条目的 st_value 回填为合成跳板地址。
    if (!patchDynsymTakeoverValuesInFile(&newFile,
                                         layout,
                                         pendingTakeoverBindings,
                                         stubOffBySlot,
                                         error)) {
        return false;
    }

    // [阶段 5] 改写 .dynamic 的 DT_* 指针。
    std::vector<Elf64_Dyn> dynEntries = required.dynamic.entries;
    if (!setDynPtr(&dynEntries, DT_SYMTAB, static_cast<Elf64_Xword>(layout.dynsymVaddr)) ||
        !setDynPtr(&dynEntries, DT_STRTAB, static_cast<Elf64_Xword>(layout.dynstrVaddr)) ||
        !setDynPtr(&dynEntries, DT_STRSZ, static_cast<Elf64_Xword>(newDynstr.size())) ||
        !setDynPtr(&dynEntries, DT_SYMENT, sizeof(Elf64_Sym)) ||
        !setDynPtr(&dynEntries, DT_GNU_HASH, static_cast<Elf64_Xword>(layout.gnuHashVaddr)) ||
        !setDynPtr(&dynEntries, DT_VERSYM, static_cast<Elf64_Xword>(layout.versymVaddr))) {
        if (error != nullptr) {
            *error = "required DT_* tag missing for rebuild";
        }
        return false;
    }
    if (!newSysvHash.empty()) {
        // .hash 不是强制项，存在则更新，不存在则保持现状。
        setDynPtr(&dynEntries, DT_HASH, static_cast<Elf64_Xword>(layout.sysvHashVaddr));
    }

    std::vector<uint8_t> dynBytes(dynEntries.size() * sizeof(Elf64_Dyn), 0);
    if (!dynBytes.empty()) {
        std::memcpy(dynBytes.data(), dynEntries.data(), dynBytes.size());
    }
    if (required.dynamic.offset + dynBytes.size() > newFile.size()) {
        if (error != nullptr) {
            *error = "dynamic section patch range out of file";
        }
        return false;
    }
    std::memcpy(newFile.data() + required.dynamic.offset, dynBytes.data(), dynBytes.size());

    // [阶段 6] 同步 section headers（静态视图与动态视图一致）。
    if (newFile.size() < sizeof(Elf64_Ehdr)) {
        if (error != nullptr) {
            *error = "output image too small";
        }
        return false;
    }
    auto* ehdr = reinterpret_cast<Elf64_Ehdr*>(newFile.data());
    if (ehdr->e_shnum > 0) {
        const uint64_t shdrSize = static_cast<uint64_t>(ehdr->e_shnum) *
                                  static_cast<uint64_t>(ehdr->e_shentsize);
        if (ehdr->e_shoff == 0 || ehdr->e_shoff + shdrSize > newFile.size()) {
            if (error != nullptr) {
                *error = "section headers out of range";
            }
            return false;
        }

        auto* shdrs = reinterpret_cast<Elf64_Shdr*>(newFile.data() + ehdr->e_shoff);
        auto patchShdr = [&shdrs](int sectionIndex) -> Elf64_Shdr* {
            return sectionIndex >= 0 ? &shdrs[sectionIndex] : nullptr;
        };

        const int dynsymIndex = required.dynsym.index;
        const int dynstrIndex = required.dynstr.index;
        const int versymIndex = required.versym.index;
        const int gnuHashIndex = required.gnuHash.index;
        const int hashIndex = required.hasHash ? required.hash.index : -1;

        if (auto* sh = patchShdr(dynsymIndex)) {
            sh->sh_offset = static_cast<Elf64_Off>(layout.dynsymFileOffset);
            sh->sh_addr = static_cast<Elf64_Addr>(layout.dynsymVaddr);
            sh->sh_size = static_cast<Elf64_Xword>(newDynsymBytes.size());
            sh->sh_entsize = sizeof(Elf64_Sym);
            sh->sh_link = static_cast<Elf64_Word>(dynstrIndex);
            sh->sh_info = 1;
        }
        if (auto* sh = patchShdr(dynstrIndex)) {
            sh->sh_offset = static_cast<Elf64_Off>(layout.dynstrFileOffset);
            sh->sh_addr = static_cast<Elf64_Addr>(layout.dynstrVaddr);
            sh->sh_size = static_cast<Elf64_Xword>(newDynstr.size());
        }
        if (auto* sh = patchShdr(versymIndex)) {
            sh->sh_offset = static_cast<Elf64_Off>(layout.versymFileOffset);
            sh->sh_addr = static_cast<Elf64_Addr>(layout.versymVaddr);
            sh->sh_size = static_cast<Elf64_Xword>(newVersym.size());
            sh->sh_entsize = 2;
            sh->sh_link = static_cast<Elf64_Word>(dynsymIndex);
        }
        if (auto* sh = patchShdr(gnuHashIndex)) {
            sh->sh_offset = static_cast<Elf64_Off>(layout.gnuHashFileOffset);
            sh->sh_addr = static_cast<Elf64_Addr>(layout.gnuHashVaddr);
            sh->sh_size = static_cast<Elf64_Xword>(newGnuHash.size());
            sh->sh_link = static_cast<Elf64_Word>(dynsymIndex);
            sh->sh_addralign = 8;
        }
        if (hashIndex >= 0 && !newSysvHash.empty()) {
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

    // [阶段 7] 若输入文件原本带 embedded payload，则回填到文件末尾。
    if (embeddedTailInfo.hasTail) {
        vmp::base::embedded::appendEmbeddedPayloadTail(&newFile, embeddedTailInfo.payloadBytes);
    }

    // [阶段 8] RELRO 收口：将可写 PT_LOAD 的 p_memsz 扩展到 relro_end（必要时）。
    std::string relroCloseError;
    if (!closeRelroCoverageByMemsz(&newFile, &relroCloseError)) {
        if (error != nullptr) {
            *error = relroCloseError.empty()
                         ? "rebuild close RELRO coverage failed"
                         : ("rebuild close RELRO coverage failed: " + relroCloseError);
        }
        return false;
    }

    // [阶段 9] 布局校验 + 落盘 + 二次 validate。
    std::string layoutError;
    if (!validateElfTablesForAndroid(newFile, &layoutError)) {
        if (error != nullptr) {
            *error = "rebuild output layout invalid: " + layoutError;
        }
        return false;
    }

    if (!vmp::base::file::writeFileBytes(outputPath, newFile)) {
        if (error != nullptr) {
            *error = "failed to write output file";
        }
        return false;
    }

    vmp::elfkit::zElfReadFacade patched(outputPath);
    if (!patched.isLoaded()) {
        if (error != nullptr) {
            *error = "failed to reload output elf";
        }
        return false;
    }
    std::string validateError;
    if (!patched.validate(&validateError)) {
        const bool ignoredKnownRelroIssue = !allowValidateFail &&
                                            isKnownRelroCoverageValidateError(validateError);
        if (!allowValidateFail && !ignoredKnownRelroIssue) {
            if (error != nullptr) {
                *error = "validate failed: " + validateError;
            }
            return false;
        }
        LOGW("rebuild validate warning%s: %s",
             ignoredKnownRelroIssue ? " (ignored known RELRO coverage issue)" : "",
             validateError.c_str());
    }

    LOGI("rebuild patch success: dynsym=%zu dynstr=%zu gnuhash=%zu sysvhash=%zu versym=%zu load_idx=%d new_load=%d",
         newDynsymBytes.size(),
         newDynstr.size(),
         newGnuHash.size(),
         newSysvHash.size(),
         newVersym.size(),
         layout.loadSegmentIndex,
         layout.usedNewLoadSegment ? 1 : 0);
    return true;
}

// 结束匿名命名空间。
} // namespace

// alias 表主落盘流程（仅重建路径）。
bool applyPatchbayAliasPayload(const vmp::elfkit::PatchRequiredSections& required,
                               const char* inputPath,
                               const char* outputPath,
                               const std::vector<uint8_t>& newDynsymBytes,
                               const std::vector<uint8_t>& newDynstr,
                               const std::vector<uint8_t>& newVersym,
                               const std::vector<uint8_t>& newGnuHash,
                               const std::vector<uint8_t>& newSysvHash,
                               const std::vector<PendingTakeoverSymbolBinding>& pendingTakeoverBindings,
                               uint64_t takeoverDispatchAddr,
                               bool allowValidateFail,
                               std::string* error) {
    // input/output/dynamic 必须有效。
    if (inputPath == nullptr || outputPath == nullptr || required.dynamic.index < 0) {
        if (error != nullptr) {
            *error = "invalid patch apply arguments";
        }
        return false;
    }

    // 单一路径：仅保留 ELF 重建落盘逻辑。
    std::string rebuildError;
    if (!applyRebuildAliasPayload(required,
                                  inputPath,
                                  outputPath,
                                  newDynsymBytes,
                                  newDynstr,
                                  newVersym,
                                  newGnuHash,
                                  newSysvHash,
                                  pendingTakeoverBindings,
                                  takeoverDispatchAddr,
                                  allowValidateFail,
                                  &rebuildError)) {
        if (error != nullptr) {
            *error = rebuildError.empty()
                         ? "rebuild patch apply failed"
                         : ("rebuild patch apply failed: " + rebuildError);
        }
        return false;
    }
    return true;
}
