#include "zElfTakeoverDynsym.h"

// strtoul。
#include <cstdlib>
// memcmp / strncmp。
#include <cstring>
// ELF 结构定义。
#include <elf.h>
// std::min。
#include <algorithm>
// std::string。
#include <string>
// 哈希映射。
#include <unordered_map>
// 顺序容器。
#include <vector>

// 文件字节读取工具。
#include "zFileBytes.h"
// 日志。
#include "zLog.h"

namespace {

// ELF64 视图（仅保留本文件需要的 dynsym/dynstr 信息）。
struct DynsymView {
    // dynsym 起始指针。
    const Elf64_Sym* symbols = nullptr;
    // dynsym 条目数。
    size_t symbolCount = 0;
    // dynstr 起始指针。
    const char* strtab = nullptr;
    // dynstr 总字节数。
    size_t strtabSize = 0;
};

// PT_LOAD 映射视图（文件偏移 <-> 虚拟地址）。
struct LoadSegmentView {
    // 段内文件映射虚拟地址起点。
    uint64_t vaddrStart = 0;
    // 段内文件映射虚拟地址终点（开区间）。
    uint64_t vaddrEnd = 0;
    // 对应文件偏移起点。
    uint64_t fileOffset = 0;
};

// 统一范围校验（offset + size 不越界）。
bool checkRange(size_t offset, size_t size, size_t totalSize) {
    if (offset > totalSize) {
        return false;
    }
    if (size > totalSize - offset) {
        return false;
    }
    return true;
}

// 从 PT_LOAD 映射把虚拟地址转换为文件偏移。
bool mapVaddrToFileOffset(uint64_t vaddr,
                          const std::vector<LoadSegmentView>& loadSegments,
                          size_t fileSize,
                          size_t* outFileOffset,
                          size_t* outMaxContiguousBytes = nullptr) {
    if (outFileOffset == nullptr) {
        return false;
    }
    for (const LoadSegmentView& load : loadSegments) {
        if (vaddr < load.vaddrStart || vaddr >= load.vaddrEnd) {
            continue;
        }
        const uint64_t delta = vaddr - load.vaddrStart;
        const uint64_t fileOffset64 = load.fileOffset + delta;
        if (fileOffset64 > static_cast<uint64_t>(fileSize)) {
            return false;
        }
        const size_t fileOffset = static_cast<size_t>(fileOffset64);
        *outFileOffset = fileOffset;
        if (outMaxContiguousBytes != nullptr) {
            const uint64_t segRemain64 = load.vaddrEnd - vaddr;
            const size_t segRemain = static_cast<size_t>(
                std::min<uint64_t>(segRemain64, static_cast<uint64_t>(fileSize - fileOffset)));
            *outMaxContiguousBytes = segRemain;
        }
        return true;
    }
    return false;
}

// 通过 DT_HASH 解析 dynsym 条目数（nchain）。
bool parseDynsymCountBySysvHash(const std::vector<uint8_t>& fileBytes,
                                const std::vector<LoadSegmentView>& loadSegments,
                                uint64_t dtHashVaddr,
                                size_t* outDynsymCount) {
    if (outDynsymCount == nullptr || dtHashVaddr == 0) {
        return false;
    }
    size_t hashOffset = 0;
    if (!mapVaddrToFileOffset(dtHashVaddr, loadSegments, fileBytes.size(), &hashOffset)) {
        return false;
    }
    // SysV hash 头至少 8 字节：nbucket + nchain。
    if (!checkRange(hashOffset, sizeof(uint32_t) * 2U, fileBytes.size())) {
        return false;
    }
    const uint32_t* hashHeader = reinterpret_cast<const uint32_t*>(fileBytes.data() + hashOffset);
    const uint32_t nchain = hashHeader[1];
    if (nchain == 0) {
        return false;
    }
    *outDynsymCount = static_cast<size_t>(nchain);
    return true;
}

// 通过 DT_GNU_HASH 解析 dynsym 条目数。
bool parseDynsymCountByGnuHash(const std::vector<uint8_t>& fileBytes,
                               const std::vector<LoadSegmentView>& loadSegments,
                               uint64_t dtGnuHashVaddr,
                               size_t* outDynsymCount) {
    if (outDynsymCount == nullptr || dtGnuHashVaddr == 0) {
        return false;
    }
    size_t gnuHashOffset = 0;
    size_t gnuHashMaxBytes = 0;
    if (!mapVaddrToFileOffset(dtGnuHashVaddr,
                              loadSegments,
                              fileBytes.size(),
                              &gnuHashOffset,
                              &gnuHashMaxBytes)) {
        return false;
    }
    // GNU hash 头：nbuckets/symoffset/bloomSize/bloomShift。
    constexpr size_t kGnuHashHeaderSize = sizeof(uint32_t) * 4U;
    if (gnuHashMaxBytes < kGnuHashHeaderSize ||
        !checkRange(gnuHashOffset, kGnuHashHeaderSize, fileBytes.size())) {
        return false;
    }

    const uint8_t* gnuHashBase = fileBytes.data() + gnuHashOffset;
    const uint32_t* gnuHashHeader = reinterpret_cast<const uint32_t*>(gnuHashBase);
    const uint32_t bucketCount = gnuHashHeader[0];
    const uint32_t symOffset = gnuHashHeader[1];
    const uint32_t bloomCount = gnuHashHeader[2];

    // bucketCount=0 说明无可用符号。
    if (bucketCount == 0) {
        return false;
    }

    // 计算 buckets/chains 起点并做边界保护。
    const uint64_t bloomBytes64 = static_cast<uint64_t>(bloomCount) * sizeof(Elf64_Xword);
    const uint64_t bucketBytes64 = static_cast<uint64_t>(bucketCount) * sizeof(uint32_t);
    const uint64_t bucketsOff64 = kGnuHashHeaderSize + bloomBytes64;
    const uint64_t chainsOff64 = bucketsOff64 + bucketBytes64;
    if (bucketsOff64 > gnuHashMaxBytes || chainsOff64 > gnuHashMaxBytes) {
        return false;
    }

    const uint8_t* bucketsBase = gnuHashBase + static_cast<size_t>(bucketsOff64);
    const uint8_t* chainsBase = gnuHashBase + static_cast<size_t>(chainsOff64);
    const uint32_t* buckets = reinterpret_cast<const uint32_t*>(bucketsBase);
    const uint32_t* chains = reinterpret_cast<const uint32_t*>(chainsBase);
    const size_t chainCountMax = (gnuHashMaxBytes - static_cast<size_t>(chainsOff64)) / sizeof(uint32_t);
    if (chainCountMax == 0) {
        return false;
    }

    bool foundAnyBucket = false;
    uint64_t maxSymbolIndex = 0;
    for (uint32_t bucketIndex = 0; bucketIndex < bucketCount; ++bucketIndex) {
        const uint32_t bucket = buckets[bucketIndex];
        if (bucket == 0) {
            continue;
        }
        if (bucket < symOffset) {
            return false;
        }
        foundAnyBucket = true;
        size_t chainIndex = static_cast<size_t>(bucket - symOffset);
        for (;;) {
            if (chainIndex >= chainCountMax) {
                return false;
            }
            const uint64_t symbolIndex = static_cast<uint64_t>(symOffset) + static_cast<uint64_t>(chainIndex);
            if (symbolIndex > maxSymbolIndex) {
                maxSymbolIndex = symbolIndex;
            }
            const uint32_t chainValue = chains[chainIndex];
            // GNU hash chain 低位 bit=1 表示桶尾。
            if ((chainValue & 1U) != 0U) {
                break;
            }
            ++chainIndex;
        }
    }

    // 所有 bucket 都为空时，dynsym 至少保留 symOffset 之前的索引空间。
    if (!foundAnyBucket) {
        *outDynsymCount = static_cast<size_t>(symOffset);
        return *outDynsymCount > 0;
    }

    *outDynsymCount = static_cast<size_t>(maxSymbolIndex + 1U);
    return *outDynsymCount > 0;
}

// 从 Program Header + Dynamic Table 构建 dynsym 视图（不依赖 Section Header）。
bool buildDynsymViewFromDynamic(const std::vector<uint8_t>& fileBytes,
                                const Elf64_Ehdr* ehdr,
                                DynsymView* outView,
                                std::string* outError) {
    if (ehdr == nullptr || outView == nullptr) {
        if (outError != nullptr) {
            *outError = "invalid elf header or output view";
        }
        return false;
    }
    if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0 || ehdr->e_phentsize != sizeof(Elf64_Phdr)) {
        if (outError != nullptr) {
            *outError = "program header table is invalid";
        }
        return false;
    }
    if (!checkRange(static_cast<size_t>(ehdr->e_phoff),
                    static_cast<size_t>(ehdr->e_phnum) * sizeof(Elf64_Phdr),
                    fileBytes.size())) {
        if (outError != nullptr) {
            *outError = "program header table out of range";
        }
        return false;
    }

    const auto* phdrs = reinterpret_cast<const Elf64_Phdr*>(fileBytes.data() + ehdr->e_phoff);
    std::vector<LoadSegmentView> loadSegments;
    loadSegments.reserve(ehdr->e_phnum);

    const Elf64_Phdr* dynamicPhdr = nullptr;
    for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
        const Elf64_Phdr& ph = phdrs[i];
        if (ph.p_type == PT_LOAD) {
            const uint64_t vaddrStart = ph.p_vaddr;
            const uint64_t vaddrEnd = ph.p_vaddr + ph.p_filesz;
            if (ph.p_filesz == 0 || vaddrEnd <= vaddrStart) {
                continue;
            }
            if (!checkRange(static_cast<size_t>(ph.p_offset),
                            static_cast<size_t>(ph.p_filesz),
                            fileBytes.size())) {
                continue;
            }
            loadSegments.push_back({vaddrStart, vaddrEnd, ph.p_offset});
            continue;
        }
        if (ph.p_type == PT_DYNAMIC) {
            dynamicPhdr = &ph;
        }
    }

    if (dynamicPhdr == nullptr || dynamicPhdr->p_filesz < sizeof(Elf64_Dyn)) {
        if (outError != nullptr) {
            *outError = "PT_DYNAMIC is missing or empty";
        }
        return false;
    }
    if (!checkRange(static_cast<size_t>(dynamicPhdr->p_offset),
                    static_cast<size_t>(dynamicPhdr->p_filesz),
                    fileBytes.size())) {
        if (outError != nullptr) {
            *outError = "PT_DYNAMIC file range is invalid";
        }
        return false;
    }

    const auto* dynEntries = reinterpret_cast<const Elf64_Dyn*>(fileBytes.data() + dynamicPhdr->p_offset);
    const size_t dynEntryCount = static_cast<size_t>(dynamicPhdr->p_filesz / sizeof(Elf64_Dyn));

    uint64_t dtSymtab = 0;
    uint64_t dtStrtab = 0;
    uint64_t dtStrsz = 0;
    uint64_t dtSyment = 0;
    uint64_t dtHash = 0;
    uint64_t dtGnuHash = 0;

    for (size_t i = 0; i < dynEntryCount; ++i) {
        const Elf64_Dyn& dyn = dynEntries[i];
        if (dyn.d_tag == DT_NULL) {
            break;
        }
        if (dyn.d_tag == DT_SYMTAB) {
            dtSymtab = dyn.d_un.d_ptr;
            continue;
        }
        if (dyn.d_tag == DT_STRTAB) {
            dtStrtab = dyn.d_un.d_ptr;
            continue;
        }
        if (dyn.d_tag == DT_STRSZ) {
            dtStrsz = dyn.d_un.d_val;
            continue;
        }
        if (dyn.d_tag == DT_SYMENT) {
            dtSyment = dyn.d_un.d_val;
            continue;
        }
        if (dyn.d_tag == DT_HASH) {
            dtHash = dyn.d_un.d_ptr;
            continue;
        }
        if (dyn.d_tag == DT_GNU_HASH) {
            dtGnuHash = dyn.d_un.d_ptr;
            continue;
        }
    }

    if (dtSymtab == 0 || dtStrtab == 0 || dtStrsz == 0) {
        if (outError != nullptr) {
            *outError = "DT_SYMTAB/DT_STRTAB/DT_STRSZ is incomplete";
        }
        return false;
    }
    // DT_SYMENT 缺失时按 ELF64 默认值兜底。
    if (dtSyment == 0) {
        dtSyment = sizeof(Elf64_Sym);
    }
    if (dtSyment != sizeof(Elf64_Sym)) {
        if (outError != nullptr) {
            *outError = "DT_SYMENT is not Elf64_Sym size";
        }
        return false;
    }

    size_t dynsymCount = 0;
    if (!parseDynsymCountBySysvHash(fileBytes, loadSegments, dtHash, &dynsymCount)) {
        if (!parseDynsymCountByGnuHash(fileBytes, loadSegments, dtGnuHash, &dynsymCount)) {
            if (outError != nullptr) {
                *outError = "cannot determine dynsym count from DT_HASH/DT_GNU_HASH";
            }
            return false;
        }
    }
    if (dynsymCount == 0) {
        if (outError != nullptr) {
            *outError = "resolved dynsym count is zero";
        }
        return false;
    }

    size_t dynsymOffset = 0;
    if (!mapVaddrToFileOffset(dtSymtab, loadSegments, fileBytes.size(), &dynsymOffset)) {
        if (outError != nullptr) {
            *outError = "DT_SYMTAB cannot map to file";
        }
        return false;
    }
    const size_t dynsymBytes = dynsymCount * sizeof(Elf64_Sym);
    if (!checkRange(dynsymOffset, dynsymBytes, fileBytes.size())) {
        if (outError != nullptr) {
            *outError = "dynsym range is out of file";
        }
        return false;
    }

    size_t dynstrOffset = 0;
    if (!mapVaddrToFileOffset(dtStrtab, loadSegments, fileBytes.size(), &dynstrOffset)) {
        if (outError != nullptr) {
            *outError = "DT_STRTAB cannot map to file";
        }
        return false;
    }
    if (!checkRange(dynstrOffset, static_cast<size_t>(dtStrsz), fileBytes.size())) {
        if (outError != nullptr) {
            *outError = "dynstr range is out of file";
        }
        return false;
    }

    outView->symbols = reinterpret_cast<const Elf64_Sym*>(fileBytes.data() + dynsymOffset);
    outView->symbolCount = dynsymCount;
    outView->strtab = reinterpret_cast<const char*>(fileBytes.data() + dynstrOffset);
    outView->strtabSize = static_cast<size_t>(dtStrsz);
    return true;
}

// 从 section table 构建 dynsym 视图（仅作 dynamic 路径失败时兜底）。
bool buildDynsymViewFromSection(const std::vector<uint8_t>& fileBytes,
                                const Elf64_Ehdr* ehdr,
                                DynsymView* outView,
                                std::string* outError) {
    if (ehdr == nullptr || outView == nullptr) {
        if (outError != nullptr) {
            *outError = "invalid elf header or output view";
        }
        return false;
    }
    if (ehdr->e_shoff == 0 || ehdr->e_shentsize != sizeof(Elf64_Shdr) || ehdr->e_shnum == 0) {
        if (outError != nullptr) {
            *outError = "section table is invalid";
        }
        return false;
    }
    if (!checkRange(static_cast<size_t>(ehdr->e_shoff),
                    static_cast<size_t>(ehdr->e_shnum) * sizeof(Elf64_Shdr),
                    fileBytes.size())) {
        if (outError != nullptr) {
            *outError = "section table out of range";
        }
        return false;
    }

    const auto* shdrs = reinterpret_cast<const Elf64_Shdr*>(fileBytes.data() + ehdr->e_shoff);
    const Elf64_Shdr* dynsymShdr = nullptr;
    const Elf64_Shdr* dynstrShdr = nullptr;
    for (uint16_t i = 0; i < ehdr->e_shnum; ++i) {
        if (shdrs[i].sh_type != SHT_DYNSYM) {
            continue;
        }
        dynsymShdr = &shdrs[i];
        if (shdrs[i].sh_link < ehdr->e_shnum) {
            dynstrShdr = &shdrs[shdrs[i].sh_link];
        }
        break;
    }

    if (dynsymShdr == nullptr || dynstrShdr == nullptr || dynstrShdr->sh_type != SHT_STRTAB) {
        if (outError != nullptr) {
            *outError = "dynsym/dynstr section is missing";
        }
        return false;
    }
    if (dynsymShdr->sh_entsize != sizeof(Elf64_Sym) || dynsymShdr->sh_size < sizeof(Elf64_Sym)) {
        if (outError != nullptr) {
            *outError = "dynsym section layout is invalid";
        }
        return false;
    }
    if (!checkRange(static_cast<size_t>(dynsymShdr->sh_offset),
                    static_cast<size_t>(dynsymShdr->sh_size),
                    fileBytes.size()) ||
        !checkRange(static_cast<size_t>(dynstrShdr->sh_offset),
                    static_cast<size_t>(dynstrShdr->sh_size),
                    fileBytes.size())) {
        if (outError != nullptr) {
            *outError = "dynsym/dynstr section range is invalid";
        }
        return false;
    }

    outView->symbols = reinterpret_cast<const Elf64_Sym*>(fileBytes.data() + dynsymShdr->sh_offset);
    outView->symbolCount = static_cast<size_t>(dynsymShdr->sh_size / sizeof(Elf64_Sym));
    outView->strtab = reinterpret_cast<const char*>(fileBytes.data() + dynstrShdr->sh_offset);
    outView->strtabSize = static_cast<size_t>(dynstrShdr->sh_size);
    return true;
}

// 解析 takeover entry 符号名：vm_takeover_entry_XXXX -> entryId。
bool parseTakeoverEntryId(const char* symbolName, uint32_t* outEntryId) {
    // 输出参数必须有效。
    if (outEntryId == nullptr || symbolName == nullptr) {
        return false;
    }
    // entry 符号固定前缀。
    static constexpr const char* kPrefix = "vm_takeover_entry_";
    // 前缀长度（不含 '\0'）。
    static constexpr size_t kPrefixLen = 18;
    // 前缀不匹配则不是槽位名。
    if (std::strncmp(symbolName, kPrefix, kPrefixLen) != 0) {
        return false;
    }
    // 取前缀后的数字串。
    const char* digits = symbolName + kPrefixLen;
    // 数字串不能为空。
    if (digits[0] == '\0') {
        return false;
    }
    // 必须全部是十进制数字。
    for (const char* p = digits; *p != '\0'; ++p) {
        if (*p < '0' || *p > '9') {
            return false;
        }
    }
    // 转成无符号长整型。
    const unsigned long entry = std::strtoul(digits, nullptr, 10);
    // 超出 uint32_t 范围则拒绝。
    if (entry > 0xFFFFFFFFUL) {
        return false;
    }
    // 回写解析结果。
    *outEntryId = static_cast<uint32_t>(entry);
    return true;
}

} // namespace

// 从 patched vmengine so 的 dynsym/dynstr 恢复 takeover 表。
bool zElfRecoverTakeoverEntriesFromPatchedSo(
    const std::string& soPath,
    std::vector<zTakeoverSymbolEntry>& outEntries
) {
    // 每次调用先清空输出容器。
    outEntries.clear();
    // 整个 so 文件字节缓冲。
    std::vector<uint8_t> fileBytes;
    // 读取 so 文件到内存。
    if (!zFileBytes::readFileBytes(soPath, fileBytes)) {
        LOGE("[route_symbol_takeover] load vmengine file failed: %s", soPath.c_str());
        return false;
    }
    // 至少要容纳 ELF64 头。
    if (fileBytes.size() < sizeof(Elf64_Ehdr)) {
        LOGE("[route_symbol_takeover] vmengine file too small: %s", soPath.c_str());
        return false;
    }

    // 解释为 ELF64 头。
    const auto* ehdr = reinterpret_cast<const Elf64_Ehdr*>(fileBytes.data());
    // 校验魔数、位宽、小端。
    if (std::memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
        LOGE("[route_symbol_takeover] invalid elf header: %s", soPath.c_str());
        return false;
    }

    // 优先走 dynamic table 解析，strip 后无 section table 时仍可工作。
    DynsymView dynsymView;
    std::string dynViewError;
    if (!buildDynsymViewFromDynamic(fileBytes, ehdr, &dynsymView, &dynViewError)) {
        LOGW("[route_symbol_takeover] dynamic parse failed, fallback section parse: %s",
             dynViewError.empty() ? "(unknown)" : dynViewError.c_str());
        // dynamic 失败时再回退 section 路径，兼容历史产物。
        if (!buildDynsymViewFromSection(fileBytes, ehdr, &dynsymView, &dynViewError)) {
            LOGE("[route_symbol_takeover] dynsym parse failed: %s",
                 dynViewError.empty() ? "(unknown)" : dynViewError.c_str());
            return false;
        }
    }
    const Elf64_Sym* dynsyms = dynsymView.symbols;
    const size_t dynsymCount = dynsymView.symbolCount;
    const char* dynstr = dynsymView.strtab;
    const size_t dynstrSize = dynsymView.strtabSize;
    if (dynsyms == nullptr || dynstr == nullptr || dynsymCount <= 1 || dynstrSize == 0) {
        LOGE("[route_symbol_takeover] dynsym view is invalid: %s", soPath.c_str());
        return false;
    }

    // 第一阶段映射：st_value -> entryId（从 vm_takeover_entry_xxxx 符号提取）。
    std::unordered_map<uint64_t, uint32_t> entryIdByValue;
    // 第二阶段映射：entryId -> key（这里 key 使用普通符号 st_size 承载）。
    std::unordered_map<uint32_t, uint64_t> keyByEntryId;

    // 第一遍：收集 entry 符号。
    for (size_t i = 1; i < dynsymCount; ++i) {
        // 跳过 dynsym[0]（保留空符号）。
        const Elf64_Sym& sym = dynsyms[i];
        // 名称偏移越界则跳过。
        if (sym.st_name >= dynstrSize) {
            continue;
        }
        // 取得符号名。
        const char* name = dynstr + sym.st_name;
        // 空名跳过。
        if (name[0] == '\0') {
            continue;
        }
        // 尝试解析 entryId。
        uint32_t entryId = 0;
        if (!parseTakeoverEntryId(name, &entryId)) {
            continue;
        }
        // 用 st_value 建立 entry 映射。
        entryIdByValue[static_cast<uint64_t>(sym.st_value)] = entryId;
    }

    // 未找到任何 entry，直接失败。
    if (entryIdByValue.empty()) {
        LOGE("[route_symbol_takeover] no takeover entries found in dynsym: %s", soPath.c_str());
        return false;
    }

    // 第二遍：从普通符号中恢复 entryId -> key。
    for (size_t i = 1; i < dynsymCount; ++i) {
        const Elf64_Sym& sym = dynsyms[i];
        // 名称越界或未定义符号跳过。
        if (sym.st_name >= dynstrSize || sym.st_shndx == SHN_UNDEF) {
            continue;
        }
        // 读取符号名。
        const char* name = dynstr + sym.st_name;
        // 空名跳过。
        if (name[0] == '\0') {
            continue;
        }
        // entry 符号本身不参与 key 提取。
        uint32_t selfEntryId = 0;
        if (parseTakeoverEntryId(name, &selfEntryId)) {
            continue;
        }
        // 用 st_value 找对应 entryId。
        const auto entryIt = entryIdByValue.find(static_cast<uint64_t>(sym.st_value));
        if (entryIt == entryIdByValue.end()) {
            continue;
        }
        const uint32_t entryId = entryIt->second;
        // 当前实现把 key 编码在 st_size 字段。
        const uint64_t key = static_cast<uint64_t>(sym.st_size);
        // key 为 0 无效。
        if (key == 0) {
            continue;
        }
        // 同一 entry 出现不同 key 视为冲突。
        auto existed = keyByEntryId.find(entryId);
        if (existed != keyByEntryId.end() && existed->second != key) {
            LOGE("[route_symbol_takeover] conflicting key for entry=%u: old=0x%llx new=0x%llx",
                 entryId,
                 static_cast<unsigned long long>(existed->second),
                 static_cast<unsigned long long>(key));
            return false;
        }
        // 写入或覆盖同值。
        keyByEntryId[entryId] = key;
    }

    // 没拿到任何 key 也算失败。
    if (keyByEntryId.empty()) {
        LOGE("[route_symbol_takeover] no takeover key entries found in dynsym: %s", soPath.c_str());
        return false;
    }

    // 输出条目数组。
    outEntries.reserve(keyByEntryId.size());
    for (const auto& item : keyByEntryId) {
        outEntries.push_back(zTakeoverSymbolEntry{item.first, item.second});
    }
    LOGI("[route_symbol_takeover] recovered takeover entries from dynsym: entry_count=%llu",
         static_cast<unsigned long long>(outEntries.size()));
    return true;
}
