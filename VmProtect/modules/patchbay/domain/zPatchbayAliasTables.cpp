#include "zPatchbayAliasTables.h"

// 引入日志接口。
#include "zLog.h"

// 引入 memcpy。
#include <cstring>
// 引入 strtoul。
#include <cstdlib>
// 引入数值边界。
#include <limits>
// 引入哈希映射。
#include <unordered_map>
// 引入去重集合。
#include <unordered_set>

// 进入匿名命名空间，封装内部辅助函数。
namespace {

// 从 dynstr 字节数组读取字符串指针。
const char* dynstrNameAt(const std::vector<uint8_t>& dynstrBytes, uint32_t offset) {
    // 偏移越界直接返回空。
    if (offset >= dynstrBytes.size()) {
        return nullptr;
    }
    // 返回偏移位置的 C 字符串首地址。
    return reinterpret_cast<const char*>(dynstrBytes.data() + offset);
}

// 解析 vm_takeover_entry_XXXX 的 entry id。
bool parseTakeoverEntryId(const char* symbolName, uint32_t* outEntryId) {
    if (symbolName == nullptr || outEntryId == nullptr) {
        return false;
    }
    static constexpr const char* kPrefix = "vm_takeover_entry_";
    static constexpr size_t kPrefixLen = 18;
    if (std::strncmp(symbolName, kPrefix, kPrefixLen) != 0) {
        return false;
    }
    const char* digits = symbolName + kPrefixLen;
    if (digits[0] == '\0') {
        return false;
    }
    for (const char* p = digits; *p != '\0'; ++p) {
        if (*p < '0' || *p > '9') {
            return false;
        }
    }
    const unsigned long entry = std::strtoul(digits, nullptr, 10);
    if (entry > std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    *outEntryId = static_cast<uint32_t>(entry);
    return true;
}

// 追加一个字符串到 dynstr，返回其起始偏移。
uint32_t appendDynstrString(std::vector<uint8_t>* dynstrBytes, const std::string& value) {
    const uint32_t off = static_cast<uint32_t>(dynstrBytes->size());
    dynstrBytes->insert(dynstrBytes->end(), value.begin(), value.end());
    dynstrBytes->push_back('\0');
    return off;
}

// 结束匿名命名空间。
}  // namespace

// 构建 patchbay alias 所需的 dynsym/dynstr/versym 新表。
bool buildPatchbayAliasTables(const vmp::elfkit::zElfReadFacade& elf,
                              const vmp::elfkit::PatchRequiredSections& required,
                              const std::vector<AliasPair>& aliasPairs,
                              AliasTableBuildResult* out,
                              std::string* error) {
    // 基础入参校验。
    if (required.dynsym.index < 0 ||
        required.dynstr.index < 0 ||
        required.versym.index < 0 ||
        aliasPairs.empty() ||
        out == nullptr) {
        if (error != nullptr) {
            *error = "invalid alias table build input";
        }
        return false;
    }

    // versym 必须是 2 字节元素对齐。
    if ((required.versymBytes.size() % 2U) != 0U) {
        if (error != nullptr) {
            *error = ".gnu.version size is not 2-byte aligned";
        }
        return false;
    }

    // 拷贝可修改副本。
    out->dynsymSymbols = required.dynsym.symbols;
    out->dynstrBytes = required.dynstr.bytes;
    out->versymBytes = required.versymBytes;
    out->dynsymRawBytes.clear();
    out->appendedCount = 0;
    out->pendingTakeoverBindings.clear();
    out->takeoverDispatchAddr = 0;

    // 预先收集已有导出名，防止重复追加；同时建名字索引与 entry 索引。
    std::unordered_set<std::string> existingNames;
    std::unordered_map<uint32_t, uint32_t> entrySymbolIndexById;
    // 防止同一 entry 符号在 pending 中重复记录。
    std::unordered_set<uint32_t> pendingEntrySymbolRecorded;
    existingNames.reserve(out->dynsymSymbols.size() + aliasPairs.size());
    entrySymbolIndexById.reserve(aliasPairs.size());
    pendingEntrySymbolRecorded.reserve(aliasPairs.size());
    for (size_t symbolIndex = 0; symbolIndex < out->dynsymSymbols.size(); ++symbolIndex) {
        const Elf64_Sym& sym = out->dynsymSymbols[symbolIndex];
        // st_name=0 表示空名，跳过。
        if (sym.st_name == 0) {
            continue;
        }
        // 从 dynstr 解析名称。
        const char* name = dynstrNameAt(out->dynstrBytes, sym.st_name);
        if (name == nullptr || name[0] == '\0') {
            continue;
        }
        existingNames.insert(name);
        uint32_t entryId = 0;
        if (parseTakeoverEntryId(name, &entryId)) {
            entrySymbolIndexById[entryId] = static_cast<uint32_t>(symbolIndex);
        }
    }

    // 最多打印前 N 条明细日志，避免日志爆炸。
    constexpr uint32_t kLogDetailLimit = 16;

    // 逐 alias 对构建新增符号。
    for (const AliasPair& pair : aliasPairs) {
        // 导出名已存在时直接报错，不允许 merge。
        if (existingNames.find(pair.exportName) != existingNames.end()) {
            if (error != nullptr) {
                *error = "duplicate export detected (merge is forbidden): " + pair.exportName;
            }
            return false;
        }

        uint32_t entryId = 0;
        const bool isEntryImpl = parseTakeoverEntryId(pair.implName.c_str(), &entryId);
        // 非 entry 模式仍要求实现符号可解析；entry 模式统一走“重构阶段合成跳板”。
        vmp::elfkit::PatchSymbolInfo impl{};
        bool implResolved = false;
        if (!isEntryImpl) {
            implResolved = elf.resolveSymbol(pair.implName.c_str(), &impl) && impl.found && impl.value != 0;
            if (!implResolved) {
                if (error != nullptr) {
                    *error = "impl symbol not found or invalid: " + pair.implName;
                }
                return false;
            }
        }

        // entry 模式统一使用“待回填地址”的 entry 符号，不再依赖预置槽位导出。
        if (isEntryImpl) {
            auto entryIt = entrySymbolIndexById.find(entryId);
            if (entryIt == entrySymbolIndexById.end()) {
                const uint32_t entryNameOffset = appendDynstrString(&out->dynstrBytes, pair.implName);
                Elf64_Sym entrySym{};
                entrySym.st_name = entryNameOffset;
                entrySym.st_info = static_cast<unsigned char>(((STB_GLOBAL & 0x0f) << 4) | (STT_FUNC & 0x0f));
                entrySym.st_other = 0;
                // 重构阶段会把 st_value 写成合成跳板地址；先标记为 ABS。
                entrySym.st_shndx = SHN_ABS;
                entrySym.st_value = 0;
                entrySym.st_size = 0;
                out->dynsymSymbols.push_back(entrySym);
                out->versymBytes.push_back(1);
                out->versymBytes.push_back(0);

                const uint32_t newEntryIndex = static_cast<uint32_t>(out->dynsymSymbols.size() - 1);
                entrySymbolIndexById[entryId] = newEntryIndex;
                existingNames.insert(pair.implName);
                entryIt = entrySymbolIndexById.find(entryId);
            }
            // 对于已有 entry 符号（旧镜像可能自带）同样强制进入 pending 回填。
            if (entryIt != entrySymbolIndexById.end() &&
                pendingEntrySymbolRecorded.insert(entryId).second) {
                out->pendingTakeoverBindings.push_back({entryIt->second, entryId});
            }
        }

        // 记录 exportName 在 dynstr 中的偏移。
        const uint32_t nameOffset = appendDynstrString(&out->dynstrBytes, pair.exportName);

        // 构建新增 dynsym 条目。
        Elf64_Sym sym{};
        // 绑定字符串偏移。
        sym.st_name = nameOffset;
        // 绑定与类型：
        // - bind 固定 STB_GLOBAL；
        // - entry 模式固定 STT_FUNC；
        // - 非 entry 模式优先沿用 impl.type，无法解析时兜底 STT_FUNC。
        const uint32_t symbolType = (!isEntryImpl && implResolved)
                                    ? (impl.type == STT_NOTYPE ? STT_FUNC : impl.type)
                                    : STT_FUNC;
        sym.st_info = static_cast<unsigned char>(((STB_GLOBAL & 0x0f) << 4) | (symbolType & 0x0f));
        // 可见性保持默认（STV_DEFAULT）。
        sym.st_other = 0;
        // 节索引/地址：
        // - entry 模式统一在重构阶段补齐（先置 ABS + value=0）；
        // - 非 entry 模式沿用实现符号。
        sym.st_shndx = (!isEntryImpl && implResolved) ? impl.shndx : SHN_ABS;
        sym.st_value = (!isEntryImpl && implResolved) ? impl.value : 0;
        // size 字段：
        // - 若 exportKey 非 0，则承载 route4 key；
        // - 否则非 entry 模式沿用实现符号 size，entry 模式记 0。
        sym.st_size = (pair.exportKey != 0) ? static_cast<Elf64_Xword>(pair.exportKey)
                                            : static_cast<Elf64_Xword>((!isEntryImpl && implResolved) ? impl.size : 0);
        // 追加到新 dynsym。
        out->dynsymSymbols.push_back(sym);
        const uint32_t newAliasIndex = static_cast<uint32_t>(out->dynsymSymbols.size() - 1);

        // versym 默认追加版本 1（小端序 0x0001）。
        out->versymBytes.push_back(1);
        out->versymBytes.push_back(0);

        // 记录新导出名，避免后续重复。
        existingNames.insert(pair.exportName);
        // 追加计数 +1。
        ++out->appendedCount;

        // entry 模式：alias 条目统一走重构阶段回填。
        if (isEntryImpl) {
            out->pendingTakeoverBindings.push_back({newAliasIndex, entryId});
        }

        // 输出有限条明细日志。
        if (out->appendedCount <= kLogDetailLimit) {
            LOGI("Append dyn export alias(patchbay): %s -> %s (addr=0x%llx key=0x%llx)",
                 pair.exportName.c_str(),
                 pair.implName.c_str(),
                 static_cast<unsigned long long>(impl.value),
                 static_cast<unsigned long long>(pair.exportKey));
        }
    }

    // 若存在待回填 entry，则必须能解析 dispatch 符号地址用于合成跳板。
    if (!out->pendingTakeoverBindings.empty()) {
        vmp::elfkit::PatchSymbolInfo dispatch{};
        if (!elf.resolveSymbol("vm_takeover_dispatch_by_id", &dispatch) || !dispatch.found || dispatch.value == 0) {
            if (error != nullptr) {
                *error = "dispatch symbol not found or invalid: vm_takeover_dispatch_by_id";
            }
            return false;
        }
        out->takeoverDispatchAddr = dispatch.value;
    }

    // 输出汇总日志。
    LOGI("patchbay alias summary: requested=%zu appended=%u",
         aliasPairs.size(),
         out->appendedCount);

    // 没有任何新增条目视为失败。
    if (out->appendedCount == 0) {
        if (error != nullptr) {
            *error = "no new aliases were appended";
        }
        return false;
    }

    // 将 dynsym 条目数组序列化为原始字节。
    out->dynsymRawBytes.resize(out->dynsymSymbols.size() * sizeof(Elf64_Sym));
    std::memcpy(out->dynsymRawBytes.data(), out->dynsymSymbols.data(), out->dynsymRawBytes.size());
    return true;
}
