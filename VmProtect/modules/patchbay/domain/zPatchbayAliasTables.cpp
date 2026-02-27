#include "zPatchbayAliasTables.h"

// 引入日志接口。
#include "zLog.h"

// 引入 memcpy。
#include <cstring>
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

    // 预先收集已有导出名，防止重复追加。
    std::unordered_set<std::string> existingNames;
    existingNames.reserve(out->dynsymSymbols.size() + aliasPairs.size());
    for (const Elf64_Sym& sym : out->dynsymSymbols) {
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
    }

    // 最多打印前 N 条明细日志，避免日志爆炸。
    constexpr uint32_t kLogDetailLimit = 16;

    // 逐 alias 对构建新增符号。
    for (const AliasPair& pair : aliasPairs) {
        // 导出名不能为空。
        if (pair.exportName.empty()) {
            if (error != nullptr) {
                *error = "empty export name in alias pair";
            }
            return false;
        }
        // key 必须非零。
        if (pair.exportKey == 0) {
            if (error != nullptr) {
                *error = "zero export key for alias: " + pair.exportName;
            }
            return false;
        }
        // soId 必须非零。
        if (pair.soId == 0) {
            if (error != nullptr) {
                *error = "zero so id for alias: " + pair.exportName;
            }
            return false;
        }
        // 导出名已存在时直接报错，不允许 merge。
        if (existingNames.find(pair.exportName) != existingNames.end()) {
            if (error != nullptr) {
                *error = "duplicate export detected (merge is forbidden): " + pair.exportName;
            }
            return false;
        }

        // 记录 exportName 在 dynstr 中的偏移。
        const uint32_t nameOffset = appendDynstrString(&out->dynstrBytes, pair.exportName);

        // 构建新增 dynsym 条目：地址占位，后续回填到合成跳板地址。
        Elf64_Sym sym{};
        sym.st_name = nameOffset;
        sym.st_info = static_cast<unsigned char>(((STB_GLOBAL & 0x0f) << 4) | (STT_FUNC & 0x0f));
        sym.st_other = 0;
        sym.st_shndx = SHN_ABS;
        sym.st_value = 0;
        sym.st_size = 0;
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

        // 记录后续回填绑定：symbolIndex -> (symbolKey, soId)。
        out->pendingTakeoverBindings.push_back({newAliasIndex, pair.exportKey, pair.soId});

        // 输出有限条明细日志。
        if (out->appendedCount <= kLogDetailLimit) {
            LOGI("Append dyn export alias(patchbay): %s -> key=0x%llx so_id=%u",
                 pair.exportName.c_str(),
                 static_cast<unsigned long long>(pair.exportKey),
                 pair.soId);
        }
    }

    // 若存在待回填条目，则必须能解析 dispatch 符号地址用于合成跳板。
    if (!out->pendingTakeoverBindings.empty()) {
        vmp::elfkit::PatchSymbolInfo dispatch{};
        if (!elf.resolveSymbol("vm_takeover_dispatch_by_key", &dispatch) || !dispatch.found || dispatch.value == 0) {
            if (error != nullptr) {
                *error = "dispatch symbol not found or invalid: vm_takeover_dispatch_by_key";
            }
            return false;
        }
        out->takeoverDispatchAddr = dispatch.value;
    }

    // 输出汇总日志。
    LOGI("patchbay alias summary: requested=%zu appended=%u pending=%zu",
         aliasPairs.size(),
         out->appendedCount,
         out->pendingTakeoverBindings.size());

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
