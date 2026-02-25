#include "zPatchbayAliasTables.h"

// 引入节字符串读取辅助。
#include "zSectionEntry.h"
// 引入日志接口。
#include "zLog.h"

// 引入 memcpy。
#include <cstring>
// 引入去重集合。
#include <unordered_set>

// 构建 patchbay alias 所需的 dynsym/dynstr/versym 新表。
bool buildPatchbayAliasTables(const vmp::elfkit::PatchElfImage& elf,
                              const vmp::elfkit::PatchRequiredSections& required,
                              const std::vector<AliasPair>& aliasPairs,
                              AliasTableBuildResult* out,
                              std::string* error) {
    // 提取必要节指针。
    const auto* dynsymSection = required.dynsym;
    const auto* dynstrSection = required.dynstr;
    const auto* versymSection = required.versym;

    // 基础入参校验。
    if (dynsymSection == nullptr ||
        dynstrSection == nullptr ||
        versymSection == nullptr ||
        aliasPairs.empty() ||
        out == nullptr) {
        if (error != nullptr) {
            *error = "invalid alias table build input";
        }
        return false;
    }

    // versym 必须是 2 字节元素对齐。
    if ((versymSection->payload.size() % 2U) != 0U) {
        if (error != nullptr) {
            *error = ".gnu.version size is not 2-byte aligned";
        }
        return false;
    }

    // 拷贝可修改副本。
    out->dynsymSymbols = dynsymSection->symbols;
    out->dynstrBytes = dynstrSection->payload;
    out->versymBytes = versymSection->payload;
    out->dynsymRawBytes.clear();
    out->appendedCount = 0;

    // 预先收集已有导出名，防止重复追加。
    std::unordered_set<std::string> existingNames;
    existingNames.reserve(out->dynsymSymbols.size() + aliasPairs.size());
    for (const Elf64_Sym& sym : out->dynsymSymbols) {
        // st_name=0 表示空名，跳过。
        if (sym.st_name == 0) {
            continue;
        }
        // 从 dynstr 解析名称。
        const char* name = dynstrSection->getStringAt(sym.st_name);
        if (name == nullptr || name[0] == '\0') {
            continue;
        }
        existingNames.insert(name);
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

        // 解析实现符号信息。
        vmp::elfkit::PatchSymbolInfo impl{};
        if (!elf.resolveSymbol(pair.implName.c_str(), &impl) || !impl.found || impl.value == 0) {
            if (error != nullptr) {
                *error = "impl symbol not found or invalid: " + pair.implName;
            }
            return false;
        }

        // 记录 exportName 在 dynstr 中的偏移。
        const uint32_t nameOffset = static_cast<uint32_t>(out->dynstrBytes.size());
        // 追加导出名字符串字节。
        out->dynstrBytes.insert(out->dynstrBytes.end(), pair.exportName.begin(), pair.exportName.end());
        // 追加字符串终止符。
        out->dynstrBytes.push_back('\0');

        // 构建新增 dynsym 条目。
        Elf64_Sym sym{};
        // 绑定字符串偏移。
        sym.st_name = nameOffset;
        // 绑定与类型：
        // - bind 固定 STB_GLOBAL；
        // - type 优先沿用 impl.type，NOTYPE 时兜底为 STT_FUNC。
        sym.st_info = static_cast<unsigned char>(
            ((STB_GLOBAL & 0x0f) << 4) |
            ((impl.type == STT_NOTYPE ? STT_FUNC : impl.type) & 0x0f));
        // 可见性保持默认（STV_DEFAULT）。
        sym.st_other = 0;
        // 节索引沿用实现符号。
        sym.st_shndx = impl.shndx;
        // 地址沿用实现符号地址。
        sym.st_value = impl.value;
        // size 字段：
        // - 若 exportKey 非 0，则承载 route4 key；
        // - 否则沿用实现符号 size。
        sym.st_size = (pair.exportKey != 0) ? static_cast<Elf64_Xword>(pair.exportKey) : impl.size;
        // 追加到新 dynsym。
        out->dynsymSymbols.push_back(sym);

        // versym 默认追加版本 1（小端序 0x0001）。
        out->versymBytes.push_back(1);
        out->versymBytes.push_back(0);

        // 记录新导出名，避免后续重复。
        existingNames.insert(pair.exportName);
        // 追加计数 +1。
        ++out->appendedCount;

        // 输出有限条明细日志。
        if (out->appendedCount <= kLogDetailLimit) {
            LOGI("Append dyn export alias(patchbay): %s -> %s (addr=0x%llx key=0x%llx)",
                 pair.exportName.c_str(),
                 pair.implName.c_str(),
                 static_cast<unsigned long long>(impl.value),
                 static_cast<unsigned long long>(pair.exportKey));
        }
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

