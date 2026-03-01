/*
 * [VMP_FLOW_NOTE] 文件级流程注释。
 * - 文件：api/zPatchbayApi.cpp
 * - 主要职责：Patchbay 外部接口层：封装补丁构建/应用能力，供 pipeline 与工具侧统一调用。
 * - 输入：上层调用参数、文件路径与功能选择配置。
 * - 输出：面向调用方的执行结果、错误状态及可追踪日志。
 * - 关键约束：
 *   1) 严格保持 ELF 布局与索引一致性，避免地址/偏移漂移。
 *   2) 失败路径必须可定位（返回值/错误信息/日志三者保持一致）。
 *   3) 本文件改动优先保证与上游调用契约兼容，不隐式改变既有语义。
 */
#include "zPatchbayApi.h"

// 引入 PatchElf 核心模型。
#include "zPatchElf.h"

// 引入 strcmp。
#include <cstring>
// 引入智能指针工具（与现有代码风格保持一致）。
#include <memory>
// 引入去重集合。
#include <unordered_set>
// 引入 move 工具。
#include <utility>

// 进入命名空间。
namespace vmp::elfkit {

// 匿名命名空间：内部辅助函数。
namespace {

// 在给定符号表中获取目标符号并填充输出结构。
bool getSymbolInTable(const zSymbolSection* symbolTable,
                      const zStrTabSection* stringTable,
                      const char* symbolName,
                      PatchSymbolInfo* outSymbolInfo) {
    // 参数必须全部有效。
    if (!symbolTable || !stringTable || !symbolName || !outSymbolInfo) {
        return false;
    }

    // 线性扫描符号表。
    for (size_t symbolIndex = 0; symbolIndex < symbolTable->symbols.size(); ++symbolIndex) {
        const Elf64_Sym& symbol = symbolTable->symbols[symbolIndex];
        // 无名符号跳过。
        if (symbol.st_name == 0) {
            continue;
        }
        // 从 strtab 取符号名。
        const char* symbolText = stringTable->getStringAt(symbol.st_name);
        if (!symbolText) {
            continue;
        }
        // 名称匹配则填充输出。
        if (std::strcmp(symbolText, symbolName) == 0) {
            outSymbolInfo->value = symbol.st_value;
            outSymbolInfo->size = symbol.st_size;
            outSymbolInfo->shndx = symbol.st_shndx;
            outSymbolInfo->type = ELF64_ST_TYPE(symbol.st_info);
            outSymbolInfo->found = true;
            return true;
        }
    }
    return false;
}

// 查询并返回 .dynsym/.dynstr 两个关键节。
bool queryDynsymDynstr(const PatchElf& elf,
                       const zSymbolSection** outDynsym,
                       const zStrTabSection** outDynstr,
                       std::string* error) {
    // 输出指针不能为空。
    if (!outDynsym || !outDynstr) {
        if (error) {
            *error = "invalid dynsym/dynstr output";
        }
        return false;
    }
    // 先清空输出。
    *outDynsym = nullptr;
    *outDynstr = nullptr;

    // 获取节表模型。
    const auto& sectionTable = elf.getSectionHeaderModel();

    // 查找 .dynsym 索引。
    const int dynsymIndex = sectionTable.getByName(".dynsym");
    if (dynsymIndex < 0) {
        if (error) {
            *error = "missing .dynsym";
        }
        return false;
    }
    // 校验 .dynsym 类型。
    const auto* dynsymSection =
            dynamic_cast<const zSymbolSection*>(sectionTable.get((size_t)dynsymIndex));
    if (!dynsymSection) {
        if (error) {
            *error = ".dynsym type mismatch";
        }
        return false;
    }

    // 查找 .dynstr 索引。
    const int dynstrIndex = sectionTable.getByName(".dynstr");
    if (dynstrIndex < 0) {
        if (error) {
            *error = "missing .dynstr";
        }
        return false;
    }
    // 校验 .dynstr 类型。
    const auto* dynstrSection =
            dynamic_cast<const zStrTabSection*>(sectionTable.get((size_t)dynstrIndex));
    if (!dynstrSection) {
        if (error) {
            *error = ".dynstr type mismatch";
        }
        return false;
    }

    // 回填输出。
    *outDynsym = dynsymSection;
    *outDynstr = dynstrSection;
    return true;
}

// 由内部节对象构造稳定节视图快照。
PatchSectionView buildSectionView(const zSectionTableElement* section, int index) {
    // 默认空视图（index=-1）。
    PatchSectionView view;
    view.index = index;
    // 输入节为空时返回默认值。
    if (section == nullptr) {
        return view;
    }
    // 回填 offset/size/addr 关键元数据。
    view.offset = static_cast<uint64_t>(section->offset);
    view.size = static_cast<uint64_t>(section->size);
    view.addr = static_cast<uint64_t>(section->addr);
    return view;
}

// 结束匿名命名空间。
}  // namespace

// pImpl 定义。
class PatchElfImage::Impl {
public:
    // 构造并加载 PatchElf。
    explicit Impl(const char* path) : elf(path) {}

    // 底层 PatchElf 对象。
    PatchElf elf;
};

// 构造函数。
PatchElfImage::PatchElfImage(const char* elfPath)
    : impl_(new Impl(elfPath)) {}

// 析构函数。
PatchElfImage::~PatchElfImage() {
    delete impl_;
    impl_ = nullptr;
}

// 移动构造。
PatchElfImage::PatchElfImage(PatchElfImage&& other) noexcept
    : impl_(other.impl_) {
    other.impl_ = nullptr;
}

// 移动赋值。
PatchElfImage& PatchElfImage::operator=(PatchElfImage&& other) noexcept {
    if (this == &other) {
        return *this;
    }
    delete impl_;
    impl_ = other.impl_;
    other.impl_ = nullptr;
    return *this;
}

// 是否已加载。
bool PatchElfImage::isLoaded() const {
    return impl_ && impl_->elf.isLoaded();
}

// 执行结构校验。
bool PatchElfImage::validate(std::string* error) const {
    if (!isLoaded()) {
        if (error) {
            *error = "elf is not loaded";
        }
        return false;
    }
    return impl_->elf.validate(error);
}

// 解析符号（优先 .symtab，再回退 .dynsym）。
bool PatchElfImage::resolveSymbol(const char* symbolName, PatchSymbolInfo* outSymbolInfo) const {
    // 参数校验。
    if (!isLoaded() || !symbolName || !outSymbolInfo) {
        return false;
    }
    // 先清空输出结果。
    *outSymbolInfo = PatchSymbolInfo{};

    // 取节表模型。
    const auto& sectionTable = impl_->elf.getSectionHeaderModel();

    // 优先尝试 .symtab/.strtab。
    const int symtabIndex = sectionTable.getByName(".symtab");
    const int strtabIndex = sectionTable.getByName(".strtab");
    if (symtabIndex >= 0 && strtabIndex >= 0) {
        const auto* symtabSection =
                dynamic_cast<const zSymbolSection*>(sectionTable.get((size_t)symtabIndex));
        const auto* strtabSection =
                dynamic_cast<const zStrTabSection*>(sectionTable.get((size_t)strtabIndex));
        if (getSymbolInTable(symtabSection, strtabSection, symbolName, outSymbolInfo)) {
            return true;
        }
    }

    // 回退到 .dynsym/.dynstr。
    const int dynsymIndex = sectionTable.getByName(".dynsym");
    const int dynstrIndex = sectionTable.getByName(".dynstr");
    if (dynsymIndex >= 0 && dynstrIndex >= 0) {
        const auto* dynsymSection =
                dynamic_cast<const zSymbolSection*>(sectionTable.get((size_t)dynsymIndex));
        const auto* dynstrSection =
                dynamic_cast<const zStrTabSection*>(sectionTable.get((size_t)dynstrIndex));
        if (getSymbolInTable(dynsymSection, dynstrSection, symbolName, outSymbolInfo)) {
            return true;
        }
    }
    return false;
}

// 收集已定义动态导出（含 value）。
bool PatchElfImage::collectDefinedDynamicExportInfos(std::vector<PatchDynamicExportInfo>* outExports,
                                                      std::string* error) const {
    // 输出容器不能为空。
    if (!outExports) {
        if (error) {
            *error = "invalid output list";
        }
        return false;
    }
    // 清空旧结果。
    outExports->clear();

    // 需要已加载状态。
    if (!isLoaded()) {
        if (error) {
            *error = "elf is not loaded";
        }
        return false;
    }

    // 获取 dynsym/dynstr。
    const zSymbolSection* dynsymSection = nullptr;
    const zStrTabSection* dynstrSection = nullptr;
    if (!queryDynsymDynstr(impl_->elf, &dynsymSection, &dynstrSection, error)) {
        return false;
    }

    // 去重集合。
    std::unordered_set<std::string> seenExportNames;
    seenExportNames.reserve(dynsymSection->symbols.size());

    // 从索引 1 开始（跳过 STN_UNDEF）。
    for (size_t symbolIndex = 1; symbolIndex < dynsymSection->symbols.size(); ++symbolIndex) {
        const Elf64_Sym& symbol = dynsymSection->symbols[symbolIndex];
        // 空名或未定义符号跳过。
        if (symbol.st_name == 0 || symbol.st_shndx == SHN_UNDEF) {
            continue;
        }
        // 仅保留 GLOBAL/WEAK。
        const unsigned bind = ELF64_ST_BIND(symbol.st_info);
        const unsigned type = ELF64_ST_TYPE(symbol.st_info);
        if (bind != STB_GLOBAL && bind != STB_WEAK) {
            continue;
        }
        // 过滤 SECTION/FILE 类型。
        if (type == STT_SECTION || type == STT_FILE) {
            continue;
        }
        // 取符号名。
        const char* symbolName = dynstrSection->getStringAt(symbol.st_name);
        if (!symbolName || symbolName[0] == '\0') {
            continue;
        }
        // 重名跳过。
        if (!seenExportNames.insert(symbolName).second) {
            continue;
        }
        // 构建导出信息对象。
        PatchDynamicExportInfo exportInfo{};
        exportInfo.name = symbolName;
        exportInfo.value = static_cast<uint64_t>(symbol.st_value);
        outExports->push_back(std::move(exportInfo));
    }
    return true;
}

// 查询 patchbay 流程依赖的关键节。
bool PatchElfImage::queryRequiredSections(PatchRequiredSections* out, std::string* error) const {
    // 输出指针不能为空。
    if (!out) {
        if (error) {
            *error = "invalid required-sections output";
        }
        return false;
    }

    // 先清空输出结构。
    *out = PatchRequiredSections{};

    // 需要已加载状态。
    if (!isLoaded()) {
        if (error) {
            *error = "elf is not loaded";
        }
        return false;
    }

    // 获取节表模型。
    const auto& sht = impl_->elf.getSectionHeaderModel();

    // 查找关键节索引。
    const int dynsymIndex = sht.getByName(".dynsym");
    const int dynstrIndex = sht.getByName(".dynstr");
    const int versymIndex = sht.getByName(".gnu.version");
    const int gnuHashIndex = sht.getByName(".gnu.hash");
    const int hashIndex = sht.getByName(".hash");
    const int dynamicIndex = sht.getByName(".dynamic");

    // 关键必需节缺失时失败。
    if (dynsymIndex < 0 || dynstrIndex < 0 || versymIndex < 0 ||
        gnuHashIndex < 0 || dynamicIndex < 0) {
        if (error) {
            *error = "required sections missing (.dynsym/.dynstr/.gnu.version/.gnu.hash/.dynamic)";
        }
        return false;
    }

    // 读取关键节对象并做类型断言。
    const auto* dynsymSection = dynamic_cast<const zSymbolSection*>(sht.get((size_t)dynsymIndex));
    const auto* dynstrSection = dynamic_cast<const zStrTabSection*>(sht.get((size_t)dynstrIndex));
    const auto* versymSection = sht.get((size_t)versymIndex);
    const auto* gnuHashSection = sht.get((size_t)gnuHashIndex);
    const auto* dynamicSection = dynamic_cast<const zDynamicSection*>(sht.get((size_t)dynamicIndex));
    if (!dynsymSection || !dynstrSection || !versymSection || !gnuHashSection || !dynamicSection) {
        if (error) {
            *error = "required section type mismatch";
        }
        return false;
    }

    // 回填 dynsym 快照。
    out->dynsym.index = dynsymIndex;
    out->dynsym.symbols = dynsymSection->symbols;

    // 回填 dynstr 快照。
    out->dynstr.index = dynstrIndex;
    out->dynstr.bytes = dynstrSection->payload;

    // 回填 versym 快照与 payload。
    out->versym = buildSectionView(versymSection, versymIndex);
    out->versymBytes = versymSection->payload;

    // 回填 gnu hash 节视图。
    out->gnuHash = buildSectionView(gnuHashSection, gnuHashIndex);

    // 回填 dynamic 快照。
    out->dynamic.index = dynamicIndex;
    out->dynamic.offset = static_cast<uint64_t>(dynamicSection->offset);
    out->dynamic.entries = dynamicSection->entries;

    // 回填可选 .hash 节视图。
    if (hashIndex >= 0) {
        out->hasHash = true;
        out->hash = buildSectionView(sht.get((size_t)hashIndex), hashIndex);
    }
    return true;
}

// 结束命名空间。
}  // namespace vmp::elfkit

