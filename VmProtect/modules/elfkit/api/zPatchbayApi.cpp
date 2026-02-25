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

// 在给定符号表中查找符号并填充输出结构。
bool findSymbolInTable(const zSymbolSection* symtab,
                       const zStrTabSection* strtab,
                       const char* symbol_name,
                       PatchSymbolInfo* out_info) {
    // 参数必须全部有效。
    if (!symtab || !strtab || !symbol_name || !out_info) {
        return false;
    }

    // 线性扫描符号表。
    for (size_t idx = 0; idx < symtab->symbols.size(); ++idx) {
        const Elf64_Sym& sym = symtab->symbols[idx];
        // 无名符号跳过。
        if (sym.st_name == 0) {
            continue;
        }
        // 从 strtab 取符号名。
        const char* name = strtab->getStringAt(sym.st_name);
        if (!name) {
            continue;
        }
        // 名称匹配则填充输出。
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

// 查询并返回 .dynsym/.dynstr 两个关键节。
bool queryDynsymDynstr(const PatchElf& elf,
                       const zSymbolSection** out_dynsym,
                       const zStrTabSection** out_dynstr,
                       std::string* error) {
    // 输出指针不能为空。
    if (!out_dynsym || !out_dynstr) {
        if (error) {
            *error = "invalid dynsym/dynstr output";
        }
        return false;
    }
    // 先清空输出。
    *out_dynsym = nullptr;
    *out_dynstr = nullptr;

    // 获取节表模型。
    const auto& sht = elf.sectionHeaderModel();

    // 查找 .dynsym 索引。
    const int dynsym_idx = sht.findByName(".dynsym");
    if (dynsym_idx < 0) {
        if (error) {
            *error = "missing .dynsym";
        }
        return false;
    }
    // 校验 .dynsym 类型。
    const auto* dynsym = dynamic_cast<const zSymbolSection*>(sht.get((size_t)dynsym_idx));
    if (!dynsym) {
        if (error) {
            *error = ".dynsym type mismatch";
        }
        return false;
    }

    // 查找 .dynstr 索引。
    const int dynstr_idx = sht.findByName(".dynstr");
    if (dynstr_idx < 0) {
        if (error) {
            *error = "missing .dynstr";
        }
        return false;
    }
    // 校验 .dynstr 类型。
    const auto* dynstr = dynamic_cast<const zStrTabSection*>(sht.get((size_t)dynstr_idx));
    if (!dynstr) {
        if (error) {
            *error = ".dynstr type mismatch";
        }
        return false;
    }

    // 回填输出。
    *out_dynsym = dynsym;
    *out_dynstr = dynstr;
    return true;
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
PatchElfImage::PatchElfImage(const char* elf_path)
    : impl_(new Impl(elf_path)) {}

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
bool PatchElfImage::loaded() const {
    return impl_ && impl_->elf.isLoaded();
}

// 执行结构校验。
bool PatchElfImage::validate(std::string* error) const {
    if (!loaded()) {
        if (error) {
            *error = "elf is not loaded";
        }
        return false;
    }
    return impl_->elf.validate(error);
}

// 解析符号（优先 .symtab，再回退 .dynsym）。
bool PatchElfImage::resolveSymbol(const char* symbol_name, PatchSymbolInfo* out_info) const {
    // 参数校验。
    if (!loaded() || !symbol_name || !out_info) {
        return false;
    }
    // 先清空输出结果。
    *out_info = PatchSymbolInfo{};

    // 取节表模型。
    const auto& sht = impl_->elf.sectionHeaderModel();

    // 优先尝试 .symtab/.strtab。
    const int symtab_idx = sht.findByName(".symtab");
    const int strtab_idx = sht.findByName(".strtab");
    if (symtab_idx >= 0 && strtab_idx >= 0) {
        const auto* symtab = dynamic_cast<const zSymbolSection*>(sht.get((size_t)symtab_idx));
        const auto* strtab = dynamic_cast<const zStrTabSection*>(sht.get((size_t)strtab_idx));
        if (findSymbolInTable(symtab, strtab, symbol_name, out_info)) {
            return true;
        }
    }

    // 回退到 .dynsym/.dynstr。
    const int dynsym_idx = sht.findByName(".dynsym");
    const int dynstr_idx = sht.findByName(".dynstr");
    if (dynsym_idx >= 0 && dynstr_idx >= 0) {
        const auto* dynsym = dynamic_cast<const zSymbolSection*>(sht.get((size_t)dynsym_idx));
        const auto* dynstr = dynamic_cast<const zStrTabSection*>(sht.get((size_t)dynstr_idx));
        if (findSymbolInTable(dynsym, dynstr, symbol_name, out_info)) {
            return true;
        }
    }
    return false;
}

// 收集已定义动态导出名。
bool PatchElfImage::collectDefinedDynamicExports(std::vector<std::string>* out_exports,
                                                 std::string* error) const {
    // 输出容器不能为空。
    if (!out_exports) {
        if (error) {
            *error = "invalid output list";
        }
        return false;
    }
    // 清空旧结果。
    out_exports->clear();

    // 需要已加载状态。
    if (!loaded()) {
        if (error) {
            *error = "elf is not loaded";
        }
        return false;
    }

    // 获取 dynsym/dynstr。
    const zSymbolSection* dynsym = nullptr;
    const zStrTabSection* dynstr = nullptr;
    if (!queryDynsymDynstr(impl_->elf, &dynsym, &dynstr, error)) {
        return false;
    }

    // 去重集合。
    std::unordered_set<std::string> seen;
    seen.reserve(dynsym->symbols.size());

    // 从索引 1 开始（跳过 STN_UNDEF）。
    for (size_t i = 1; i < dynsym->symbols.size(); ++i) {
        const Elf64_Sym& sym = dynsym->symbols[i];
        // 空名或未定义符号跳过。
        if (sym.st_name == 0 || sym.st_shndx == SHN_UNDEF) {
            continue;
        }
        // 仅保留 GLOBAL/WEAK。
        const unsigned bind = ELF64_ST_BIND(sym.st_info);
        const unsigned type = ELF64_ST_TYPE(sym.st_info);
        if (bind != STB_GLOBAL && bind != STB_WEAK) {
            continue;
        }
        // 过滤 SECTION/FILE 类型。
        if (type == STT_SECTION || type == STT_FILE) {
            continue;
        }
        // 取符号名。
        const char* name = dynstr->getStringAt(sym.st_name);
        if (!name || name[0] == '\0') {
            continue;
        }
        // 重名跳过。
        if (!seen.insert(name).second) {
            continue;
        }
        out_exports->emplace_back(name);
    }
    return true;
}

// 收集已定义动态导出（含 value）。
bool PatchElfImage::collectDefinedDynamicExportInfos(std::vector<PatchDynamicExportInfo>* out_exports,
                                                      std::string* error) const {
    // 输出容器不能为空。
    if (!out_exports) {
        if (error) {
            *error = "invalid output list";
        }
        return false;
    }
    // 清空旧结果。
    out_exports->clear();

    // 需要已加载状态。
    if (!loaded()) {
        if (error) {
            *error = "elf is not loaded";
        }
        return false;
    }

    // 获取 dynsym/dynstr。
    const zSymbolSection* dynsym = nullptr;
    const zStrTabSection* dynstr = nullptr;
    if (!queryDynsymDynstr(impl_->elf, &dynsym, &dynstr, error)) {
        return false;
    }

    // 去重集合。
    std::unordered_set<std::string> seen;
    seen.reserve(dynsym->symbols.size());

    // 从索引 1 开始（跳过 STN_UNDEF）。
    for (size_t i = 1; i < dynsym->symbols.size(); ++i) {
        const Elf64_Sym& sym = dynsym->symbols[i];
        // 空名或未定义符号跳过。
        if (sym.st_name == 0 || sym.st_shndx == SHN_UNDEF) {
            continue;
        }
        // 仅保留 GLOBAL/WEAK。
        const unsigned bind = ELF64_ST_BIND(sym.st_info);
        const unsigned type = ELF64_ST_TYPE(sym.st_info);
        if (bind != STB_GLOBAL && bind != STB_WEAK) {
            continue;
        }
        // 过滤 SECTION/FILE 类型。
        if (type == STT_SECTION || type == STT_FILE) {
            continue;
        }
        // 取符号名。
        const char* name = dynstr->getStringAt(sym.st_name);
        if (!name || name[0] == '\0') {
            continue;
        }
        // 重名跳过。
        if (!seen.insert(name).second) {
            continue;
        }
        // 构建导出信息对象。
        PatchDynamicExportInfo info{};
        info.name = name;
        info.value = static_cast<uint64_t>(sym.st_value);
        out_exports->push_back(std::move(info));
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
    if (!loaded()) {
        if (error) {
            *error = "elf is not loaded";
        }
        return false;
    }

    // 获取节表模型。
    const auto& sht = impl_->elf.sectionHeaderModel();

    // 查找关键节索引。
    out->dynsym_index = sht.findByName(".dynsym");
    out->dynstr_index = sht.findByName(".dynstr");
    out->versym_index = sht.findByName(".gnu.version");
    out->gnu_hash_index = sht.findByName(".gnu.hash");
    out->hash_index = sht.findByName(".hash");
    const int dynamic_index = sht.findByName(".dynamic");
    out->patchbay_index = sht.findByName(".vmp_patchbay");

    // 关键必需节缺失时失败。
    if (out->dynsym_index < 0 || out->dynstr_index < 0 || out->versym_index < 0 ||
        out->gnu_hash_index < 0 || dynamic_index < 0) {
        if (error) {
            *error = "required sections missing (.dynsym/.dynstr/.gnu.version/.gnu.hash/.dynamic)";
        }
        return false;
    }

    // 转换并保存节指针。
    out->dynsym = dynamic_cast<const zSymbolSection*>(sht.get((size_t)out->dynsym_index));
    out->dynstr = dynamic_cast<const zStrTabSection*>(sht.get((size_t)out->dynstr_index));
    out->versym = sht.get((size_t)out->versym_index);
    out->gnu_hash = sht.get((size_t)out->gnu_hash_index);
    out->dynamic = dynamic_cast<const zDynamicSection*>(sht.get((size_t)dynamic_index));

    // .hash 是可选节。
    if (out->hash_index >= 0) {
        out->hash = sht.get((size_t)out->hash_index);
    }
    // .vmp_patchbay 是可选节。
    if (out->patchbay_index >= 0) {
        out->patchbay = sht.get((size_t)out->patchbay_index);
    }

    // 类型断言失败时返回错误。
    if (!out->dynsym || !out->dynstr || !out->versym || !out->gnu_hash || !out->dynamic) {
        if (error) {
            *error = "required section type mismatch";
        }
        return false;
    }
    return true;
}

// 结束命名空间。
}  // namespace vmp::elfkit

