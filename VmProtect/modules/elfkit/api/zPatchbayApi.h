// 防止头文件重复包含。
#pragma once

// 引入 ELF ABI 类型定义。
#include "zElfAbi.h"

// 引入基础整型定义。
#include <cstdint>
// 引入字符串类型。
#include <string>
// 引入动态数组容器。
#include <vector>

// 前置声明：动态段节对象。
class zDynamicSection;
// 前置声明：通用节对象。
class zSectionTableElement;
// 前置声明：字符串节对象。
class zStrTabSection;
// 前置声明：符号节对象。
class zSymbolSection;

// 进入命名空间。
namespace vmp::elfkit {

// 符号解析结果。
struct PatchSymbolInfo {
    // 符号地址。
    Elf64_Addr value = 0;
    // 符号大小。
    Elf64_Xword size = 0;
    // 所在节索引。
    Elf64_Half shndx = SHN_UNDEF;
    // 符号类型（STT_*）。
    unsigned type = STT_NOTYPE;
    // 是否找到。
    bool found = false;
};

// 动态导出符号信息（用于 patchbay 生成 alias）。
struct PatchDynamicExportInfo {
    // 导出符号名。
    std::string name;
    // 导出符号值。
    uint64_t value = 0;
};

// patchbay 流程依赖的关键节集合。
// 注意：这些指针生命周期绑定到 PatchElfImage 实例。
struct PatchRequiredSections {
    // .dynsym 节。
    const zSymbolSection* dynsym = nullptr;
    // .dynstr 节。
    const zStrTabSection* dynstr = nullptr;
    // .gnu.version 节。
    const zSectionTableElement* versym = nullptr;
    // .gnu.hash 节。
    const zSectionTableElement* gnu_hash = nullptr;
    // .hash 节（可选）。
    const zSectionTableElement* hash = nullptr;
    // .dynamic 节。
    const zDynamicSection* dynamic = nullptr;
    // .vmp_patchbay 节（可选）。
    const zSectionTableElement* patchbay = nullptr;

    // .dynsym 索引。
    int dynsym_index = -1;
    // .dynstr 索引。
    int dynstr_index = -1;
    // .gnu.version 索引。
    int versym_index = -1;
    // .gnu.hash 索引。
    int gnu_hash_index = -1;
    // .hash 索引。
    int hash_index = -1;
    // .vmp_patchbay 索引。
    int patchbay_index = -1;
};

// PatchElfImage：面向 patchbay 场景的 ELF 只读访问器。
class PatchElfImage {
public:
    // 按路径加载 ELF。
    explicit PatchElfImage(const char* elf_path);
    // 析构释放资源。
    ~PatchElfImage();

    // 禁止拷贝。
    PatchElfImage(const PatchElfImage&) = delete;
    // 禁止拷贝赋值。
    PatchElfImage& operator=(const PatchElfImage&) = delete;
    // 支持移动构造。
    PatchElfImage(PatchElfImage&& other) noexcept;
    // 支持移动赋值。
    PatchElfImage& operator=(PatchElfImage&& other) noexcept;

    // ELF 是否加载成功。
    bool loaded() const;
    // 执行结构校验。
    bool validate(std::string* error = nullptr) const;

    // 解析指定符号（优先 .symtab，回退 .dynsym）。
    bool resolveSymbol(const char* symbol_name, PatchSymbolInfo* out_info) const;

    // 收集已定义的动态导出名列表。
    bool collectDefinedDynamicExports(std::vector<std::string>* out_exports,
                                      std::string* error) const;
    // 收集已定义动态导出（含 value）。
    bool collectDefinedDynamicExportInfos(std::vector<PatchDynamicExportInfo>* out_exports,
                                          std::string* error) const;

    // 查询 patchbay 所需关键节集合。
    bool queryRequiredSections(PatchRequiredSections* out, std::string* error) const;

private:
    // pImpl 前置声明。
    class Impl;
    // pImpl 指针。
    Impl* impl_ = nullptr;
};

// 结束命名空间。
}  // namespace vmp::elfkit

