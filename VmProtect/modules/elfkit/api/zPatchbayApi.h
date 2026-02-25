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

// 通用节视图快照（只保留 patchbay 需要的最小元数据）。
struct PatchSectionView {
    // 节索引（找不到时为 -1）。
    int index = -1;
    // 节文件偏移。
    uint64_t offset = 0;
    // 节字节长度。
    uint64_t size = 0;
    // 节虚拟地址。
    uint64_t addr = 0;
};

// .dynsym 节快照。
struct PatchDynsymView {
    // .dynsym 节索引。
    int index = -1;
    // .dynsym 符号表快照。
    std::vector<Elf64_Sym> symbols;
};

// .dynstr 节快照。
struct PatchDynstrView {
    // .dynstr 节索引。
    int index = -1;
    // .dynstr 原始字节快照。
    std::vector<uint8_t> bytes;
};

// .dynamic 节快照。
struct PatchDynamicView {
    // .dynamic 节索引。
    int index = -1;
    // .dynamic 文件偏移。
    uint64_t offset = 0;
    // .dynamic 条目快照。
    std::vector<Elf64_Dyn> entries;
};

// patchbay 流程依赖的关键节集合。
// 注意：该结构仅暴露稳定数据快照，不暴露内部节对象类型。
struct PatchRequiredSections {
    // .dynsym 快照。
    PatchDynsymView dynsym;
    // .dynstr 快照。
    PatchDynstrView dynstr;
    // .gnu.version 节基础信息快照。
    PatchSectionView versym;
    // .gnu.version 原始字节快照。
    std::vector<uint8_t> versymBytes;
    // .gnu.hash 节基础信息快照。
    PatchSectionView gnuHash;
    // .hash 节基础信息快照（可选）。
    PatchSectionView hash;
    // 是否存在 .hash。
    bool hasHash = false;
    // .dynamic 快照。
    PatchDynamicView dynamic;
    // .vmp_patchbay 节基础信息快照（可选）。
    PatchSectionView patchbay;
    // 是否存在 .vmp_patchbay。
    bool hasPatchbay = false;
};

// PatchElfImage：面向 patchbay 场景的 ELF 只读访问器。
class PatchElfImage {
public:
    // 按路径加载 ELF。
    explicit PatchElfImage(const char* elfPath);
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
    bool isLoaded() const;
    // 执行结构校验。
    bool validate(std::string* error = nullptr) const;

    // 解析指定符号（优先 .symtab，回退 .dynsym）。
    bool resolveSymbol(const char* symbolName, PatchSymbolInfo* outInfo) const;

    // 收集已定义动态导出（含 value）。
    bool collectDefinedDynamicExportInfos(std::vector<PatchDynamicExportInfo>* outExports,
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
