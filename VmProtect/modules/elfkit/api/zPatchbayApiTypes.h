/*
 * [VMP_FLOW_NOTE] 文件级流程注释。
 * - 文件：api/zPatchbayApiTypes.h
 * - 主要职责：Patchbay API 类型定义：统一对外参数、结果与错误语义，减少跨模块耦合。
 * - 输入：上层调用参数、文件路径与功能选择配置。
 * - 输出：稳定的接口声明、类型约束和调用契约。
 * - 关键约束：
 *   1) 严格保持 ELF 布局与索引一致性，避免地址/偏移漂移。
 *   2) 失败路径必须可定位（返回值/错误信息/日志三者保持一致）。
 *   3) 本文件改动优先保证与上游调用契约兼容，不隐式改变既有语义。
 */
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
};

// 结束命名空间。
}  // namespace vmp::elfkit
