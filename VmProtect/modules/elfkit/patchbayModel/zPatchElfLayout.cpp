// 布局打印与 PHT 迁移实现：用于 patchbay 视角下的 ELF 结构可视化与结构调整。
#include "zPatchElf.h"
// 对齐/页大小等工具。
#include "zPatchElfUtils.h"
// 日志接口。
#include "zLog.h"

// 排序工具。
#include <algorithm>
// printf/snprintf。
#include <cstdio>
// 字符串拼接。
#include <string>
// 动态数组。
#include <vector>

namespace {

// 统一布局块模型：顶层块和子块共用该结构。
struct LayoutBlock {
    // 文件内起始偏移。
    uint64_t start = 0;
    // 区块大小（字节）。
    uint64_t size = 0;
    // 打印缩进层级（0 顶层，1 子项）。
    int level = 0;
    // 区块标签文本。
    std::string label;
    // 子区块（例如 PHT/SHT 的逐条元素）。
    std::vector<LayoutBlock> children;
};

// 把 PF_R/PF_W/PF_X 转成可读文本。
std::string formatPhFlags(uint32_t flags) {
    // 读权限位。
    const char r = (flags & PF_R) ? 'R' : '_';
    // 写权限位。
    const char w = (flags & PF_W) ? 'W' : '_';
    // 执行权限位。
    const char x = (flags & PF_X) ? 'X' : '_';
    // 组合成 "(RWX)" 风格字符串。
    return std::string("(") + r + w + x + ")";
}

// Program Header 类型描述文本。
const char* programTypeDesc(uint32_t type) {
    switch (type) {
    case PT_PHDR:
        return "Program Header";
    case PT_INTERP:
        return "Interpreter Path";
    case PT_LOAD:
        return "Loadable Segment";
    case PT_DYNAMIC:
        return "Dynamic Segment";
    case PT_NOTE:
        return "Note";
    case PT_GNU_RELRO:
        return "GNU Read-only After Relocation";
    case PT_GNU_EH_FRAME:
        return "GCC .eh_frame_hdr Segment";
    case PT_GNU_STACK:
        return "GNU Stack (executability)";
    default:
        return "Program Header";
    }
}

// 按统一列宽打印一个布局条目。
void printBlockLine(const LayoutBlock& block) {
    // 空块不打印。
    if (block.size == 0) {
        return;
    }
    // 计算结束偏移（闭区间）。
    const uint64_t end = block.start + block.size - 1;
    // 根据层级生成缩进。
    std::string indent((size_t)block.level * 4, ' ');
    // 输出单行布局信息。
    std::printf("%s0x%08llx-0x%08llx    0x%08llx    %s\n",
                indent.c_str(),
                (unsigned long long)block.start,
                (unsigned long long)end,
                (unsigned long long)block.size,
                block.label.c_str());
}

} // namespace

// 打印当前模型视图下的 ELF 布局信息（按文件偏移升序）。
void PatchElf::printLayout() {
    // 未加载文件时无法打印布局。
    if (!isLoaded()) {
        std::printf("ELF file not loaded\n");
        return;
    }

    // 顶层布局块列表。
    std::vector<LayoutBlock> top_blocks;

    // 1) 顶层加入 ELF Header 区块。
    const uint64_t eh_size = header_model_.raw.e_ehsize;
    if (eh_size > 0) {
        LayoutBlock eh;
        eh.start = 0;
        eh.size = eh_size;
        eh.label = "elf_header";
        top_blocks.push_back(std::move(eh));
    }

    // 2) 构建 Program Header Table 区块及其子条目。
    if (header_model_.raw.e_phoff != 0 && header_model_.raw.e_phnum > 0 && header_model_.raw.e_phentsize > 0) {
        // 顶层 PHT 区块。
        LayoutBlock pht;
        pht.start = header_model_.raw.e_phoff;
        pht.size = (uint64_t)header_model_.raw.e_phnum * header_model_.raw.e_phentsize;
        pht.label = "program_header_table";
        // 逐条构建子项。
        for (size_t programHeaderIndex = 0;
             programHeaderIndex < ph_table_model_.elements.size();
             ++programHeaderIndex) {
            LayoutBlock child;
            // 当前 phdr 在文件中的偏移。
            child.start = header_model_.raw.e_phoff +
                          (uint64_t)programHeaderIndex * header_model_.raw.e_phentsize;
            // 单条大小固定为 e_phentsize。
            child.size = header_model_.raw.e_phentsize;
            // 取当前 phdr。
            const auto& ph = ph_table_model_.elements[programHeaderIndex];
            // 权限文本。
            const std::string flags = formatPhFlags(ph.flags);
            // 文件映射长度。
            const uint64_t file_size = (uint64_t)ph.filesz;
            // 文件映射结束偏移（闭区间；零长时显示 offset）。
            const uint64_t file_end = file_size ? ((uint64_t)ph.offset + file_size - 1) : (uint64_t)ph.offset;
            // 生成子项说明文本。
            char buf[160];
            std::snprintf(buf,
                          sizeof(buf),
                          "program_table_element[0x%02zx] 0x%08llx-0x%08llx %s %s",
                          programHeaderIndex,
                          (unsigned long long)ph.offset,
                          (unsigned long long)file_end,
                          flags.c_str(),
                          programTypeDesc(ph.type));
            child.label = buf;
            // 挂到 PHT 子列表。
            pht.children.push_back(std::move(child));
        }
        // 子项按偏移排序便于阅读。
        std::sort(pht.children.begin(), pht.children.end(),
                  [](const LayoutBlock& a, const LayoutBlock& b) { return a.start < b.start; });
        // 顶层加入 PHT 区块。
        top_blocks.push_back(std::move(pht));
    }

    // 3) 加入每个实际占文件空间的 section 区块（跳过 NOBITS/size=0）。
    for (size_t sectionIndex = 0; sectionIndex < sh_table_model_.elements.size(); ++sectionIndex) {
        // 当前节。
        const auto& sec = *sh_table_model_.elements[sectionIndex];
        // NOBITS 或空节不占文件字节，跳过。
        if (sec.type == SHT_NOBITS || sec.size == 0) {
            continue;
        }
        LayoutBlock sec_block;
        // 节文件偏移。
        sec_block.start = sec.offset;
        // 节文件大小。
        sec_block.size = sec.size;

        // 输出标签前缀（映射到哪些 phdr）。
        std::string prefix;
        // LOAD 映射前缀。
        std::string load_prefix;
        // 非 LOAD 映射前缀。
        std::string other_prefix;

        // 遍历 phdr，找出覆盖当前 section 的段。
        for (size_t ph_idx = 0; ph_idx < ph_table_model_.elements.size(); ++ph_idx) {
            const auto& ph = ph_table_model_.elements[ph_idx];
            // filesz=0 的段没有文件覆盖能力。
            if (ph.filesz == 0) {
                continue;
            }
            // 段文件区间起点。
            const uint64_t ph_begin = ph.offset;
            // 段文件区间终点（开区间）。
            const uint64_t ph_end = ph.offset + (uint64_t)ph.filesz;
            // 节文件区间起点。
            const uint64_t sec_begin = sec.offset;
            // 节文件区间终点（开区间）。
            const uint64_t sec_end = sec.offset + (uint64_t)sec.size;
            // 只有“节完整包含于段文件区间”才算覆盖。
            if (sec_begin >= ph_begin && sec_end <= ph_end) {
                const std::string flags = formatPhFlags(ph.flags);
                char ph_buf[160];
                std::snprintf(ph_buf,
                              sizeof(ph_buf),
                              "program_table_element[0x%02zx] %s %s",
                              ph_idx,
                              flags.c_str(),
                              programTypeDesc(ph.type));
                // LOAD 优先放在 load_prefix。
                if (ph.type == PT_LOAD) {
                    if (!load_prefix.empty()) {
                        load_prefix.append(" | ");
                    }
                    load_prefix.append(ph_buf);
                } else {
                    // 其他段放在 other_prefix。
                    if (!other_prefix.empty()) {
                        other_prefix.append(" | ");
                    }
                    other_prefix.append(ph_buf);
                }
            }
        }

        // 合并 LOAD 前缀。
        if (!load_prefix.empty()) {
            prefix = load_prefix;
        }
        // 合并其他段前缀。
        if (!other_prefix.empty()) {
            if (!prefix.empty()) {
                prefix.append(" | ");
            }
            prefix.append(other_prefix);
        }
        // 末尾补空格分隔正文。
        if (!prefix.empty()) {
            prefix.append("    ");
        }
        // 生成最终 section 标签。
        char buf[200];
        std::snprintf(buf,
                      sizeof(buf),
                      "%ssection[0x%02zx] %s",
                      prefix.c_str(),
                      sectionIndex,
                      sec.resolved_name.empty() ? "<unnamed>" : sec.resolved_name.c_str());
        sec_block.label = buf;
        top_blocks.push_back(std::move(sec_block));
    }

    // 4) 加入 Section Header Table 区块及其子条目。
    if (header_model_.raw.e_shoff != 0 && header_model_.raw.e_shnum > 0 && header_model_.raw.e_shentsize > 0) {
        // 顶层 SHT 区块。
        LayoutBlock sht;
        sht.start = header_model_.raw.e_shoff;
        sht.size = (uint64_t)header_model_.raw.e_shnum * header_model_.raw.e_shentsize;
        sht.label = "section_header_table";
        // 构建每条 shdr 子项。
        for (size_t sectionHeaderIndex = 0;
             sectionHeaderIndex < sh_table_model_.elements.size();
             ++sectionHeaderIndex) {
            LayoutBlock child;
            // 当前 shdr 在文件中的偏移。
            child.start = header_model_.raw.e_shoff +
                          (uint64_t)sectionHeaderIndex * header_model_.raw.e_shentsize;
            // 单条大小固定为 e_shentsize。
            child.size = header_model_.raw.e_shentsize;
            // 当前节对象。
            const auto& sec = *sh_table_model_.elements[sectionHeaderIndex];
            // 0 号索引固定标记 SHN_UNDEF。
            const char* name = (sectionHeaderIndex == 0) ? "SHN_UNDEF" :
                               (sec.resolved_name.empty() ? "<unnamed>" : sec.resolved_name.c_str());
            // 生成子项标签文本。
            char buf[128];
            std::snprintf(buf,
                          sizeof(buf),
                          "section_table_element[0x%02zx] %s",
                          sectionHeaderIndex,
                          name);
            child.label = buf;
            sht.children.push_back(std::move(child));
        }
        // 子项按偏移排序。
        std::sort(sht.children.begin(), sht.children.end(),
                  [](const LayoutBlock& a, const LayoutBlock& b) { return a.start < b.start; });
        // 顶层加入 SHT 区块。
        top_blocks.push_back(std::move(sht));
    }

    // 5) 根据相邻区块间距补齐 [padding] 视图，帮助识别空洞空间。
    std::vector<LayoutBlock> padding_blocks;
    // 拷贝一份用于排序扫描。
    std::vector<LayoutBlock> sorted = top_blocks;
    std::sort(sorted.begin(), sorted.end(),
              [](const LayoutBlock& a, const LayoutBlock& b) { return a.start < b.start; });
    // 扫描相邻块之间的空洞。
    for (size_t blockIndex = 0; blockIndex + 1 < sorted.size(); ++blockIndex) {
        // 当前块结束（开区间终点）。
        const uint64_t currentEnd = sorted[blockIndex].start + sorted[blockIndex].size;
        // 下一块起点。
        const uint64_t nextStart = sorted[blockIndex + 1].start;
        // 存在间隙则创建 padding 块。
        if (nextStart > currentEnd) {
            LayoutBlock pad;
            pad.start = currentEnd;
            pad.size = nextStart - currentEnd;
            pad.label = "[padding]";
            padding_blocks.push_back(std::move(pad));
        }
    }

    // 把 padding 合并进顶层块列表。
    for (auto& pad : padding_blocks) {
        top_blocks.push_back(std::move(pad));
    }

    // 顶层块最终按偏移排序。
    std::sort(top_blocks.begin(), top_blocks.end(),
              [](const LayoutBlock& a, const LayoutBlock& b) { return a.start < b.start; });

    // 先打印顶层，再打印子项。
    for (const auto& block : top_blocks) {
        printBlockLine(block);
        for (const auto& child : block.children) {
            LayoutBlock child_line = child;
            child_line.level = block.level + 1;
            printBlockLine(child_line);
        }
    }
}

// 迁移并扩容 Program Header Table（常用于给新增段预留 phdr 条目）。
bool PatchElf::relocateAndExpandPht(int extraEntries, const char* outputPath) {
    // 扩容项必须为正数。
    if (extraEntries <= 0) {
        LOGE("extraEntries must be positive");
        return false;
    }

    // 先在模型尾部追加 PT_NULL 占位条目。
    for (int extraEntryIndex = 0; extraEntryIndex < extraEntries; ++extraEntryIndex) {
        zProgramTableElement entry;
        entry.type = PT_NULL;
        ph_table_model_.elements.push_back(entry);
    }

    // 依据现有段推断页大小。
    const Elf64_Off PAGE_SIZE = (Elf64_Off)inferRuntimePageSizeFromPhdrs(ph_table_model_.elements);
    // 新 PHT 放到当前文件末尾并按页对齐，避免覆盖现有数据。
    const Elf64_Off new_pht_offset = alignUpOff((Elf64_Off)getMaxFileEnd(), PAGE_SIZE);
    // 刷新 ELF Header 的 e_phoff。
    header_model_.raw.e_phoff = new_pht_offset;
    // 刷新 ELF Header 的 e_phnum。
    header_model_.raw.e_phnum = (Elf64_Half)ph_table_model_.elements.size();

    // 若存在 PT_PHDR，需同步刷新其映射信息。
    int pt_phdr_idx = ph_table_model_.getFirstByType(PT_PHDR);
    if (pt_phdr_idx >= 0) {
        // 取可写引用。
        auto& pt_phdr = ph_table_model_.elements[pt_phdr_idx];
        // 更新文件偏移。
        pt_phdr.offset = new_pht_offset;
        // 计算新偏移在 LOAD 映射中的虚拟地址。
        Elf64_Addr mapped_vaddr = 0;
        for (const auto& ph : ph_table_model_.elements) {
            // 只在有文件内容的 LOAD 里找映射。
            if (ph.type != PT_LOAD || ph.filesz == 0) {
                continue;
            }
            // 目标偏移落在该 LOAD 文件区间内。
            if (new_pht_offset >= ph.offset && new_pht_offset < ph.offset + ph.filesz) {
                mapped_vaddr = (Elf64_Addr)(ph.vaddr + (new_pht_offset - ph.offset));
                break;
            }
        }
        // 写回 vaddr。
        pt_phdr.vaddr = mapped_vaddr;
        // paddr 与 vaddr 保持一致。
        pt_phdr.paddr = pt_phdr.vaddr;
        // 刷新 filesz 为新 phdr 总大小。
        pt_phdr.filesz = (Elf64_Xword)(ph_table_model_.elements.size() * sizeof(Elf64_Phdr));
        // memsz 与 filesz 保持一致。
        pt_phdr.memsz = pt_phdr.filesz;
        // 对齐按页大小。
        pt_phdr.align = PAGE_SIZE;
    }

    // 标记模型有重构变更。
    reconstruction_dirty_ = true;
    // 把模型重建到 file_image_。
    if (!reconstruct()) {
        return false;
    }

    // 做一次全量校验，确保迁移后结构仍合法。
    std::string err;
    if (!validate(&err)) {
        LOGE("relocateAndExpandPht validation failed: %s", err.c_str());
        return false;
    }

    // 若给了输出路径则落盘，否则只更新内存模型。
    return outputPath ? save(outputPath) : true;
}

