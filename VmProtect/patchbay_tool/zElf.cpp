#include "zElf.h"
#include "zElfUtils.h"
#include "zLog.h"

#include <algorithm>
#include <cstdio>
#include <limits>
#include <string>
#include <vector>

/**
 * @file zElf.cpp
 * @brief zElf 主类的高层调度实现。
 *
 * 本文件侧重"对外 API"与"模块编排"：
 * - save / validate / print_layout 等常用入口；
 * - relocate_and_expand_pht 的高层流程；
 * - 注入入口与模型访问器。
 *
 * 具体重构、加载、注入细节分别在对应实现文件中完成。
 */

// 对外重构入口：委托到核心实现。
bool zElf::Reconstruction() {
    return reconstructionImpl();
}

// 保存 ELF：若模型有脏数据则先重构，再写出 file_image_。
bool zElf::save(const char* output_path) {
    if (!output_path) {
        return false;
    }
    if (reconstruction_dirty_ && !Reconstruction()) {
        return false;
    }

    FILE* fp = std::fopen(output_path, "wb");
    if (!fp) {
        LOGE("Failed to open output file: %s", output_path);
        return false;
    }
    size_t written = std::fwrite(file_image_.data(), 1, file_image_.size(), fp);
    std::fclose(fp);
    if (written != file_image_.size()) {
        LOGE("Failed to write complete file, written=%zu expected=%zu", written, file_image_.size());
        return false;
    }
    return true;
}

bool zElf::isLoaded() const {
    // 既要有字节镜像，也要通过 ELF64+AArch64 头校验才算“已加载”。
    return !file_image_.empty() && header_model_.isElf64AArch64();
}

size_t zElf::fileImageSize() const {
    // 返回当前内存镜像大小（可能尚未 save 到磁盘）。
    return file_image_.size();
}

const uint8_t* zElf::fileImageData() const {
    // 空镜像返回 nullptr，避免调用方误解为可访问缓冲。
    return file_image_.empty() ? nullptr : file_image_.data();
}

// 统一校验入口。
bool zElf::validate(std::string* error) const {
    return zElfValidator::validateAll(*this, error);
}

namespace {
struct LayoutBlock {
    // 文件内起始偏移。
    uint64_t start = 0;
    // 区块大小。
    uint64_t size = 0;
    // 打印缩进层级。
    int level = 0;
    // 区块文本标签。
    std::string label;
    // 子区块（例如 PHT/SHT 的逐条元素）。
    std::vector<LayoutBlock> children;
};

// 把 PF_R/PF_W/PF_X 转成可读文本。
static std::string format_ph_flags(uint32_t flags) {
    const char r = (flags & PF_R) ? 'R' : '_';
    const char w = (flags & PF_W) ? 'W' : '_';
    const char x = (flags & PF_X) ? 'X' : '_';
    return std::string("(") + r + w + x + ")";
}

static const char* program_type_desc(uint32_t type) {
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
static void print_block_line(const LayoutBlock& block) {
    if (block.size == 0) {
        return;
    }
    const uint64_t end = block.start + block.size - 1;
    std::string indent((size_t)block.level * 4, ' ');
    std::printf("%s0x%08llx-0x%08llx    0x%08llx    %s\n",
                indent.c_str(),
                (unsigned long long)block.start,
                (unsigned long long)end,
                (unsigned long long)block.size,
                block.label.c_str());
}
} // namespace

// 打印当前模型视图下的 ELF 布局信息（按文件偏移降序）。
void zElf::print_layout() {
    if (!isLoaded()) {
        std::printf("ELF file not loaded\n");
        return;
    }

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
        // PHT 主块 + 每个 phdr 子块。
        LayoutBlock pht;
        pht.start = header_model_.raw.e_phoff;
        pht.size = (uint64_t)header_model_.raw.e_phnum * header_model_.raw.e_phentsize;
        pht.label = "program_header_table";
        for (size_t idx = 0; idx < ph_table_model_.elements.size(); ++idx) {
            LayoutBlock child;
            // 第 idx 条 phdr 在 PHT 内的文件偏移位置。
            child.start = header_model_.raw.e_phoff + (uint64_t)idx * header_model_.raw.e_phentsize;
            child.size = header_model_.raw.e_phentsize;
            const auto& ph = ph_table_model_.elements[idx];
            const std::string flags = format_ph_flags(ph.flags);
            const uint64_t file_size = (uint64_t)ph.filesz;
            const uint64_t file_end = file_size ? ((uint64_t)ph.offset + file_size - 1) : (uint64_t)ph.offset;
            char buf[160];
            std::snprintf(buf,
                          sizeof(buf),
                          "program_table_element[0x%02zx] 0x%08llx-0x%08llx %s %s",
                          idx,
                          (unsigned long long)ph.offset,
                          (unsigned long long)file_end,
                          flags.c_str(),
                          program_type_desc(ph.type));
            child.label = buf;
            pht.children.push_back(std::move(child));
        }
        // 子条目按文件偏移升序打印，便于肉眼扫描布局。
        std::sort(pht.children.begin(), pht.children.end(),
                  [](const LayoutBlock& a, const LayoutBlock& b) { return a.start < b.start; });
        top_blocks.push_back(std::move(pht));
    }

    // 3) 加入每个实际占文件空间的 section 区块（跳过 NOBITS/size=0）。
    for (size_t idx = 0; idx < sh_table_model_.elements.size(); ++idx) {
        const auto& sec = *sh_table_model_.elements[idx];
        if (sec.type == SHT_NOBITS || sec.size == 0) {
            continue;
        }
        LayoutBlock sec_block;
        sec_block.start = sec.offset;
        sec_block.size = sec.size;
        std::string prefix;
        std::string load_prefix;
        std::string other_prefix;
        // 给每个 section 生成“所在 segment”前缀，便于快速观察映射关系。
        for (size_t ph_idx = 0; ph_idx < ph_table_model_.elements.size(); ++ph_idx) {
            const auto& ph = ph_table_model_.elements[ph_idx];
            if (ph.filesz == 0) {
                continue;
            }
            const uint64_t ph_begin = ph.offset;
            const uint64_t ph_end = ph.offset + (uint64_t)ph.filesz;
            const uint64_t sec_begin = sec.offset;
            const uint64_t sec_end = sec.offset + (uint64_t)sec.size;
            if (sec_begin >= ph_begin && sec_end <= ph_end) {
                const std::string flags = format_ph_flags(ph.flags);
                char ph_buf[160];
                std::snprintf(ph_buf,
                              sizeof(ph_buf),
                              "program_table_element[0x%02zx] %s %s",
                              ph_idx,
                              flags.c_str(),
                              program_type_desc(ph.type));
                if (ph.type == PT_LOAD) {
                    // PT_LOAD 信息优先展示。
                    if (!load_prefix.empty()) {
                        load_prefix.append(" | ");
                    }
                    load_prefix.append(ph_buf);
                } else {
                    // 非 LOAD 的覆盖信息（如 PT_DYNAMIC/NOTE）作为补充。
                    if (!other_prefix.empty()) {
                        other_prefix.append(" | ");
                    }
                    other_prefix.append(ph_buf);
                }
            }
        }
        if (!load_prefix.empty()) {
            prefix = load_prefix;
        }
        if (!other_prefix.empty()) {
            if (!prefix.empty()) {
                prefix.append(" | ");
            }
            prefix.append(other_prefix);
        }
        if (!prefix.empty()) {
            prefix.append("    ");
        }
        char buf[200];
        std::snprintf(buf,
                      sizeof(buf),
                      "%ssection[0x%02zx] %s",
                      prefix.c_str(),
                      idx,
                      sec.resolved_name.empty() ? "<unnamed>" : sec.resolved_name.c_str());
        sec_block.label = buf;
        top_blocks.push_back(std::move(sec_block));
    }

    // 4) 加入 Section Header Table 区块及其子条目。
    if (header_model_.raw.e_shoff != 0 && header_model_.raw.e_shnum > 0 && header_model_.raw.e_shentsize > 0) {
        // SHT 主块 + 每个 shdr 子块。
        LayoutBlock sht;
        sht.start = header_model_.raw.e_shoff;
        sht.size = (uint64_t)header_model_.raw.e_shnum * header_model_.raw.e_shentsize;
        sht.label = "section_header_table";
        for (size_t idx = 0; idx < sh_table_model_.elements.size(); ++idx) {
            LayoutBlock child;
            child.start = header_model_.raw.e_shoff + (uint64_t)idx * header_model_.raw.e_shentsize;
            child.size = header_model_.raw.e_shentsize;
            const auto& sec = *sh_table_model_.elements[idx];
            // 索引 0 按 ELF 规范显示为 SHN_UNDEF。
            const char* name = (idx == 0) ? "SHN_UNDEF" :
                               (sec.resolved_name.empty() ? "<unnamed>" : sec.resolved_name.c_str());
            char buf[128];
            std::snprintf(buf,
                          sizeof(buf),
                          "section_table_element[0x%02zx] %s",
                          idx,
                          name);
            child.label = buf;
            sht.children.push_back(std::move(child));
        }
        std::sort(sht.children.begin(), sht.children.end(),
                  [](const LayoutBlock& a, const LayoutBlock& b) { return a.start < b.start; });
        top_blocks.push_back(std::move(sht));
    }

    // 5) 根据相邻区块间距补齐 [padding] 视图，帮助识别空洞空间。
    std::vector<LayoutBlock> padding_blocks;
    std::vector<LayoutBlock> sorted = top_blocks;
    std::sort(sorted.begin(), sorted.end(),
              [](const LayoutBlock& a, const LayoutBlock& b) { return a.start < b.start; });
    for (size_t i = 0; i + 1 < sorted.size(); ++i) {
        // 计算相邻块之间的空洞，单独标记 [padding]。
        const uint64_t cur_end = sorted[i].start + sorted[i].size;
        const uint64_t next_start = sorted[i + 1].start;
        if (next_start > cur_end) {
            LayoutBlock pad;
            pad.start = cur_end;
            pad.size = next_start - cur_end;
            pad.label = "[padding]";
            padding_blocks.push_back(std::move(pad));
        }
    }

    for (auto& pad : padding_blocks) {
        top_blocks.push_back(std::move(pad));
    }

    // 顶层条目排序后统一打印。
    std::sort(top_blocks.begin(), top_blocks.end(),
              [](const LayoutBlock& a, const LayoutBlock& b) { return a.start < b.start; });

    for (const auto& block : top_blocks) {
        print_block_line(block);
        for (const auto& child : block.children) {
            LayoutBlock child_line = child;
            child_line.level = block.level + 1;
            print_block_line(child_line);
        }
    }
}

// 迁移并扩容 Program Header Table（常用于给新增段预留 phdr 条目）。
bool zElf::relocate_and_expand_pht(int extra_entries, const char* output_path) {
    if (extra_entries <= 0) {
        LOGE("extra_entries must be positive");
        return false;
    }

    for (int i = 0; i < extra_entries; ++i) {
        zProgramTableElement entry;
        entry.type = PT_NULL;
        ph_table_model_.elements.push_back(entry);
    }

    const Elf64_Off PAGE_SIZE = (Elf64_Off)infer_runtime_page_size_from_phdrs(ph_table_model_.elements);
    // 新 PHT 放到当前文件末尾并按页对齐，避免覆盖现有数据。
    const Elf64_Off new_pht_offset = align_up_off((Elf64_Off)currentMaxFileEnd(), PAGE_SIZE);
    header_model_.raw.e_phoff = new_pht_offset;
    header_model_.raw.e_phnum = (Elf64_Half)ph_table_model_.elements.size();

    int pt_phdr_idx = ph_table_model_.findFirstByType(PT_PHDR);
    if (pt_phdr_idx >= 0) {
        // 若原文件有 PT_PHDR，则同步刷新其 offset/vaddr/filesz/memsz。
        auto& pt_phdr = ph_table_model_.elements[pt_phdr_idx];
        pt_phdr.offset = new_pht_offset;
        Elf64_Addr mapped_vaddr = 0;
        for (const auto& ph : ph_table_model_.elements) {
            if (ph.type != PT_LOAD || ph.filesz == 0) {
                continue;
            }
            // 找到覆盖新 pht_offset 的 LOAD，用它反推 PT_PHDR 的虚拟地址。
            if (new_pht_offset >= ph.offset && new_pht_offset < ph.offset + ph.filesz) {
                mapped_vaddr = (Elf64_Addr)(ph.vaddr + (new_pht_offset - ph.offset));
                break;
            }
        }
        pt_phdr.vaddr = mapped_vaddr;
        pt_phdr.paddr = pt_phdr.vaddr;
        pt_phdr.filesz = (Elf64_Xword)(ph_table_model_.elements.size() * sizeof(Elf64_Phdr));
        pt_phdr.memsz = pt_phdr.filesz;
        pt_phdr.align = PAGE_SIZE;
    }

    // 提交模型变更到 file_image_。
    reconstruction_dirty_ = true;
    if (!Reconstruction()) {
        return false;
    }

    // 做一次全量校验，确保迁移后结构仍合法。
    std::string err;
    if (!validate(&err)) {
        LOGE("relocate_and_expand_pht validation failed: %s", err.c_str());
        return false;
    }

    return output_path ? save(output_path) : true;
}
// Header 模型可写访问。
zElfHeader& zElf::headerModel() {
    return header_model_;
}

// Program Header 模型可写访问。
zElfProgramHeaderTable& zElf::programHeaderModel() {
    return ph_table_model_;
}

// Section Header 模型可写访问。
zElfSectionHeaderTable& zElf::sectionHeaderModel() {
    return sh_table_model_;
}

// Header 模型只读访问。
const zElfHeader& zElf::headerModel() const {
    return header_model_;
}

// Program Header 模型只读访问。
const zElfProgramHeaderTable& zElf::programHeaderModel() const {
    return ph_table_model_;
}

// Section Header 模型只读访问。
const zElfSectionHeaderTable& zElf::sectionHeaderModel() const {
    return sh_table_model_;
}

zProgramTableElement* zElf::getProgramHeader(size_t idx) {
    // 越界保护：调用方收到 nullptr 表示索引非法。
    if (idx >= ph_table_model_.elements.size()) {
        return nullptr;
    }
    return &ph_table_model_.elements[idx];
}

const zProgramTableElement* zElf::getProgramHeader(size_t idx) const {
    if (idx >= ph_table_model_.elements.size()) {
        return nullptr;
    }
    return &ph_table_model_.elements[idx];
}

zProgramTableElement* zElf::findFirstProgramHeader(Elf64_Word type) {
    // 复用 table 模型查找，再返回可写指针。
    const int idx = ph_table_model_.findFirstByType(type);
    return idx >= 0 ? &ph_table_model_.elements[(size_t)idx] : nullptr;
}

const zProgramTableElement* zElf::findFirstProgramHeader(Elf64_Word type) const {
    const int idx = ph_table_model_.findFirstByType(type);
    return idx >= 0 ? &ph_table_model_.elements[(size_t)idx] : nullptr;
}

std::vector<zProgramTableElement*> zElf::findAllProgramHeaders(Elf64_Word type) {
    std::vector<zProgramTableElement*> result;
    // 过滤掉模型与索引列表之间的潜在越界。
    for (int idx : ph_table_model_.findAllByType(type)) {
        if (idx >= 0 && (size_t)idx < ph_table_model_.elements.size()) {
            result.push_back(&ph_table_model_.elements[(size_t)idx]);
        }
    }
    return result;
}

std::vector<const zProgramTableElement*> zElf::findAllProgramHeaders(Elf64_Word type) const {
    std::vector<const zProgramTableElement*> result;
    for (int idx : ph_table_model_.findAllByType(type)) {
        if (idx >= 0 && (size_t)idx < ph_table_model_.elements.size()) {
            result.push_back(&ph_table_model_.elements[(size_t)idx]);
        }
    }
    return result;
}

zSectionTableElement* zElf::getSection(size_t idx) {
    // 委托到 section table 的边界检查逻辑。
    return sh_table_model_.get(idx);
}

const zSectionTableElement* zElf::getSection(size_t idx) const {
    return sh_table_model_.get(idx);
}

zSectionTableElement* zElf::findSectionByName(const std::string& section_name) {
    // 先拿索引，再取对象，避免重复遍历。
    const int idx = sh_table_model_.findByName(section_name);
    return idx >= 0 ? sh_table_model_.get((size_t)idx) : nullptr;
}

const zSectionTableElement* zElf::findSectionByName(const std::string& section_name) const {
    const int idx = sh_table_model_.findByName(section_name);
    return idx >= 0 ? sh_table_model_.get((size_t)idx) : nullptr;
}

bool zElf::addProgramHeader(const zProgramTableElement& ph, size_t* out_index) {
    // 仅更新模型并标脏；实际写回由 Reconstruction/save 完成。
    ph_table_model_.elements.push_back(ph);
    if (out_index) {
        *out_index = ph_table_model_.elements.size() - 1;
    }
    reconstruction_dirty_ = true;
    return true;
}

bool zElf::addSectionSimple(const std::string& name,
                            Elf64_Word type,
                            Elf64_Xword flags,
                            Elf64_Xword addralign,
                            const std::vector<uint8_t>& payload,
                            size_t* out_index) {
    if (name.empty()) {
        return false;
    }
    if (header_model_.raw.e_shstrndx >= sh_table_model_.elements.size()) {
        return false;
    }
    auto* shstrtab = dynamic_cast<zStrTabSection*>(sh_table_model_.get(header_model_.raw.e_shstrndx));
    if (!shstrtab) {
        return false;
    }

    auto section = std::make_unique<zSectionTableElement>();
    section->type = type;
    section->flags = flags;
    section->addralign = addralign == 0 ? 1 : addralign;
    section->payload = payload;
    section->resolved_name = name;
    section->name = shstrtab->addString(name);
    if ((flags & SHF_ALLOC) == 0 && type != SHT_NOBITS && !payload.empty()) {
        // 非 ALLOC 节直接追加到文件尾，尽量不干扰 LOAD 映射。
        auto align_up_local = [](Elf64_Off value, Elf64_Off align) -> Elf64_Off {
            if (align == 0) {
                return value;
            }
            return ((value + align - 1) / align) * align;
        };
        section->offset = align_up_local((Elf64_Off)currentMaxFileEnd(), (Elf64_Off)section->addralign);
    }
    section->syncHeader();

    const size_t new_index = sh_table_model_.elements.size();
    sh_table_model_.elements.push_back(std::move(section));
    if (out_index) {
        *out_index = new_index;
    }
    reconstruction_dirty_ = true;
    return true;
}

bool zElf::addSectionPaddingByName(const std::string& section_name, size_t pad_size) {
    // 名称接口只是索引接口的薄封装。
    const int idx = sh_table_model_.findByName(section_name);
    if (idx < 0) {
        return false;
    }
    return addSectionPaddingByIndex((size_t)idx, pad_size);
}

bool zElf::addSectionPaddingByIndex(size_t idx, size_t pad_size) {
    if (pad_size == 0) {
        return true;
    }
    auto* section = sh_table_model_.get(idx);
    if (!section) {
        return false;
    }
    if (section->type == SHT_NOBITS) {
        // NOBITS 扩容只改 size（不产生文件 payload）。
        section->size += (Elf64_Xword)pad_size;
    } else {
        // 其他节在 payload 尾部补 0。
        section->payload.resize(section->payload.size() + pad_size, 0);
    }
    section->syncHeader();
    reconstruction_dirty_ = true;
    return true;
}

bool zElf::addZeroFillToSegment(size_t idx, Elf64_Xword extra_memsz) {
    if (idx >= ph_table_model_.elements.size()) {
        return false;
    }
    if (extra_memsz == 0) {
        return true;
    }
    auto& ph = ph_table_model_.elements[idx];
    // 只扩 memsz，不改 filesz，表示新增的是零填充内存页。
    ph.memsz += extra_memsz;
    if (ph.memsz < ph.filesz) {
        ph.memsz = ph.filesz;
    }
    reconstruction_dirty_ = true;
    return true;
}

static Elf64_Word parse_pf_flags_text(const std::string& flags_text) {
    // 约定使用三字符文本（例如 "RWX" / "R_X"）。
    if (flags_text.size() < 3) {
        return 0;
    }
    Elf64_Word flags = 0;
    if (flags_text[0] == 'R') {
        flags |= PF_R;
    }
    if (flags_text[1] == 'W') {
        flags |= PF_W;
    }
    if (flags_text[2] == 'X') {
        flags |= PF_X;
    }
    return flags;
}

bool zElf::add_segment(Elf64_Word type,
                       const std::string& flags_text,
                       size_t* out_index) {
    // 新段默认放到文件尾/虚拟地址尾，并按页对齐。
    const Elf64_Off page_size = (Elf64_Off)infer_runtime_page_size_from_phdrs(ph_table_model_.elements);
    const Elf64_Off new_off = align_up_off((Elf64_Off)currentMaxFileEnd(), page_size);
    const uint64_t vaddr_base = (uint64_t)align_up_off((Elf64_Off)currentMaxLoadVaddrEnd(), page_size);
    const Elf64_Addr new_vaddr = (Elf64_Addr)(vaddr_base + ((uint64_t)new_off % (uint64_t)page_size));

    zProgramTableElement ph;
    // 新段的文件地址和虚拟地址都从各自末尾对齐后分配。
    ph.type = type;
    ph.flags = parse_pf_flags_text(flags_text);
    ph.offset = new_off;
    ph.vaddr = new_vaddr;
    ph.paddr = new_vaddr;
    ph.filesz = 0;
    ph.memsz = 0;
    ph.align = page_size;

    ph_table_model_.elements.push_back(ph);
    if (out_index) {
        *out_index = ph_table_model_.elements.size() - 1;
    }
    reconstruction_dirty_ = true;
    return true;
}

bool zElf::add_section(const std::string& name,
                       size_t load_segment_idx,
                       size_t* out_index) {
    if (load_segment_idx >= ph_table_model_.elements.size()) {
        return false;
    }
    auto& seg = ph_table_model_.elements[load_segment_idx];
    if (seg.type != PT_LOAD) {
        return false;
    }
    if (header_model_.raw.e_shstrndx >= sh_table_model_.elements.size()) {
        return false;
    }
    auto* shstrtab = dynamic_cast<zStrTabSection*>(sh_table_model_.get(header_model_.raw.e_shstrndx));
    if (!shstrtab) {
        return false;
    }

    const Elf64_Off align = 0x10;
    const size_t payload_size = 0x10;

    uint64_t next_load_off = std::numeric_limits<uint64_t>::max();
    // 找到紧随当前 seg 的下一个 LOAD，用于判断文件区间是否会冲突。
    for (const auto& ph : ph_table_model_.elements) {
        if (ph.type != PT_LOAD || ph.offset <= seg.offset) {
            continue;
        }
        next_load_off = std::min<uint64_t>(next_load_off, ph.offset);
    }

    const Elf64_Off sec_off = align_up_off((Elf64_Off)(seg.offset + seg.filesz), align);
    const uint64_t sec_end = (uint64_t)sec_off + payload_size;
    const bool overlap_next_load = next_load_off != std::numeric_limits<uint64_t>::max() &&
                                   sec_end > next_load_off;

    auto section = std::make_unique<zSectionTableElement>();
    section->flags = SHF_ALLOC;
    section->addralign = align;
    if (overlap_next_load) {
        // 回退为 NOBITS，避免与后续 PT_LOAD 文件区间重叠。
        const uint64_t aligned_addr = align_up_off((Elf64_Off)(seg.vaddr + seg.memsz), align);
        section->type = SHT_NOBITS;
        section->size = payload_size;
        section->addr = (Elf64_Addr)aligned_addr;
        section->offset = (Elf64_Off)(seg.offset + (section->addr - seg.vaddr));
    } else {
        // 文件空间允许时创建 PROGBITS 并分配零初始化 payload。
        section->type = SHT_PROGBITS;
        section->payload.assign(payload_size, 0);
        section->offset = sec_off;
        section->addr = (Elf64_Addr)(seg.vaddr + (sec_off - seg.offset));
        const Elf64_Off new_end = sec_off + (Elf64_Off)section->payload.size();
        if (new_end > seg.offset + seg.filesz) {
            seg.filesz = (Elf64_Xword)(new_end - seg.offset);
        }
    }
    section->resolved_name = name;
    section->name = shstrtab->addString(name);
    section->syncHeader();

    if (seg.memsz < seg.filesz) {
        // 保证段满足 memsz >= filesz。
        seg.memsz = seg.filesz;
    }
    if (section->type == SHT_NOBITS) {
        const uint64_t sec_mem_end = section->addr + section->size;
        const uint64_t seg_mem_end = seg.vaddr + seg.memsz;
        if (sec_mem_end > seg_mem_end) {
            seg.memsz = (Elf64_Xword)(sec_mem_end - seg.vaddr);
        }
    }

    const size_t new_index = sh_table_model_.elements.size();
    sh_table_model_.elements.push_back(std::move(section));
    if (out_index) {
        *out_index = new_index;
    }
    reconstruction_dirty_ = true;
    return true;
}

bool zElf::add_section(const std::string& name, size_t* out_index) {
    // 简化接口：默认挂到最后一个 LOAD。
    const int idx = get_last_load_segment();
    if (idx < 0) {
        return false;
    }
    return add_section(name, (size_t)idx, out_index);
}

int zElf::get_first_load_segment() const {
    // 返回第一个 PT_LOAD 索引（不存在则 -1）。
    return ph_table_model_.findFirstByType(PT_LOAD);
}

int zElf::get_last_load_segment() const {
    int last = -1;
    for (int idx : ph_table_model_.findAllByType(PT_LOAD)) {
        if (idx > last) {
            last = idx;
        }
    }
    return last;
}

bool zElf::relocate(const std::string& output_path) {
    // 兼容旧接口：本质就是 save。
    return save(output_path.c_str());
}

bool zElf::backup() {
    // 重新加载源文件，恢复到最初解析状态。
    if (source_path_.empty()) {
        return false;
    }
    return load_elf_file(source_path_.c_str());
}

zElf::~zElf() {
}

// 完整重构流程已从当前生产链路移除，保留失败返回避免误写文件。
bool zElf::reconstructionImpl() {
    LOGE("reconstructionImpl is removed from current patchbay runtime");
    return false;
}
