/*
 * [VMP_FLOW_NOTE] 文件级流程注释。
 * - 文件：patchbayModel/zPatchElfModel.cpp
 * - 主要职责：Patch ELF 内存模型：组织段/节/符号等结构化数据，作为后续补丁操作基础。
 * - 输入：ELF 原始字节、补丁模型状态以及段/节/符号元数据。
 * - 输出：经过校验的补丁模型或重建后的 ELF 输出数据。
 * - 关键约束：
 *   1) 严格保持 ELF 布局与索引一致性，避免地址/偏移漂移。
 *   2) 失败路径必须可定位（返回值/错误信息/日志三者保持一致）。
 *   3) 本文件改动优先保证与上游调用契约兼容，不隐式改变既有语义。
 */
// PatchElf 模型读写接口实现：负责 header/phdr/shdr 访问、增量修改与简单封装操作。
#include "zPatchElf.h"
// 对齐与页大小推断工具。
#include "zPatchElfUtils.h"

// 排序/最值工具。
#include <algorithm>
// 数值上限。
#include <limits>
// 字符串处理。
#include <string>
// 字节载荷容器。
#include <vector>

// Header 模型可写访问。
zElfHeader& PatchElf::getHeaderModel() {
    return header_model_;
}

// Program Header 模型可写访问。
zElfProgramHeaderTable& PatchElf::getProgramHeaderModel() {
    return ph_table_model_;
}

// Section Header 模型可写访问。
zElfSectionHeaderTable& PatchElf::getSectionHeaderModel() {
    return sh_table_model_;
}

// Header 模型只读访问。
const zElfHeader& PatchElf::getHeaderModel() const {
    return header_model_;
}

// Program Header 模型只读访问。
const zElfProgramHeaderTable& PatchElf::getProgramHeaderModel() const {
    return ph_table_model_;
}

// Section Header 模型只读访问。
const zElfSectionHeaderTable& PatchElf::getSectionHeaderModel() const {
    return sh_table_model_;
}

// 按索引获取可写 Program Header。
zProgramTableElement* PatchElf::getProgramHeader(size_t programHeaderIndex) {
    // 越界保护：调用方收到 nullptr 表示索引非法。
    if (programHeaderIndex >= ph_table_model_.elements.size()) {
        return nullptr;
    }
    // 返回对应元素指针。
    return &ph_table_model_.elements[programHeaderIndex];
}

// 按索引获取只读 Program Header。
const zProgramTableElement* PatchElf::getProgramHeader(size_t programHeaderIndex) const {
    // 越界返回空。
    if (programHeaderIndex >= ph_table_model_.elements.size()) {
        return nullptr;
    }
    // 返回只读指针。
    return &ph_table_model_.elements[programHeaderIndex];
}

// 查找首个指定类型的 Program Header（可写）。
zProgramTableElement* PatchElf::getFirstProgramHeader(Elf64_Word type) {
    // 复用 table 模型查找，再返回可写指针。
    const int programHeaderIndex = ph_table_model_.getFirstByType(type);
    return programHeaderIndex >= 0 ? &ph_table_model_.elements[(size_t)programHeaderIndex] : nullptr;
}

// 查找首个指定类型的 Program Header（只读）。
const zProgramTableElement* PatchElf::getFirstProgramHeader(Elf64_Word type) const {
    const int programHeaderIndex = ph_table_model_.getFirstByType(type);
    return programHeaderIndex >= 0 ? &ph_table_model_.elements[(size_t)programHeaderIndex] : nullptr;
}

// 查找全部指定类型 Program Header（可写）。
std::vector<zProgramTableElement*> PatchElf::getAllProgramHeaders(Elf64_Word type) {
    std::vector<zProgramTableElement*> result;
    // 过滤掉模型与索引列表之间的潜在越界。
    for (int programHeaderIndex : ph_table_model_.getAllByType(type)) {
        if (programHeaderIndex >= 0 &&
            (size_t)programHeaderIndex < ph_table_model_.elements.size()) {
            result.push_back(&ph_table_model_.elements[(size_t)programHeaderIndex]);
        }
    }
    return result;
}

// 查找全部指定类型 Program Header（只读）。
std::vector<const zProgramTableElement*> PatchElf::getAllProgramHeaders(Elf64_Word type) const {
    std::vector<const zProgramTableElement*> result;
    for (int programHeaderIndex : ph_table_model_.getAllByType(type)) {
        if (programHeaderIndex >= 0 &&
            (size_t)programHeaderIndex < ph_table_model_.elements.size()) {
            result.push_back(&ph_table_model_.elements[(size_t)programHeaderIndex]);
        }
    }
    return result;
}

// 按索引获取可写 Section。
zSectionTableElement* PatchElf::getSection(size_t sectionIndex) {
    // 委托到 section table 的边界检查逻辑。
    return sh_table_model_.get(sectionIndex);
}

// 按索引获取只读 Section。
const zSectionTableElement* PatchElf::getSection(size_t sectionIndex) const {
    return sh_table_model_.get(sectionIndex);
}

// 按名称查找可写 Section。
zSectionTableElement* PatchElf::getSectionByName(const std::string& sectionName) {
    // 先拿索引，再取对象，避免重复遍历。
    const int sectionIndex = sh_table_model_.getByName(sectionName);
    return sectionIndex >= 0 ? sh_table_model_.get((size_t)sectionIndex) : nullptr;
}

// 按名称查找只读 Section。
const zSectionTableElement* PatchElf::getSectionByName(const std::string& sectionName) const {
    const int sectionIndex = sh_table_model_.getByName(sectionName);
    return sectionIndex >= 0 ? sh_table_model_.get((size_t)sectionIndex) : nullptr;
}

// 追加 Program Header 到模型。
bool PatchElf::addProgramHeader(const zProgramTableElement& ph, size_t* outIndex) {
    // 仅更新模型并标脏；实际写回由 reconstruct/save 完成。
    ph_table_model_.elements.push_back(ph);
    // 回传新索引（可选）。
    if (outIndex) {
        *outIndex = ph_table_model_.elements.size() - 1;
    }
    // 标记需要重构。
    reconstruction_dirty_ = true;
    return true;
}

// 简单追加 Section：按输入参数快速构造一个节对象。
bool PatchElf::addSectionSimple(const std::string& name,
                                Elf64_Word type,
                                Elf64_Xword flags,
                                Elf64_Xword addralign,
                                const std::vector<uint8_t>& payload,
                                size_t* outIndex) {
    // 名称不能为空。
    if (name.empty()) {
        return false;
    }
    // e_shstrndx 必须指向有效节索引。
    if (header_model_.raw.e_shstrndx >= sh_table_model_.elements.size()) {
        return false;
    }
    // 取节名字符串表。
    auto* shstrtab = dynamic_cast<zStrTabSection*>(sh_table_model_.get(header_model_.raw.e_shstrndx));
    if (!shstrtab) {
        return false;
    }

    // 构建新节对象。
    auto section = std::make_unique<zSectionTableElement>();
    // 类型。
    section->type = type;
    // 标志位。
    section->flags = flags;
    // 对齐最小值 1。
    section->addralign = addralign == 0 ? 1 : addralign;
    // 写入载荷。
    section->payload = payload;
    // 记录解析名。
    section->resolved_name = name;
    // 向 shstrtab 追加名字并记录 name 偏移。
    section->name = shstrtab->addString(name);
    // 非 ALLOC 且非 NOBITS 的节，放到文件尾并按对齐补齐。
    if ((flags & SHF_ALLOC) == 0 && type != SHT_NOBITS && !payload.empty()) {
        // 局部对齐辅助。
        auto alignUp = [](Elf64_Off value, Elf64_Off align) -> Elf64_Off {
            if (align == 0) {
                return value;
            }
            return ((value + align - 1) / align) * align;
        };
        section->offset = alignUp((Elf64_Off)getMaxFileEnd(), (Elf64_Off)section->addralign);
    }
    // 同步 section header 字段。
    section->syncHeader();

    // 新节索引。
    const size_t new_index = sh_table_model_.elements.size();
    // 插入节对象。
    sh_table_model_.elements.push_back(std::move(section));
    // 回传索引（可选）。
    if (outIndex) {
        *outIndex = new_index;
    }
    // 标记需要重构。
    reconstruction_dirty_ = true;
    return true;
}

// 按节名给节尾补 padding。
bool PatchElf::addSectionPaddingByName(const std::string& sectionName, size_t padSize) {
    // 名称接口只是索引接口的薄封装。
    const int sectionIndex = sh_table_model_.getByName(sectionName);
    if (sectionIndex < 0) {
        return false;
    }
    return addSectionPaddingByIndex((size_t)sectionIndex, padSize);
}

// 按节索引给节尾补 padding。
bool PatchElf::addSectionPaddingByIndex(size_t sectionIndex, size_t padSize) {
    // 补 0 字节视为成功无操作。
    if (padSize == 0) {
        return true;
    }
    // 获取目标节。
    auto* section = sh_table_model_.get(sectionIndex);
    if (!section) {
        return false;
    }
    // NOBITS 扩容只改 size（不产生文件 payload）。
    if (section->type == SHT_NOBITS) {
        section->size += (Elf64_Xword)padSize;
    } else {
        // 其他节在 payload 尾部补 0。
        section->payload.resize(section->payload.size() + padSize, 0);
    }
    // 同步头字段。
    section->syncHeader();
    // 标记需要重构。
    reconstruction_dirty_ = true;
    return true;
}

// 仅扩大段 memsz（不改 filesz），用于零填充内存扩容。
bool PatchElf::addZeroFillToSegment(size_t segmentIndex, Elf64_Xword extraMemsz) {
    // 索引越界。
    if (segmentIndex >= ph_table_model_.elements.size()) {
        return false;
    }
    // 扩容为 0 视为成功无操作。
    if (extraMemsz == 0) {
        return true;
    }
    // 取可写段引用。
    auto& ph = ph_table_model_.elements[segmentIndex];
    // 只扩 memsz，不改 filesz，表示新增的是零填充内存页。
    ph.memsz += extraMemsz;
    // 兜底保证 memsz >= filesz。
    if (ph.memsz < ph.filesz) {
        ph.memsz = ph.filesz;
    }
    // 标记需要重构。
    reconstruction_dirty_ = true;
    return true;
}

namespace {

// 解析三字符权限文本（例如 "RWX" / "R_X"）到 PF_* 位掩码。
Elf64_Word parsePfFlagsText(const std::string& flagsText) {
    // 长度不足三位直接返回 0。
    if (flagsText.size() < 3) {
        return 0;
    }
    // 初始权限值。
    Elf64_Word flags = 0;
    // 读权限。
    if (flagsText[0] == 'R') {
        flags |= PF_R;
    }
    // 写权限。
    if (flagsText[1] == 'W') {
        flags |= PF_W;
    }
    // 执行权限。
    if (flagsText[2] == 'X') {
        flags |= PF_X;
    }
    return flags;
}

} // namespace

// 追加一个新段（初始 filesz/memsz 为 0）。
bool PatchElf::addSegment(Elf64_Word type,
                          const std::string& flagsText,
                          size_t* outIndex) {
    // 新段默认放到文件尾/虚拟地址尾，并按页对齐。
    const Elf64_Off page_size = (Elf64_Off)inferRuntimePageSizeFromPhdrs(ph_table_model_.elements);
    // 文件偏移按页对齐。
    const Elf64_Off new_off = alignUpOff((Elf64_Off)getMaxFileEnd(), page_size);
    // 虚拟地址基准按页对齐。
    const uint64_t vaddr_base = (uint64_t)alignUpOff((Elf64_Off)getMaxLoadVaddrEnd(), page_size);
    // 兼容 p_vaddr%page == p_offset%page 的同余关系。
    const Elf64_Addr new_vaddr = (Elf64_Addr)(vaddr_base + ((uint64_t)new_off % (uint64_t)page_size));

    // 构建新段对象。
    zProgramTableElement ph;
    // 新段的文件地址和虚拟地址都从各自末尾对齐后分配。
    ph.type = type;
    // 解析权限文本。
    ph.flags = parsePfFlagsText(flagsText);
    // 文件偏移。
    ph.offset = new_off;
    // 虚拟地址。
    ph.vaddr = new_vaddr;
    // 物理地址与虚拟地址保持一致。
    ph.paddr = new_vaddr;
    // 初始无文件内容。
    ph.filesz = 0;
    // 初始无内存扩展。
    ph.memsz = 0;
    // 段对齐。
    ph.align = page_size;

    // 追加到段表。
    ph_table_model_.elements.push_back(ph);
    // 回传索引（可选）。
    if (outIndex) {
        *outIndex = ph_table_model_.elements.size() - 1;
    }
    // 标记需要重构。
    reconstruction_dirty_ = true;
    return true;
}

// 在指定 LOAD 段上追加一个简单节。
bool PatchElf::addSection(const std::string& name,
                          size_t loadSegmentIndex,
                          size_t* outIndex) {
    // 段索引越界。
    if (loadSegmentIndex >= ph_table_model_.elements.size()) {
        return false;
    }
    // 取目标段引用。
    auto& seg = ph_table_model_.elements[loadSegmentIndex];
    // 只允许挂在 PT_LOAD 上。
    if (seg.type != PT_LOAD) {
        return false;
    }
    // 节名字符串表索引必须合法。
    if (header_model_.raw.e_shstrndx >= sh_table_model_.elements.size()) {
        return false;
    }
    // 取 shstrtab 节。
    auto* shstrtab = dynamic_cast<zStrTabSection*>(sh_table_model_.get(header_model_.raw.e_shstrndx));
    if (!shstrtab) {
        return false;
    }

    // 新节对齐。
    const Elf64_Off align = 0x10;
    // 默认载荷大小。
    const size_t payloadSize = 0x10;

    // 下一个 LOAD 的 offset（用于冲突检测）。
    uint64_t nextLoadOffset = std::numeric_limits<uint64_t>::max();
    // 找到紧随当前 seg 的下一个 LOAD，用于判断文件区间是否会冲突。
    for (const auto& ph : ph_table_model_.elements) {
        if (ph.type != PT_LOAD || ph.offset <= seg.offset) {
            continue;
        }
        nextLoadOffset = std::min<uint64_t>(nextLoadOffset, ph.offset);
    }

    // 计算节文件偏移（紧接当前段 filesz 后并对齐）。
    const Elf64_Off sectionOffset = alignUpOff((Elf64_Off)(seg.offset + seg.filesz), align);
    // 计算节文件结束（开区间）。
    const uint64_t sectionEnd = (uint64_t)sectionOffset + payloadSize;
    // 判断是否会撞到后一个 LOAD。
    const bool overlapNextLoad = nextLoadOffset != std::numeric_limits<uint64_t>::max() &&
                                 sectionEnd > nextLoadOffset;

    // 创建节对象。
    auto section = std::make_unique<zSectionTableElement>();
    // 新节默认设为 ALLOC。
    section->flags = SHF_ALLOC;
    // 对齐要求。
    section->addralign = align;

    // 若会冲突，则用 NOBITS 仅扩内存不占文件字节。
    if (overlapNextLoad) {
        // 回退为 NOBITS，避免与后续 PT_LOAD 文件区间重叠。
        const uint64_t aligned_addr = alignUpOff((Elf64_Off)(seg.vaddr + seg.memsz), align);
        section->type = SHT_NOBITS;
        section->size = payloadSize;
        section->addr = (Elf64_Addr)aligned_addr;
        section->offset = (Elf64_Off)(seg.offset + (section->addr - seg.vaddr));
    } else {
        // 文件空间允许时创建 PROGBITS 并分配零初始化 payload。
        section->type = SHT_PROGBITS;
        section->payload.assign(payloadSize, 0);
        section->offset = sectionOffset;
        section->addr = (Elf64_Addr)(seg.vaddr + (sectionOffset - seg.offset));
        const Elf64_Off newEnd = sectionOffset + (Elf64_Off)section->payload.size();
        // 如 section 扩展了段文件边界，则同步更新 filesz。
        if (newEnd > seg.offset + seg.filesz) {
            seg.filesz = (Elf64_Xword)(newEnd - seg.offset);
        }
    }
    // 写入节名。
    section->resolved_name = name;
    // 在 shstrtab 里登记 name 偏移。
    section->name = shstrtab->addString(name);
    // 同步头字段。
    section->syncHeader();

    // 段关系兜底：保证 memsz >= filesz。
    if (seg.memsz < seg.filesz) {
        seg.memsz = seg.filesz;
    }
    // NOBITS 额外确保段 mem 覆盖到节末。
    if (section->type == SHT_NOBITS) {
        const uint64_t sec_mem_end = section->addr + section->size;
        const uint64_t seg_mem_end = seg.vaddr + seg.memsz;
        if (sec_mem_end > seg_mem_end) {
            seg.memsz = (Elf64_Xword)(sec_mem_end - seg.vaddr);
        }
    }

    // 新节索引。
    const size_t new_index = sh_table_model_.elements.size();
    // 插入新节。
    sh_table_model_.elements.push_back(std::move(section));
    // 回传索引（可选）。
    if (outIndex) {
        *outIndex = new_index;
    }
    // 标记需要重构。
    reconstruction_dirty_ = true;
    return true;
}

// 追加节的简化接口：默认挂到最后一个 LOAD。
bool PatchElf::addSection(const std::string& name, size_t* outIndex) {
    // 简化接口：默认挂到最后一个 LOAD。
    const int lastLoadIndex = getLastLoadSegment();
    if (lastLoadIndex < 0) {
        return false;
    }
    return addSection(name, (size_t)lastLoadIndex, outIndex);
}

// 获取首个 PT_LOAD 索引。
int PatchElf::getFirstLoadSegment() const {
    // 返回第一个 PT_LOAD 索引（不存在则 -1）。
    return ph_table_model_.getFirstByType(PT_LOAD);
}

// 获取最后一个 PT_LOAD 索引。
int PatchElf::getLastLoadSegment() const {
    int last = -1;
    for (int loadIndex : ph_table_model_.getAllByType(PT_LOAD)) {
        if (loadIndex > last) {
            last = loadIndex;
        }
    }
    return last;
}

// 兼容旧接口：relocate 实际等价于 save。
bool PatchElf::relocate(const std::string& outputPath) {
    // 兼容旧接口：本质就是 save。
    return save(outputPath.c_str());
}

// 回滚到源文件初始状态。
bool PatchElf::backup() {
    // 重新加载源文件，恢复到最初解析状态。
    if (source_path_.empty()) {
        return false;
    }
    return loadElfFile(source_path_.c_str());
}

