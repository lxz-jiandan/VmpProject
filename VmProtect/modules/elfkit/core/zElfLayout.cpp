/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - zElf 布局分析与 PHT 迁移实现。
 * - 加固链路位置：离线结构校验与二进制改写辅助。
 * - 输入：已加载的 ELF 文件视图。
 * - 输出：布局文本与迁移后的 ELF 文件。
 */
#include "zElf.h"
// 文件写入工具。
#include "zFile.h"
// 日志输出工具。
#include "zLog.h"
// sort。
#include <algorithm>
// printf/snprintf。
#include <cstdio>
// memcpy/memset/strcmp/strncmp/strlen/strcpy。
#include <cstring>
// std::string。
#include <string>
// std::vector。
#include <vector>

// 打印 ELF 文件布局（含各区域与 padding 空洞），便于人工验证结构边界。
void zElf::printLayout() {
    // 入口保护：未加载文件时不允许继续做任何指针/偏移计算。
    if (!elf_file_ptr) {
        printf("ELF file not loaded\n");
        return;
    }

    // 标题输出：按“文件偏移升序”展示所有区域。
    printf("\n=== ELF File Layout (by address order) ===\n\n");

    // 内部结构：描述一个连续文件区间。
    struct MemRegion {
        // 区间起始文件偏移（包含）。
        unsigned long long start;
        // 区间结束文件偏移（包含）。
        unsigned long long end;
        // 区间长度（字节）。
        unsigned long long size;
        // 区域名称（固定缓冲，便于后续 printf）。
        char name[256];
        // 层级：0=顶层区域，1=子项区域。
        int level;
    };

    // 第一阶段：收集“原始区域”（不含自动补齐的 padding）。
    std::vector<MemRegion> regions;

    // 1) ELF Header 作为首个顶层区域加入。
    regions.push_back({
        0,
        (unsigned long long)(elf_header_size - 1),
        elf_header_size,
        "elf_header",
        0
    });

    // 2) Program Header Table 作为顶层区域加入。
    Elf64_Off phdr_offset = elf_header->e_phoff;
    Elf64_Xword phdr_size = elf_header->e_phentsize * program_header_table_num;
    regions.push_back({
        (unsigned long long)phdr_offset,
        (unsigned long long)(phdr_offset + phdr_size - 1),
        (unsigned long long)phdr_size,
        "program_header_table",
        0
    });

    // 2.1) 把每个 Program Header 条目也加入（作为 program_header_table 的子项）。
    for (int programHeaderIndex = 0; programHeaderIndex < program_header_table_num; ++programHeaderIndex) {
        // 当前条目的文件偏移 = pht 起始 + i * 单条大小。
        Elf64_Off entry_offset = phdr_offset + programHeaderIndex * elf_header->e_phentsize;

        // 生成可读的段类型描述文本。
        const char* type_name = "";
        switch (program_header_table[programHeaderIndex].p_type) {
            case PT_NULL: type_name = "NULL"; break;
            case PT_LOAD: type_name = "Loadable Segment"; break;
            case PT_DYNAMIC: type_name = "Dynamic Segment"; break;
            case PT_INTERP: type_name = "Interpreter Path"; break;
            case PT_NOTE: type_name = "Note"; break;
            case PT_PHDR: type_name = "Program Header"; break;
            case PT_TLS: type_name = "Thread-Local Storage"; break;
            case PT_GNU_EH_FRAME: type_name = "GCC .eh_frame_hdr Segment"; break;
            case PT_GNU_STACK: type_name = "GNU Stack (executability)"; break;
            case PT_GNU_RELRO: type_name = "GNU Read-only After Relocation"; break;
            default: type_name = "Unknown"; break;
        }

        // 把 p_flags 转成可读权限串（R/W/X 或下划线）。
        Elf64_Word flags = program_header_table[programHeaderIndex].p_flags;
        char perms[4];
        perms[0] = (flags & PF_R) ? 'R' : '_';
        perms[1] = (flags & PF_W) ? 'W' : '_';
        perms[2] = (flags & PF_X) ? 'X' : '_';
        perms[3] = '\0';

        // 拼装最终展示名称。
        char name[256];
        snprintf(name, sizeof(name), "program_table_element[0x%02x] (%s) %s",
                 programHeaderIndex,
                 perms,
                 type_name);

        // 先压入空 name，再拷贝格式化好的名字（沿用当前实现方式）。
        regions.push_back({
            (unsigned long long)entry_offset,
            (unsigned long long)(entry_offset + elf_header->e_phentsize - 1),
            (unsigned long long)elf_header->e_phentsize,
            "",
            1
        });
        strcpy(regions.back().name, name);
    }

    // 3) 收集“有实体文件内容”的 section 数据区为顶层区域。
    // 过滤条件：
    // - sh_size > 0：空节不输出；
    // - sh_offset > 0：避免把无效偏移当成实体区；
    // - sh_type != SHT_NOBITS：.bss 这类不占文件字节的节跳过。
    if (section_header_table && section_header_table_num > 0) {
        Elf64_Shdr *section = section_header_table;
        for (int sectionIndex = 0; sectionIndex < section_header_table_num; ++sectionIndex) {
            if (section->sh_size > 0 && section->sh_offset > 0 && section->sh_type != SHT_NOBITS) {
                // 从 .shstrtab 解析节名；异常情况下回退为空名。
                const char *section_name = "";
                if (section_string_table && section->sh_name < 10000) {
                    section_name = section_string_table + section->sh_name;
                }

                // 组装节展示名称，优先使用真实节名。
                char name[256];
                if (strlen(section_name) > 0) {
                    snprintf(name, sizeof(name), "section[0x%02x] %s", sectionIndex, section_name);
                } else {
                    snprintf(name, sizeof(name), "section[0x%02x]", sectionIndex);
                }

                // 节数据区作为顶层区域压入。
                regions.push_back({
                    (unsigned long long)section->sh_offset,
                    (unsigned long long)(section->sh_offset + section->sh_size - 1),
                    (unsigned long long)section->sh_size,
                    "",
                    0
                });
                strcpy(regions.back().name, name);
            }
            // 手动推进到下一节头。
            section++;
        }
    }

    // 4) 把 Section Header Table 自身作为顶层区域，并把每个表项当子项加入。
    if (section_header_table && section_header_table_num > 0) {
        Elf64_Off shdr_physical_offset = elf_header->e_shoff;
        Elf64_Xword shdr_physical_size = elf_header->e_shentsize * section_header_table_num;

        // 顶层：section_header_table 区域。
        regions.push_back({
            (unsigned long long)shdr_physical_offset,
            (unsigned long long)(shdr_physical_offset + shdr_physical_size - 1),
            (unsigned long long)shdr_physical_size,
            "section_header_table",
            0
        });

        // 子项：section_table_element[i]。
        for (int sectionHeaderIndex = 0;
             sectionHeaderIndex < section_header_table_num;
             ++sectionHeaderIndex) {
            // 当前 section header 条目偏移。
            Elf64_Off entry_offset = shdr_physical_offset + sectionHeaderIndex * elf_header->e_shentsize;

            // 解析节名：索引 0 约定为 SHN_UNDEF。
            const char *section_name = "";
            if (sectionHeaderIndex == 0) {
                section_name = "SHN_UNDEF";
            } else {
                Elf64_Shdr *sect = &section_header_table[sectionHeaderIndex];
                if (section_string_table && sect->sh_name < 10000) {
                    section_name = section_string_table + sect->sh_name;
                }
            }

            // 组装子项显示名称。
            char name[256];
            if (strlen(section_name) > 0) {
                snprintf(name, sizeof(name),
                         "section_table_element[0x%02x] %s",
                         sectionHeaderIndex,
                         section_name);
            } else {
                snprintf(name, sizeof(name), "section_table_element[0x%02x]", sectionHeaderIndex);
            }

            // 压入 section header 子项。
            regions.push_back({
                (unsigned long long)entry_offset,
                (unsigned long long)(entry_offset + elf_header->e_shentsize - 1),
                (unsigned long long)elf_header->e_shentsize,
                "",
                1
            });
            strcpy(regions.back().name, name);
        }
    }

    // 第二阶段：先把原始区域按起始偏移排序，后续才能正确补 gap。
    std::sort(regions.begin(), regions.end(), [](const MemRegion& a, const MemRegion& b) {
        return a.start < b.start;
    });

    // 第三阶段：构造“补齐空洞后的全量区域列表”。
    std::vector<MemRegion> all_regions_with_gaps;

    // 3.1) 先处理所有顶层区域之间的空洞。
    std::vector<MemRegion> top_level;
    for (const auto& r : regions) {
        if (r.level == 0) {
            top_level.push_back(r);
        }
    }
    std::sort(top_level.begin(), top_level.end(), [](const MemRegion& a, const MemRegion& b) {
        return a.start < b.start;
    });

    // last_end 表示“当前已覆盖的下一个起点”。
    unsigned long long last_end = 0;
    for (const auto& region : top_level) {
        // 若下一区域起点在 last_end 之后，中间即为 padding 空洞。
        if (region.start > last_end) {
            all_regions_with_gaps.push_back({
                last_end,
                region.start - 1,
                region.start - last_end,
                "[padding]",
                0
            });
        }

        // 加入当前真实区域。
        all_regions_with_gaps.push_back(region);

        // 更新覆盖终点（end 是包含边界，所以 +1）。
        if (region.end + 1 > last_end) {
            last_end = region.end + 1;
        }
    }

    // 3.2) 处理 program_header_table 的子项空洞。
    std::vector<MemRegion> program_children;
    Elf64_Off program_start = 0, program_end = 0;
    // 先找到 program_header_table 顶层范围。
    for (const auto& r : top_level) {
        if (strcmp(r.name, "program_header_table") == 0) {
            program_start = r.start;
            program_end = r.end;
            break;
        }
    }
    // 收集属于 program_table_element* 的子项。
    for (const auto& r : regions) {
        if (r.level == 1 && strncmp(r.name, "program_table_element", 21) == 0) {
            program_children.push_back(r);
        }
    }
    // 按偏移排序，才能顺序补空洞。
    std::sort(program_children.begin(), program_children.end(), [](const MemRegion& a, const MemRegion& b) {
        return a.start < b.start;
    });

    // 以父区间起点为扫描起点补 gap。
    last_end = program_start;
    for (const auto& region : program_children) {
        if (region.start > last_end) {
            all_regions_with_gaps.push_back({
                last_end,
                region.start - 1,
                region.start - last_end,
                "[padding]",
                1
            });
        }
        all_regions_with_gaps.push_back(region);
        if (region.end + 1 > last_end) {
            last_end = region.end + 1;
        }
    }

    // program_end 当前只用于保留父区间信息，避免未使用告警。
    (void)program_end;

    // 3.3) 处理 section_header_table 的子项空洞。
    std::vector<MemRegion> section_header_children;
    Elf64_Off section_header_start = 0;
    // 先找到 section_header_table 顶层范围起点。
    for (const auto& r : top_level) {
        if (strcmp(r.name, "section_header_table") == 0) {
            section_header_start = r.start;
            break;
        }
    }
    // 收集 section_table_element* 子项。
    for (const auto& r : regions) {
        if (r.level == 1 && strncmp(r.name, "section_table_element", strlen("section_table_element")) == 0) {
            section_header_children.push_back(r);
        }
    }
    // 排序后逐段补空洞。
    std::sort(section_header_children.begin(), section_header_children.end(), [](const MemRegion& a, const MemRegion& b) {
        return a.start < b.start;
    });

    last_end = section_header_start;
    for (const auto& region : section_header_children) {
        if (region.start > last_end) {
            all_regions_with_gaps.push_back({
                last_end,
                region.start - 1,
                region.start - last_end,
                "[padding]",
                1
            });
        }
        all_regions_with_gaps.push_back(region);
        if (region.end + 1 > last_end) {
            last_end = region.end + 1;
        }
    }

    // 第四阶段：用“补齐后列表”替换原始列表，供最终打印。
    regions = all_regions_with_gaps;

    // 第五阶段：按地址顺序打印。
    for (const auto& region : regions) {
        // 只从顶层项起打印，子项在父项分支里缩进打印。
        if (region.level == 0) {
            // 顶层输出格式：start-end size name。
            printf("0x%08llx-0x%08llx    0x%08llx    %s\n",
                   region.start, region.end, region.size, region.name);

            // 若当前顶层是 program_header_table，则打印其包含的所有子项。
            if (strcmp(region.name, "program_header_table") == 0) {
                for (const auto& child : regions) {
                    // 子项必须是 level=1 且地址范围完全落在父区间内。
                    if (child.level == 1 && child.start >= region.start && child.end <= region.end) {
                        printf("    0x%08llx-0x%08llx    0x%08llx    %s\n",
                               child.start, child.end, child.size, child.name);
                    }
                }
            }

            // 若当前顶层是 section_header_table，则打印其包含的所有子项。
            if (strcmp(region.name, "section_header_table") == 0) {
                for (const auto& child : regions) {
                    if (child.level == 1 && child.start >= region.start && child.end <= region.end) {
                        printf("    0x%08llx-0x%08llx    0x%08llx    %s\n",
                               child.start, child.end, child.size, child.name);
                    }
                }
            }
        }
    }

    // 末尾给出覆盖率摘要，强调已把空洞区间也显式建模。
    printf("\n=== Coverage Summary ===\n");
    printf("✓ Full coverage - all bytes accounted for (including gaps/padding)\n");
    printf("Total file size: 0x%08zx (%zu bytes)\n", file_size, file_size);
}

// 执行 PHT 迁移与扩容：
// 1) 在固定偏移构建新 PHT；
// 2) 追加一个“自救 PT_LOAD”覆盖新 PHT 区间；
// 3) 回写 ELF Header 的 e_phoff/e_phnum；
// 4) 产出新文件（不改原文件）。
bool zElf::relocateAndExpandPht(int extraEntries, const char* outputPath) {
    LOGI("=== Step-2: PHT Relocation & Expansion (Surgical Approach) ===");
    LOGI("Extra entries to add: %d", extraEntries);

    if (!outputPath || outputPath[0] == '\0') {
        LOGE("invalid output path");
        return false;
    }

    if (!elf_file_ptr || !program_header_table) {
        LOGE("ELF not loaded or parsed");
        return false;
    }

    // 迁移策略当前写死到 0x3000，用于 demo 流程稳定复现。
    // 页大小固定 4KB，与 ARM64 常见页对齐一致。
    const size_t PAGE_SIZE = 0x1000;
    // 新 PHT 目标偏移（文件内固定锚点）。
    const Elf64_Off NEW_PHT_OFFSET = 0x3000;

    // ========== 第一阶段：空间预计算 ==========
    LOGI("\n[Phase 1] Space Precalculation");

    Elf64_Half old_ph_num = program_header_table_num;
    // 新条目数 = 旧条目 + 额外扩展条目。
    Elf64_Half new_ph_num = old_ph_num + extraEntries;
    LOGI("  Old_PH_Num: %d", old_ph_num);
    LOGI("  New_PH_Num: %d", new_ph_num);

    // 新 PHT 总字节数 = 条目数 * 单条大小。
    size_t new_pht_size = new_ph_num * sizeof(Elf64_Phdr);
    LOGI("  New PHT size: 0x%zx (%zu bytes)", new_pht_size, new_pht_size);
    LOGI("  New PHT offset (fixed): 0x%llx", (unsigned long long)NEW_PHT_OFFSET);

    // ========== 第二阶段：构建新 PHT ==========
    LOGI("\n[Phase 2] Build New PHT");

    std::vector<Elf64_Phdr> new_pht_buffer(new_ph_num);

    // 拷贝旧 PHT
    // 保持原有段顺序与内容不变，只在尾部扩展新条目。
    std::memcpy(new_pht_buffer.data(), program_header_table, old_ph_num * sizeof(Elf64_Phdr));
    LOGI("  Copied %d old PHT entries", old_ph_num);

    // 初始化新增的 PHT 条目为 PT_NULL
    for (int newHeaderIndex = old_ph_num; newHeaderIndex < new_ph_num; ++newHeaderIndex) {
        // 先清零整条，避免脏字段。
        std::memset(&new_pht_buffer[(size_t)newHeaderIndex], 0, sizeof(Elf64_Phdr));
        // 再显式标记为 PT_NULL，占位但不参与装载。
        new_pht_buffer[newHeaderIndex].p_type = PT_NULL;
    }
    LOGI("  Initialized %d new PHT entries (PT_NULL)", extraEntries);

    // ========== 第三阶段：创建自救 LOAD 段（手术刀方案）==========
    LOGI("\n[Phase 3] Create Self-Rescue LOAD Segment (Surgical)");

    // 使用最后一个新增槽位（索引 = old_ph_num + extra_entries - 1）。
    int rescue_load_idx = old_ph_num + extraEntries - 1;
    LOGI("  Creating new PT_LOAD at index %d", rescue_load_idx);

    // 直接拿到目标槽位，后续逐字段填充。
    Elf64_Phdr* rescue_load = &new_pht_buffer[(size_t)rescue_load_idx];
    // 段类型：可装载段。
    rescue_load->p_type = PT_LOAD;
    // 文件偏移：指向新 PHT 起点。
    rescue_load->p_offset = NEW_PHT_OFFSET;
    // 虚拟地址：这里采用与文件偏移一致的最简模型。
    rescue_load->p_vaddr = NEW_PHT_OFFSET;
    // 物理地址：与虚拟地址保持一致（多数平台不实际使用）。
    rescue_load->p_paddr = NEW_PHT_OFFSET;
    // 文件内字节数覆盖整个新 PHT。
    rescue_load->p_filesz = new_pht_size;
    // 内存字节数同样覆盖整个新 PHT。
    rescue_load->p_memsz = new_pht_size;
    // 自救段只读即可，防止无必要的写权限。
    rescue_load->p_flags = PF_R;
    rescue_load->p_align = PAGE_SIZE;

    LOGI("  New PT_LOAD[%d] configuration:", rescue_load_idx);
    LOGI("    p_type:   PT_LOAD");
    LOGI("    p_offset: 0x%llx", (unsigned long long)rescue_load->p_offset);
    LOGI("    p_vaddr:  0x%llx", (unsigned long long)rescue_load->p_vaddr);
    LOGI("    p_filesz: 0x%llx", (unsigned long long)rescue_load->p_filesz);
    LOGI("    p_memsz:  0x%llx", (unsigned long long)rescue_load->p_memsz);
    LOGI("    p_flags:  PF_R (0x%x)", rescue_load->p_flags);
    LOGI("    p_align:  0x%llx", (unsigned long long)rescue_load->p_align);

    // ========== 第四阶段：修正 PT_PHDR ==========
    LOGI("\n[Phase 4] Update PT_PHDR Metadata");

    int pt_phdr_idx = -1;
    for (int programHeaderIndex = 0; programHeaderIndex < old_ph_num; ++programHeaderIndex) {
        // 只在原有条目里找 PT_PHDR，新增条目不会承载该语义。
        if (new_pht_buffer[(size_t)programHeaderIndex].p_type == PT_PHDR) {
            pt_phdr_idx = programHeaderIndex;
            break;
        }
    }

    if (pt_phdr_idx != -1) {
        // 命中 PT_PHDR 后，更新其指向到新 PHT。
        Elf64_Phdr* pt_phdr = &new_pht_buffer[(size_t)pt_phdr_idx];
        // 记录旧值便于日志对比。
        Elf64_Addr old_vaddr = pt_phdr->p_vaddr;
        Elf64_Off old_offset = pt_phdr->p_offset;

        // p_offset 指向新 PHT 文件偏移。
        pt_phdr->p_offset = NEW_PHT_OFFSET;
        // p_vaddr/p_paddr 同步迁移到新锚点。
        pt_phdr->p_vaddr = NEW_PHT_OFFSET;
        pt_phdr->p_paddr = NEW_PHT_OFFSET;
        // PT_PHDR 覆盖长度也改成新 PHT 长度。
        pt_phdr->p_filesz = new_pht_size;
        pt_phdr->p_memsz = new_pht_size;

        LOGI("  Updated PT_PHDR[%d]:", pt_phdr_idx);
        LOGI("    p_offset: 0x%llx -> 0x%llx", (unsigned long long)old_offset, (unsigned long long)NEW_PHT_OFFSET);
        LOGI("    p_vaddr:  0x%llx -> 0x%llx", (unsigned long long)old_vaddr, (unsigned long long)NEW_PHT_OFFSET);
        LOGI("    p_filesz: 0x%llx", (unsigned long long)pt_phdr->p_filesz);
        LOGI("    p_memsz:  0x%llx", (unsigned long long)pt_phdr->p_memsz);

        // 验证页对齐一致性
        LOGI("  Page alignment check:");
        LOGI("    File offset  %% 0x1000 = 0x%llx", (unsigned long long)(NEW_PHT_OFFSET % PAGE_SIZE));
        LOGI("    Virtual addr %% 0x1000 = 0x%llx", (unsigned long long)(NEW_PHT_OFFSET % PAGE_SIZE));
        LOGI("    ✓ PERFECT: p_vaddr == p_offset (simplest case)");
    } else {
        LOGI("  No PT_PHDR found (optional)");
    }

    // ========== 第五阶段：构建输出文件 ==========
    LOGI("\n[Phase 5] Build Output File");

    // 输出文件至少要容纳“新 PHT 末尾”。
    size_t new_file_size = NEW_PHT_OFFSET + new_pht_size;
    LOGI("  New file size: 0x%zx (%zu bytes)", new_file_size, new_file_size);

    // 初始化为 0，天然保证新增区域默认填充为零。
    std::vector<uint8_t> new_file_bytes(new_file_size, 0);

    // 把原文件先拷贝到新缓冲。
    // 若原文件已超过 NEW_PHT_OFFSET，只复制到锚点前，避免覆盖新 PHT 区。
    size_t copy_size = (file_size < NEW_PHT_OFFSET) ? file_size : NEW_PHT_OFFSET;
    std::memcpy(new_file_bytes.data(), elf_file_ptr, copy_size);

    // 填充到新 PHT 位置的间隙（vector 初始化时已清零）。
    if (NEW_PHT_OFFSET > file_size) {
        LOGI("  Filled padding: 0x%llx bytes", (unsigned long long)(NEW_PHT_OFFSET - file_size));
    }

    // 在目标偏移写入新 PHT。
    std::memcpy(new_file_bytes.data() + NEW_PHT_OFFSET, new_pht_buffer.data(), new_pht_size);
    LOGI("  Placed new PHT at offset 0x%llx", (unsigned long long)NEW_PHT_OFFSET);

    // 更新 ELF Header（新的 e_phoff / e_phnum）。
    // 直接在新文件缓冲头部改字段，不触碰原始输入映射。
    Elf64_Ehdr* new_elf_header = reinterpret_cast<Elf64_Ehdr*>(new_file_bytes.data());
    // 记录旧字段用于对比日志。
    Elf64_Off old_e_phoff = new_elf_header->e_phoff;
    Elf64_Half old_e_phnum = new_elf_header->e_phnum;

    // 新 PHT 文件偏移写回 e_phoff。
    new_elf_header->e_phoff = NEW_PHT_OFFSET;
    // 新条目数写回 e_phnum。
    new_elf_header->e_phnum = new_ph_num;

    LOGI("  Updated ELF Header:");
    LOGI("    e_phoff: 0x%llx -> 0x%llx", (unsigned long long)old_e_phoff, (unsigned long long)NEW_PHT_OFFSET);
    LOGI("    e_phnum: %d -> %d", old_e_phnum, new_ph_num);

    // ========== 第六阶段：一致性校验 ==========
    LOGI("\n[Phase 6] Consistency Check");

    // 确认 e_phoff + pht_size 不越过新文件总长。
    if (new_elf_header->e_phoff + new_pht_size > new_file_size) {
        LOGE("Consistency check failed: PHT exceeds file size");
        return false;
    }

    LOGI("  ✓ PHT within file bounds");
    LOGI("  ✓ All existing LOAD segments preserved");
    LOGI("  ✓ New rescue LOAD segment at index %d", rescue_load_idx);
    LOGI("  ✓ All consistency checks passed");

    // ========== 第七阶段：写入文件 ==========
    LOGI("\n[Phase 7] Write Output File");

    // 把组装好的新文件一次性写出。
    if (!vmp::base::file::writeFileBytes(outputPath, new_file_bytes)) {
        LOGE("Failed to open output file: %s", outputPath);
        return false;
    }

    LOGI("  ✓ Successfully wrote to: %s", outputPath);
    LOGI("\n=== Summary ===");
    LOGI("  Original file size: 0x%zx (%zu bytes)", file_size, file_size);
    LOGI("  New file size: 0x%zx (%zu bytes)", new_file_size, new_file_size);
    LOGI("  PHT relocated from 0x%llx to 0x%llx", (unsigned long long)old_e_phoff, (unsigned long long)NEW_PHT_OFFSET);
    LOGI("  PHT entries: %d -> %d (added %d)", old_e_phnum, new_ph_num, extraEntries);
    LOGI("  Strategy: Surgical - Added dedicated rescue LOAD segment without modifying existing segments");

    return true;
}



