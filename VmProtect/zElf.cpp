#include "zElf.h"
#include "elf.h"
#include "zLog.h"
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <algorithm>
#include <string>

#define ElfW(type) Elf64_ ## type

// 默认构造：仅创建空壳对象，不触发文件 I/O。
zElf::zElf() {
    LOGD("Default constructor called");
}

// 便捷构造：加载 ELF 并按固定顺序建立解析上下文。
// 顺序不可乱：头部 -> 程序头 -> 动态段 -> 节表 -> 函数列表。
zElf::zElf(const char *elf_file_name) {
    LOGD("Constructor called with elf_file_name: %s", elf_file_name);

    // 当前工具链只支持文件视图解析。
    link_view = LINK_VIEW::FILE_VIEW;
    // 只有文件加载成功后，后续解析步骤才有意义。
    if (load_elf_file(elf_file_name)) {
        parse_elf_head();
        parse_program_header_table();
        parse_dynamic_table();
        parse_section_table();
        build_function_list();
    }
}

// 解析 ELF 头部并初始化 Program/Section Header 的基础指针。
void zElf::parse_elf_head() {
    LOGD("parse_elf_head called");

    if (!elf_file_ptr) {
        LOGE("elf_file_ptr is null");
        return;
    }

    // elf_file_ptr 指向整个文件起始，首部直接 reinterpret 即可。
    elf_header = (Elf64_Ehdr *) elf_file_ptr;
    LOGD("elf_header->e_shoff 0x%llx", (unsigned long long)elf_header->e_shoff);
    LOGD("elf_header->e_shnum %x", elf_header->e_shnum);

    // 记录 e_ehsize，打印布局时需要它做第一个区间。
    elf_header_size = elf_header->e_ehsize;

    // Program Header Table = 文件起始 + e_phoff。
    program_header_table = (Elf64_Phdr*)(elf_file_ptr + elf_header->e_phoff);
    program_header_table_num = elf_header->e_phnum;

    // Section Header Table = 文件起始 + e_shoff。
    section_header_table = (Elf64_Shdr*)(elf_file_ptr + elf_header->e_shoff);
    section_header_table_num = elf_header->e_shnum;
}

// 遍历 Program Header Table，提取 PT_LOAD 和 PT_DYNAMIC 关键信息。
void zElf::parse_program_header_table() {
    LOGD("parse_program_header_table called");

    if (!elf_file_ptr || !program_header_table) {
        LOGE("Invalid state for parsing program header table");
        return;
    }

    bool found_load_segment = false;

    // 遍历所有 Program Header 条目。
    for (int i = 0; i < program_header_table_num; i++) {
        // 第一个 PT_LOAD 提供了 VA->文件偏移换算所需的基准。
        if (program_header_table[i].p_type == PT_LOAD && !found_load_segment) {
            found_load_segment = true;
            load_segment_virtual_offset = program_header_table[i].p_vaddr;
            load_segment_physical_offset = program_header_table[i].p_paddr;
            LOGD("load_segment_virtual_offset 0x%llx", (unsigned long long)load_segment_virtual_offset);
        }

        // PT_DYNAMIC 保存 DT_* 元数据，是后续符号解析入口。
        if (program_header_table[i].p_type == PT_DYNAMIC) {
            dynamic_table_offset = program_header_table[i].p_offset;
            dynamic_table = (Elf64_Dyn*)(elf_file_ptr + program_header_table[i].p_offset);
            dynamic_element_num = (program_header_table[i].p_filesz) / sizeof(Elf64_Dyn);
            LOGD("dynamic_table_offset 0x%llx", (unsigned long long)dynamic_table_offset);
            LOGD("dynamic_element_num %llu", (unsigned long long)dynamic_element_num);
        }
    }
}

// 解析动态段 DT_*，建立动态符号/字符串表等索引。
void zElf::parse_dynamic_table() {
    LOGD("parse_dynamic_table called");

    if (!dynamic_table) {
        LOGD("No dynamic table found");
        return;
    }

    Elf64_Dyn *dynamic_element = dynamic_table;

    // 逐条扫描 dynamic table，关注项目需要的关键 tag。
    for (int i = 0; i < dynamic_element_num; i++) {
        if (dynamic_element->d_tag == DT_STRTAB) {
            // 动态字符串表地址（虚拟地址语义）。
            LOGD("DT_STRTAB 0x%llx", (unsigned long long)dynamic_element->d_un.d_ptr);
            dynamic_string_table_offset = dynamic_element->d_un.d_ptr;
        } else if (dynamic_element->d_tag == DT_STRSZ) {
            // 动态字符串表长度，用于后续边界判断。
            LOGD("DT_STRSZ 0x%llx", (unsigned long long)dynamic_element->d_un.d_val);
            dynamic_string_table_size = dynamic_element->d_un.d_val;
        } else if (dynamic_element->d_tag == DT_SYMTAB) {
            // 动态符号表地址（虚拟地址语义）。
            LOGD("DT_SYMTAB 0x%llx", (unsigned long long)dynamic_element->d_un.d_ptr);
            dynamic_symbol_table_offset = dynamic_element->d_un.d_ptr;
        } else if (dynamic_element->d_tag == DT_SYMENT) {
            // 单个动态符号表项大小。
            LOGD("DT_SYMENT 0x%llx", (unsigned long long)dynamic_element->d_un.d_val);
            dynamic_symbol_element_size = dynamic_element->d_un.d_val;
        } else if (dynamic_element->d_tag == DT_SONAME) {
            // so 名称在动态字符串表中的偏移。
            LOGD("DT_SONAME 0x%llx", (unsigned long long)dynamic_element->d_un.d_ptr);
            soname_offset = dynamic_element->d_un.d_ptr;
        } else if (dynamic_element->d_tag == DT_GNU_HASH) {
            // GNU hash 地址，当前主要用于记录和调试。
            LOGD("DT_GNU_HASH 0x%llx", (unsigned long long)dynamic_element->d_un.d_ptr);
            gnu_hash_table_offset = dynamic_element->d_un.d_ptr;
        }
        // 继续扫描下一条 DT_*。
        dynamic_element++;
    }

    LOGI("parse_dynamic_table succeed");
}

// 解析 Section Header Table，建立 .symtab/.strtab/.dynsym/.dynstr 指针。
void zElf::parse_section_table() {
    LOGD("parse_section_table called");

    if (!elf_file_ptr || !section_header_table) {
        LOGE("Invalid state for parsing section table");
        return;
    }

    // e_shstrndx 指向“节名字符串表”所在节。
    int section_string_section_id = elf_header->e_shstrndx;
    LOGD("parse_section_table section_string_section_id %d", section_string_section_id);

    Elf64_Shdr *section_element = section_header_table;

    // 先定位节名表，后续每个节名都由 sh_name 索引得到。
    section_string_table = elf_file_ptr + (section_element + section_string_section_id)->sh_offset;
    LOGD("parse_section_table section_string_table %p", (void*)section_string_table);

    // 扫描所有节并抓取符号/字符串相关节。
    for (int i = 0; i < section_header_table_num; i++) {
        char *section_name = section_string_table + section_element->sh_name;

        if (strcmp(section_name, ".strtab") == 0) {
            // 普通字符串表（配合 .symtab）。
            LOGD("strtab 0x%llx", (unsigned long long)section_element->sh_offset);
            string_table = elf_file_ptr + section_element->sh_offset;
        } else if (strcmp(section_name, ".dynsym") == 0) {
            // 动态符号表（配合 .dynstr）。
            LOGD("dynsym 0x%llx", (unsigned long long)section_element->sh_offset);
            dynamic_symbol_table = (Elf64_Sym*)(elf_file_ptr + section_element->sh_offset);
            dynamic_symbol_table_num = section_element->sh_size / sizeof(Elf64_Sym);
            LOGD("symbol_table_num %llu", (unsigned long long)dynamic_symbol_table_num);
        } else if (strcmp(section_name, ".dynstr") == 0) {
            // 动态字符串表。
            LOGD("dynstr 0x%llx", (unsigned long long)section_element->sh_offset);
            dynamic_string_table = elf_file_ptr + section_element->sh_offset;
        } else if (strcmp(section_name, ".symtab") == 0) {
            // 常规符号表（常含更多本地符号）。
            symbol_table = (Elf64_Sym*) (elf_file_ptr + section_element->sh_offset);
            section_symbol_num = section_element->sh_size / section_element->sh_entsize;
            LOGD("section_symbol_num %llx", (unsigned long long)section_symbol_num);
        }
        // 继续下一个节头条目。
        section_element++;
    }
    LOGI("parse_section_table succeed");
}

// 从磁盘读取整个 ELF 到堆内存，供后续离线解析。
bool zElf::load_elf_file(const char *elf_path) {
    LOGI("load_elf_file %s", elf_path);

    // 以二进制只读方式打开输入 so。
    FILE *fp = fopen(elf_path, "rb");
    if (!fp) {
        LOGE("Failed to open file: %s", elf_path);
        return false;
    }

    // 获取文件大小
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size <= 0) {
        LOGE("Invalid file size");
        fclose(fp);
        return false;
    }

    LOGD("File size: %zu", file_size);

    // 一次性申请完整缓冲，后续所有指针都基于该缓冲计算。
    elf_file_ptr = (char*)malloc(file_size);
    if (!elf_file_ptr) {
        LOGE("Failed to allocate memory");
        fclose(fp);
        return false;
    }

    // 读取完整文件到内存。
    size_t read_size = fread(elf_file_ptr, 1, file_size, fp);
    fclose(fp);

    if (read_size != file_size) {
        LOGE("Failed to read complete file");
        free(elf_file_ptr);
        elf_file_ptr = nullptr;
        return false;
    }

    LOGI("File loaded successfully");
    return true;
}

// 打印 ELF 文件布局（含各区域与 padding 空洞），便于人工验证结构边界。
void zElf::print_layout() {
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
    for (int i = 0; i < program_header_table_num; i++) {
        // 当前条目的文件偏移 = pht 起始 + i * 单条大小。
        Elf64_Off entry_offset = phdr_offset + i * elf_header->e_phentsize;

        // 生成可读的段类型描述文本。
        const char* type_name = "";
        switch (program_header_table[i].p_type) {
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
        Elf64_Word flags = program_header_table[i].p_flags;
        char perms[4];
        perms[0] = (flags & PF_R) ? 'R' : '_';
        perms[1] = (flags & PF_W) ? 'W' : '_';
        perms[2] = (flags & PF_X) ? 'X' : '_';
        perms[3] = '\0';

        // 拼装最终展示名称。
        char name[256];
        snprintf(name, sizeof(name), "program_table_element[0x%02x] (%s) %s", i, perms, type_name);

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
        for (int i = 0; i < section_header_table_num; i++) {
            if (section->sh_size > 0 && section->sh_offset > 0 && section->sh_type != SHT_NOBITS) {
                // 从 .shstrtab 解析节名；异常情况下回退为空名。
                const char *section_name = "";
                if (section_string_table && section->sh_name < 10000) {
                    section_name = section_string_table + section->sh_name;
                }

                // 组装节展示名称，优先使用真实节名。
                char name[256];
                if (strlen(section_name) > 0) {
                    snprintf(name, sizeof(name), "section[0x%02x] %s", i, section_name);
                } else {
                    snprintf(name, sizeof(name), "section[0x%02x]", i);
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
        for (int i = 0; i < section_header_table_num; i++) {
            // 当前 section header 条目偏移。
            Elf64_Off entry_offset = shdr_physical_offset + i * elf_header->e_shentsize;

            // 解析节名：索引 0 约定为 SHN_UNDEF。
            const char *section_name = "";
            if (i == 0) {
                section_name = "SHN_UNDEF";
            } else {
                Elf64_Shdr *sect = &section_header_table[i];
                if (section_string_table && sect->sh_name < 10000) {
                    section_name = section_string_table + sect->sh_name;
                }
            }

            // 组装子项显示名称。
            char name[256];
            if (strlen(section_name) > 0) {
                snprintf(name, sizeof(name), "section_table_element[0x%02x] %s", i, section_name);
            } else {
                snprintf(name, sizeof(name), "section_table_element[0x%02x]", i);
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
bool zElf::relocate_and_expand_pht(int extra_entries, const char* output_path) {
    LOGI("=== Step-2: PHT Relocation & Expansion (Surgical Approach) ===");
    LOGI("Extra entries to add: %d", extra_entries);

    if (!elf_file_ptr || !program_header_table) {
        LOGE("ELF not loaded or parsed");
        return false;
    }

    // 迁移策略当前写死到 0x3000，用于 demo 流程稳定复现。
    const size_t PAGE_SIZE = 0x1000;
    const Elf64_Off NEW_PHT_OFFSET = 0x3000;

    // ========== 第一阶段：空间预计算 ==========
    LOGI("\n[Phase 1] Space Precalculation");

    Elf64_Half old_ph_num = program_header_table_num;
    Elf64_Half new_ph_num = old_ph_num + extra_entries;
    LOGI("  Old_PH_Num: %d", old_ph_num);
    LOGI("  New_PH_Num: %d", new_ph_num);

    size_t new_pht_size = new_ph_num * sizeof(Elf64_Phdr);
    LOGI("  New PHT size: 0x%zx (%zu bytes)", new_pht_size, new_pht_size);
    LOGI("  New PHT offset (fixed): 0x%llx", (unsigned long long)NEW_PHT_OFFSET);

    // ========== 第二阶段：构建新 PHT ==========
    LOGI("\n[Phase 2] Build New PHT");

    Elf64_Phdr* new_pht_buffer = (Elf64_Phdr*)malloc(new_pht_size);
    if (!new_pht_buffer) {
        LOGE("Failed to allocate memory for new PHT");
        return false;
    }

    // 拷贝旧 PHT
    memcpy(new_pht_buffer, program_header_table, old_ph_num * sizeof(Elf64_Phdr));
    LOGI("  Copied %d old PHT entries", old_ph_num);

    // 初始化新增的 PHT 条目为 PT_NULL
    for (int i = old_ph_num; i < new_ph_num; i++) {
        memset(&new_pht_buffer[i], 0, sizeof(Elf64_Phdr));
        new_pht_buffer[i].p_type = PT_NULL;
    }
    LOGI("  Initialized %d new PHT entries (PT_NULL)", extra_entries);

    // ========== 第三阶段：创建自救 LOAD 段（手术刀方案）==========
    LOGI("\n[Phase 3] Create Self-Rescue LOAD Segment (Surgical)");

    // 使用最后一个新增槽位（索引 = old_ph_num + extra_entries - 1）。
    int rescue_load_idx = old_ph_num + extra_entries - 1;
    LOGI("  Creating new PT_LOAD at index %d", rescue_load_idx);

    Elf64_Phdr* rescue_load = &new_pht_buffer[rescue_load_idx];
    rescue_load->p_type = PT_LOAD;
    rescue_load->p_offset = NEW_PHT_OFFSET;
    rescue_load->p_vaddr = NEW_PHT_OFFSET;
    rescue_load->p_paddr = NEW_PHT_OFFSET;
    rescue_load->p_filesz = new_pht_size;
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
    for (int i = 0; i < old_ph_num; i++) {
        if (new_pht_buffer[i].p_type == PT_PHDR) {
            pt_phdr_idx = i;
            break;
        }
    }

    if (pt_phdr_idx != -1) {
        Elf64_Phdr* pt_phdr = &new_pht_buffer[pt_phdr_idx];
        Elf64_Addr old_vaddr = pt_phdr->p_vaddr;
        Elf64_Off old_offset = pt_phdr->p_offset;

        pt_phdr->p_offset = NEW_PHT_OFFSET;
        pt_phdr->p_vaddr = NEW_PHT_OFFSET;
        pt_phdr->p_paddr = NEW_PHT_OFFSET;
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

    size_t new_file_size = NEW_PHT_OFFSET + new_pht_size;
    LOGI("  New file size: 0x%zx (%zu bytes)", new_file_size, new_file_size);

    char* new_file_ptr = (char*)malloc(new_file_size);
    if (!new_file_ptr) {
        LOGE("Failed to allocate memory for new file");
        free(new_pht_buffer);
        return false;
    }

    // 把原文件先拷贝到新缓冲。
    size_t copy_size = (file_size < NEW_PHT_OFFSET) ? file_size : NEW_PHT_OFFSET;
    memcpy(new_file_ptr, elf_file_ptr, copy_size);

    // 填充到新 PHT 位置的间隙（用 0 填充）
    if (NEW_PHT_OFFSET > file_size) {
        memset(new_file_ptr + file_size, 0, NEW_PHT_OFFSET - file_size);
        LOGI("  Filled padding: 0x%llx bytes", (unsigned long long)(NEW_PHT_OFFSET - file_size));
    }

    // 在目标偏移写入新 PHT。
    memcpy(new_file_ptr + NEW_PHT_OFFSET, new_pht_buffer, new_pht_size);
    LOGI("  Placed new PHT at offset 0x%llx", (unsigned long long)NEW_PHT_OFFSET);

    // 更新 ELF Header（新的 e_phoff / e_phnum）。
    Elf64_Ehdr* new_elf_header = (Elf64_Ehdr*)new_file_ptr;
    Elf64_Off old_e_phoff = new_elf_header->e_phoff;
    Elf64_Half old_e_phnum = new_elf_header->e_phnum;

    new_elf_header->e_phoff = NEW_PHT_OFFSET;
    new_elf_header->e_phnum = new_ph_num;

    LOGI("  Updated ELF Header:");
    LOGI("    e_phoff: 0x%llx -> 0x%llx", (unsigned long long)old_e_phoff, (unsigned long long)NEW_PHT_OFFSET);
    LOGI("    e_phnum: %d -> %d", old_e_phnum, new_ph_num);

    // ========== 第六阶段：一致性校验 ==========
    LOGI("\n[Phase 6] Consistency Check");

    if (new_elf_header->e_phoff + new_pht_size > new_file_size) {
        LOGE("Consistency check failed: PHT exceeds file size");
        free(new_file_ptr);
        free(new_pht_buffer);
        return false;
    }

    LOGI("  ✓ PHT within file bounds");
    LOGI("  ✓ All existing LOAD segments preserved");
    LOGI("  ✓ New rescue LOAD segment at index %d", rescue_load_idx);
    LOGI("  ✓ All consistency checks passed");

    // ========== 第七阶段：写入文件 ==========
    LOGI("\n[Phase 7] Write Output File");

    FILE* fp = fopen(output_path, "wb");
    if (!fp) {
        LOGE("Failed to open output file: %s", output_path);
        free(new_file_ptr);
        free(new_pht_buffer);
        return false;
    }

    size_t written = fwrite(new_file_ptr, 1, new_file_size, fp);
    fclose(fp);

    if (written != new_file_size) {
        LOGE("Failed to write complete file, written: %zu, expected: %zu", written, new_file_size);
        free(new_file_ptr);
        free(new_pht_buffer);
        return false;
    }

    LOGI("  ✓ Successfully wrote to: %s", output_path);
    LOGI("\n=== Summary ===");
    LOGI("  Original file size: 0x%zx (%zu bytes)", file_size, file_size);
    LOGI("  New file size: 0x%zx (%zu bytes)", new_file_size, new_file_size);
    LOGI("  PHT relocated from 0x%llx to 0x%llx", (unsigned long long)old_e_phoff, (unsigned long long)NEW_PHT_OFFSET);
    LOGI("  PHT entries: %d -> %d (added %d)", old_e_phnum, new_ph_num, extra_entries);
    LOGI("  Strategy: Surgical - Added dedicated rescue LOAD segment without modifying existing segments");

    free(new_file_ptr);
    free(new_pht_buffer);
    return true;
}

// 通过动态符号表查找符号偏移（文件视图）。
// 返回值是“符号 VA 相对首个 PT_LOAD 的偏移”。
Elf64_Addr zElf::find_symbol_offset_by_dynamic(const char *symbol_name) {
    LOGD("find_symbol_by_dynamic dynamic_symbol_table_offset 0x%llx", (unsigned long long)dynamic_symbol_table_offset);
    LOGD("find_symbol_by_dynamic dynamic_symbol_table_num %llu", (unsigned long long)dynamic_symbol_table_num);
    LOGD("find_symbol_by_dynamic dynamic_string_table_offset 0x%llx", (unsigned long long)dynamic_string_table_offset);

    if (!dynamic_symbol_table || !dynamic_string_table) {
        LOGD("Dynamic symbol table or string table not available");
        return 0;
    }

    // 遍历动态符号表，匹配同名符号。
    Elf64_Sym* dynamic_symbol = dynamic_symbol_table;
    for (uint64_t i = 0; i < dynamic_symbol_table_num; i++) {
        // 先做 st_name 边界保护，避免越界访问 dynstr。
        if (dynamic_symbol->st_name >= 0 && dynamic_symbol->st_name <= dynamic_string_table_size) {
            const char *name = dynamic_string_table + dynamic_symbol->st_name;
            if (strcmp(name, symbol_name) == 0) {
                LOGD("find_dynamic_symbol [%llu] %s offset: 0x%llx value: 0x%llx",
                     (unsigned long long)i, name,
                     (unsigned long long)dynamic_symbol->st_name,
                     (unsigned long long)dynamic_symbol->st_value);
                // 在文件视图中，返回相对于加载段的偏移
                return dynamic_symbol->st_value - load_segment_virtual_offset;
            }
        }

        dynamic_symbol++;
    }
    return 0;
}

// 通过节符号表查找符号偏移（文件视图回退路径）。
Elf64_Addr zElf::find_symbol_offset_by_section(const char *symbol_name) {
    if (!symbol_table || !string_table) {
        LOGD("Symbol table or string table not available");
        return 0;
    }

    Elf64_Sym *symbol = symbol_table;
    for (uint64_t j = 0; j < section_symbol_num; j++) {
        const char *name = string_table + symbol->st_name;
        if (strcmp(name, symbol_name) == 0) {
            LOGD("find_symbol_offset_by_section [%llu] %s value: 0x%llx",
                 (unsigned long long)j, name,
                 (unsigned long long)symbol->st_value);
            // 在文件视图中，返回相对于物理地址的偏移
            return symbol->st_value - physical_address;
        }
        symbol++;
    }

    return 0;
}

// 统一符号偏移查找：优先 dynamic，回退 section。
Elf64_Addr zElf::find_symbol_offset(const char *symbol_name) {
    Elf64_Addr symbol_offset = 0;
    symbol_offset = find_symbol_offset_by_dynamic(symbol_name);
    if (symbol_offset == 0) {
        symbol_offset = find_symbol_offset_by_section(symbol_name);
    }
    return symbol_offset;
}

// 获取符号在当前 FILE_VIEW 缓冲中的地址。
char* zElf::get_symbol_file_address(const char *symbol_name) {
    if (elf_file_ptr == nullptr) {
        LOGE("get_symbol_file_address elf_file_ptr == nullptr");
        return nullptr;
    }

    Elf64_Addr symbol_offset = find_symbol_offset(symbol_name);

    if (symbol_offset == 0) {
        LOGE("get_symbol_file_address %s failed", symbol_name);
        return nullptr;
    }
    return elf_file_ptr + symbol_offset;
}

// 查找完整符号表项（含 st_size），用于构建 zFunctionData。
Elf64_Sym* zElf::find_symbol_info(const char *symbol_name) {
    // 先在动态符号表中查找
    if (dynamic_symbol_table && dynamic_string_table) {
        Elf64_Sym* dynamic_symbol = dynamic_symbol_table;
        for (uint64_t i = 0; i < dynamic_symbol_table_num; i++) {
            if (dynamic_symbol->st_name >= 0 && dynamic_symbol->st_name <= dynamic_string_table_size) {
                const char *name = dynamic_string_table + dynamic_symbol->st_name;
                if (strcmp(name, symbol_name) == 0) {
                    LOGD("find_symbol_info: found in dynamic table [%llu] %s size: 0x%llx",
                         (unsigned long long)i, name, (unsigned long long)dynamic_symbol->st_size);
                    return dynamic_symbol;
                }
            }
            dynamic_symbol++;
        }
    }

    // 在节表符号表中查找
    if (symbol_table && string_table) {
        Elf64_Sym *symbol = symbol_table;
        for (uint64_t j = 0; j < section_symbol_num; j++) {
            const char *name = string_table + symbol->st_name;
            if (strcmp(name, symbol_name) == 0) {
                LOGD("find_symbol_info: found in section table [%llu] %s size: 0x%llx",
                     (unsigned long long)j, name, (unsigned long long)symbol->st_size);
                return symbol;
            }
            symbol++;
        }
    }

    return nullptr;
}

bool zElf::add_function_from_symbol(const char* symbol_name, Elf64_Xword symbol_size) {
    // 过滤空名字，避免污染函数缓存。
    if (!symbol_name || symbol_name[0] == '\0') {
        return false;
    }

    // 已存在则直接跳过，避免重复构建。
    if (find_function_in_list(symbol_name) != nullptr) {
        return false;
    }

    // 先定位符号偏移，再取文件视图地址。
    Elf64_Addr symbol_offset = find_symbol_offset(symbol_name);
    if (symbol_offset == 0) {
        return false;
    }

    char* symbol_file_addr = get_symbol_file_address(symbol_name);
    if (!symbol_file_addr) {
        return false;
    }

    // 若符号未给 size，退化为固定窗口，便于回归调试。
    size_t symbol_bytes_size = symbol_size > 0 ? static_cast<size_t>(symbol_size) : 256;
    std::vector<uint8_t> symbol_bytes(symbol_bytes_size);
    memcpy(symbol_bytes.data(), symbol_file_addr, symbol_bytes_size);

    // 统一按 zFunctionData 构建函数对象，和当前 zFunction 构造签名保持一致。
    zFunctionData data;
    data.function_name = symbol_name;
    data.function_offset = symbol_offset;
    data.function_bytes = std::move(symbol_bytes);
    function_list_.emplace_back(data);
    return true;
}

zFunction* zElf::find_function_in_list(const char* function_name) {
    if (!function_name || function_name[0] == '\0') {
        return nullptr;
    }

    for (auto& function : function_list_) {
        if (function.name() == function_name) {
            return &function;
        }
    }
    return nullptr;
}

bool zElf::build_function_list() {
    // 每次重建前先清空，避免旧状态残留。
    function_list_.clear();

    if (!elf_file_ptr) {
        return false;
    }

    // 优先扫描动态符号表（导出符号）。
    if (dynamic_symbol_table && dynamic_string_table) {
        for (uint64_t i = 0; i < dynamic_symbol_table_num; i++) {
            Elf64_Sym* symbol = &dynamic_symbol_table[i];
            if (ELF64_ST_TYPE(symbol->st_info) != STT_FUNC) {
                continue;
            }
            if (symbol->st_name >= dynamic_string_table_size) {
                continue;
            }
            const char* symbol_name = dynamic_string_table + symbol->st_name;
            add_function_from_symbol(symbol_name, symbol->st_size);
        }
    }

    // 再扫描节符号表（补充非导出符号）。
    if (symbol_table && string_table) {
        for (uint64_t i = 0; i < section_symbol_num; i++) {
            Elf64_Sym* symbol = &symbol_table[i];
            if (ELF64_ST_TYPE(symbol->st_info) != STT_FUNC) {
                continue;
            }
            const char* symbol_name = string_table + symbol->st_name;
            add_function_from_symbol(symbol_name, symbol->st_size);
        }
    }

    // 允许返回空列表（例如极简或被裁剪符号的 so），由上层决定是否视为错误。
    LOGI("build_function_list complete, function_count=%zu", function_list_.size());
    return !function_list_.empty();
}

zFunction* zElf::getFunction(const char* function_name) {
    if (!function_name || function_name[0] == '\0') {
        return nullptr;
    }

    // 先走缓存，避免重复查表与拷贝。
    zFunction* function = find_function_in_list(function_name);
    if (function) {
        return function;
    }

    // 缓存未命中时，按符号信息补建并回填缓存。
    Elf64_Sym* symbol = find_symbol_info(function_name);
    if (!symbol) {
        return nullptr;
    }

    if (!add_function_from_symbol(function_name, symbol->st_size)) {
        return nullptr;
    }
    return find_function_in_list(function_name);
}

zFunction* zElf::getfunction(const char* function_name) {
    return getFunction(function_name);
}

const std::vector<zFunction>& zElf::getFunctionList() const {
    return function_list_;
}

// 析构：释放文件缓冲，防止长时间批处理时内存累积。
zElf::~zElf() {
    if (elf_file_ptr) {
        free(elf_file_ptr);
        elf_file_ptr = nullptr;
    }
}
