/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - ELF 解析核心，实现符号/段/动态表读取与函数抽取。
 * - 加固链路位置：离线翻译前置基础设施。
 * - 输入：目标 so 文件字节。
 * - 输出：zFunction 对象列表与函数地址映射。
 */
#include "zElf.h"
// ELF 常量与类型定义。
#include "zElfTypes.h"
// ELF 文件读取与范围校验工具。
#include "zElfFile.h"
// 日志输出。
#include "zLog.h"
// memcpy。
#include <cstring>
// 整型类型。
#include <cstdint>
// malloc/free。
#include <cstdlib>
// 错误信息字符串。
#include <string>
// 文件字节缓存。
#include <vector>

// 兼容历史宏：统一使用 64 位 ELF 类型。
#define ElfW(type) Elf64_ ## type

// 默认构造：仅创建空壳对象，不触发文件 I/O。
zElf::zElf() {
    LOGD("Default constructor called");
}

// 便捷构造：加载 ELF 并按固定顺序建立解析上下文。
// 顺序不可乱：头部 -> 程序头 -> 动态段 -> 节表 -> 函数列表。
zElf::zElf(const char *elfFileName) {
    // 打印输入文件名，便于多文件批处理定位问题。
    LOGD("Constructor called with elf_file_name: %s", elfFileName);

    // 当前工具链只支持文件视图解析。
    link_view = LINK_VIEW::FILE_VIEW;
    // 文件加载成功后才继续后续解析。
    if (loadElfFile(elfFileName)) {
        // 解析 ELF 头。
        parseElfHead();
        // 解析 Program Header Table。
        parseProgramHeaderTable();
        // 解析 DT_* 动态表。
        parseDynamicTable();
        // 解析 Section Header Table。
        parseSectionTable();
        // 最后构建函数列表缓存。
        buildFunctionList();
    }
}

// 解析 ELF 头部并初始化 Program/Section Header 的基础指针。
void zElf::parseElfHead() {
    // 记录入口日志。
    LOGD("parseElfHead called");

    // 文件缓冲为空时无法解析。
    if (!elf_file_ptr) {
        LOGE("elf_file_ptr is null");
        return;
    }

    // 临时错误字符串。
    std::string elf_error;
    // 解析统一 ELF 文件视图（含头表边界校验）。
    vmp::elfkit::internal::ElfFileView64 elfView;
    if (!vmp::elfkit::internal::parseElfFileView64Aarch64(
            reinterpret_cast<const uint8_t*>(elf_file_ptr), file_size, &elfView, &elf_error)) {
        LOGE("invalid elf header: %s", elf_error.c_str());
        return;
    }

    // 文件起始地址即 ELF Header 起始地址。
    elf_header = (Elf64_Ehdr*)elfView.elfHeader;
    // 打印节头表偏移。
    LOGD("elf_header->e_shoff 0x%llx", (unsigned long long)elf_header->e_shoff);
    // 打印节头数量。
    LOGD("elf_header->e_shnum %x", elf_header->e_shnum);

    // 记录 ELF Header 长度，布局打印时会用到。
    elf_header_size = elf_header->e_ehsize;
    // 从共享视图回填 PHT/SHT 信息，避免重复解析。
    program_header_table = const_cast<Elf64_Phdr*>(elfView.programHeaders);
    program_header_table_num = elfView.programHeaderCount;
    section_header_table = const_cast<Elf64_Shdr*>(elfView.sectionHeaders);
    section_header_table_num = elfView.sectionHeaderCount;
}

// 遍历 Program Header Table，提取 PT_LOAD 和 PT_DYNAMIC 关键信息。
void zElf::parseProgramHeaderTable() {
    // 记录入口日志。
    LOGD("parseProgramHeaderTable called");

    // 基础状态检查：文件与 PHT 指针都必须可用。
    if (!elf_file_ptr || !program_header_table) {
        LOGE("Invalid state for parsing program header table");
        return;
    }

    // 首个 PT_LOAD 仅记录一次。
    bool found_load_segment = false;

    // 遍历全部 Program Header 条目。
    for (int programHeaderIndex = 0; programHeaderIndex < program_header_table_num; ++programHeaderIndex) {
        // 第一个 PT_LOAD 提供 VA->文件偏移换算基准。
        if (program_header_table[programHeaderIndex].p_type == PT_LOAD && !found_load_segment) {
            // 标记已命中首个 LOAD 段。
            found_load_segment = true;
            // 记录 LOAD 段虚拟地址基准。
            load_segment_virtual_offset = program_header_table[programHeaderIndex].p_vaddr;
            // 记录 LOAD 段物理地址基准。
            load_segment_physical_offset = program_header_table[programHeaderIndex].p_paddr;
            LOGD("load_segment_virtual_offset 0x%llx", (unsigned long long)load_segment_virtual_offset);
        }

        // PT_DYNAMIC 给出 DT_* 元数据入口。
        if (program_header_table[programHeaderIndex].p_type == PT_DYNAMIC) {
            // 保存动态段文件偏移。
            dynamic_table_offset = program_header_table[programHeaderIndex].p_offset;
            // 计算动态段起始指针。
            dynamic_table = (Elf64_Dyn*)(elf_file_ptr + program_header_table[programHeaderIndex].p_offset);
            // 计算动态表项数量。
            dynamic_element_num = (program_header_table[programHeaderIndex].p_filesz) / sizeof(Elf64_Dyn);
            LOGD("dynamic_table_offset 0x%llx", (unsigned long long)dynamic_table_offset);
            LOGD("dynamic_element_num %llu", (unsigned long long)dynamic_element_num);
        }
    }
}

// 解析动态段 DT_*，建立动态符号/字符串表等索引。
void zElf::parseDynamicTable() {
    // 记录入口日志。
    LOGD("parseDynamicTable called");

    // 没有动态段时直接返回。
    if (!dynamic_table) {
        LOGD("No dynamic table found");
        return;
    }

    // 指向当前扫描的动态表项。
    Elf64_Dyn *dynamic_element = dynamic_table;

    // 顺序扫描全部 DT_* 表项。
    for (int dynamicIndex = 0; dynamicIndex < dynamic_element_num; ++dynamicIndex) {
        // 动态字符串表地址。
        if (dynamic_element->d_tag == DT_STRTAB) {
            LOGD("DT_STRTAB 0x%llx", (unsigned long long)dynamic_element->d_un.d_ptr);
            dynamic_string_table_offset = dynamic_element->d_un.d_ptr;
        // 动态字符串表长度。
        } else if (dynamic_element->d_tag == DT_STRSZ) {
            LOGD("DT_STRSZ 0x%llx", (unsigned long long)dynamic_element->d_un.d_val);
            dynamic_string_table_size = dynamic_element->d_un.d_val;
        // 动态符号表地址。
        } else if (dynamic_element->d_tag == DT_SYMTAB) {
            LOGD("DT_SYMTAB 0x%llx", (unsigned long long)dynamic_element->d_un.d_ptr);
            dynamic_symbol_table_offset = dynamic_element->d_un.d_ptr;
        // 动态符号单项大小。
        } else if (dynamic_element->d_tag == DT_SYMENT) {
            LOGD("DT_SYMENT 0x%llx", (unsigned long long)dynamic_element->d_un.d_val);
            dynamic_symbol_element_size = dynamic_element->d_un.d_val;
        // SONAME 在 dynstr 中的偏移。
        } else if (dynamic_element->d_tag == DT_SONAME) {
            LOGD("DT_SONAME 0x%llx", (unsigned long long)dynamic_element->d_un.d_ptr);
            soname_offset = dynamic_element->d_un.d_ptr;
        // GNU hash 地址。
        } else if (dynamic_element->d_tag == DT_GNU_HASH) {
            LOGD("DT_GNU_HASH 0x%llx", (unsigned long long)dynamic_element->d_un.d_ptr);
            gnu_hash_table_offset = dynamic_element->d_un.d_ptr;
        }
        // 前进到下一条动态表项。
        dynamic_element++;
    }

    // 动态表解析完成。
    LOGI("parseDynamicTable succeed");
}

// 解析 Section Header Table，建立 .symtab/.strtab/.dynsym/.dynstr 指针。
void zElf::parseSectionTable() {
    // 记录入口日志。
    LOGD("parseSectionTable called");

    // 文件缓冲或 SHT 指针无效时无法继续。
    if (!elf_file_ptr || !section_header_table) {
        LOGE("Invalid state for parsing section table");
        return;
    }

    // e_shstrndx 给出“节名字符串表”所在 section 索引。
    int section_string_section_id = elf_header->e_shstrndx;
    LOGD("parseSectionTable section_string_section_id %d", section_string_section_id);

    // 指向 section header 首项。
    Elf64_Shdr *section_element = section_header_table;

    // 根据 shstrtab 节偏移得到节名字符串表基址。
    section_string_table = elf_file_ptr + (section_element + section_string_section_id)->sh_offset;
    LOGD("parseSectionTable section_string_table %p", (void*)section_string_table);

    // 扫描所有 section，抓取符号/字符串相关节。
    for (int sectionIndex = 0; sectionIndex < section_header_table_num; ++sectionIndex) {
        // 当前 section 名称。
        char *section_name = section_string_table + section_element->sh_name;

        // 普通字符串表 .strtab。
        if (strcmp(section_name, ".strtab") == 0) {
            LOGD("strtab 0x%llx", (unsigned long long)section_element->sh_offset);
            string_table = elf_file_ptr + section_element->sh_offset;
        // 动态符号表 .dynsym。
        } else if (strcmp(section_name, ".dynsym") == 0) {
            LOGD("dynsym 0x%llx", (unsigned long long)section_element->sh_offset);
            dynamic_symbol_table = (Elf64_Sym*)(elf_file_ptr + section_element->sh_offset);
            dynamic_symbol_table_num = section_element->sh_size / sizeof(Elf64_Sym);
            LOGD("symbol_table_num %llu", (unsigned long long)dynamic_symbol_table_num);
        // 动态字符串表 .dynstr。
        } else if (strcmp(section_name, ".dynstr") == 0) {
            LOGD("dynstr 0x%llx", (unsigned long long)section_element->sh_offset);
            dynamic_string_table = elf_file_ptr + section_element->sh_offset;
        // 常规符号表 .symtab。
        } else if (strcmp(section_name, ".symtab") == 0) {
            symbol_table = (Elf64_Sym*) (elf_file_ptr + section_element->sh_offset);
            section_symbol_num = section_element->sh_size / section_element->sh_entsize;
            LOGD("section_symbol_num %llx", (unsigned long long)section_symbol_num);
        }
        // 前进到下一条 section header。
        section_element++;
    }
    // 节表解析完成。
    LOGI("parseSectionTable succeed");
}

// 从磁盘读取整个 ELF 到堆内存，供后续离线解析。
bool zElf::loadElfFile(const char *elfPath) {
    // 打印输入路径。
    LOGI("loadElfFile %s", elfPath);
    // 错误信息缓存。
    std::string elf_error;
    // 临时字节缓冲。
    std::vector<uint8_t> loaded_bytes;
    // 读取文件字节。
    if (!vmp::elfkit::internal::loadElfFileBytes(elfPath, &loaded_bytes, &elf_error)) {
        LOGE("Failed to load elf bytes: %s", elf_error.c_str());
        return false;
    }
    // 读取后先做格式校验。
    if (!vmp::elfkit::internal::validateElf64Aarch64(
            loaded_bytes.data(), loaded_bytes.size(), &elf_error)) {
        LOGE("Failed to validate elf format: %s", elf_error.c_str());
        return false;
    }
    // 输出文件大小。
    LOGD("File size: %zu", loaded_bytes.size());

    // 允许同一实例重复 load：先释放旧缓冲。
    if (elf_file_ptr) {
        free(elf_file_ptr);
        elf_file_ptr = nullptr;
        file_size = 0;
    }

    // 记录新文件大小。
    file_size = loaded_bytes.size();
    // 申请堆内存保存整份 ELF。
    elf_file_ptr = (char*)malloc(file_size);
    // 申请失败时回滚大小并失败返回。
    if (!elf_file_ptr) {
        LOGE("Failed to allocate memory");
        file_size = 0;
        return false;
    }
    // 复制字节到内部缓冲。
    std::memcpy(elf_file_ptr, loaded_bytes.data(), file_size);

    // 加载完成。
    LOGI("File loaded successfully");
    return true;
}

// 析构：释放文件缓冲，防止批处理常驻时内存累积。
zElf::~zElf() {
    // 只有非空时才释放。
    if (elf_file_ptr) {
        free(elf_file_ptr);
        elf_file_ptr = nullptr;
    }
}
