#ifndef OVERT_ZELF_H
#define OVERT_ZELF_H

#include "elf.h"
#include "zFunction.h"
#include <cstddef>
#include <cstdint>
#include <vector>

// zElf 负责把磁盘上的 ELF 文件加载到内存并建立解析视图。
// 当前项目只面向 FILE_VIEW（文件字节视角），用于：
// 1) 解析符号与函数体；
// 2) 导出 zFunction 数据给 VmProtect 编码流程；
// 3) 执行 PHT 迁移/扩容等离线改写。
class zElf {
public:
    // 链接视图模式：当前仅实现 FILE_VIEW。
    enum LINK_VIEW {
        FILE_VIEW,    // 以文件偏移解释地址。
        UNKNOWN_VIEW  // 未初始化或不支持模式。
    };

    // 当前实例使用的解析视图。
    LINK_VIEW link_view = UNKNOWN_VIEW;

    // 整个 ELF 文件映射到堆内存后的首地址（malloc 分配，析构时 free）。
    char* elf_file_ptr = nullptr;
    // ELF 文件总字节数。
    size_t file_size = 0;

    // 默认构造：仅保留空对象，不自动加载文件。
    zElf();
    // 便捷构造：加载文件并串行执行 parse_*。
    zElf(const char* elf_file_name);
    // 析构：释放 elf_file_ptr 持有的文件缓存。
    ~zElf();

    // ELF Header 指针（位于 elf_file_ptr 起始）。
    Elf64_Ehdr* elf_header = nullptr;
    // Program Header Table 首地址。
    Elf64_Phdr* program_header_table = nullptr;
    // Program Header Table 条目数（e_phnum）。
    Elf64_Half program_header_table_num = 0;
    // ELF Header 大小（e_ehsize）。
    Elf64_Half elf_header_size = 0;
    // 解析 ELF Header，初始化基础指针和数量字段。
    void parse_elf_head();

    // 首个 PT_LOAD 的虚拟地址（用于 VA->文件偏移换算）。
    Elf64_Addr load_segment_virtual_offset = 0;
    // 首个 PT_LOAD 的物理地址（某些符号回退路径会使用）。
    Elf64_Addr load_segment_physical_offset = 0;
    // PT_DYNAMIC 的文件偏移。
    Elf64_Addr dynamic_table_offset = 0;
    // 动态段表首地址（指向 elf_file_ptr 内部）。
    Elf64_Dyn* dynamic_table = nullptr;
    // 动态段条目总数。
    Elf64_Xword dynamic_element_num = 0;
    // 遍历 Program Header Table，提取 PT_LOAD/PT_DYNAMIC 信息。
    void parse_program_header_table();

    // 节名称字符串表（.shstrtab）起始地址。
    char* section_string_table = nullptr;
    // 节头表首地址（Section Header Table）。
    Elf64_Shdr* section_header_table = nullptr;
    // 节头条目数量（e_shnum）。
    Elf64_Half section_header_table_num = 0;
    // .symtab 符号数量。
    Elf64_Xword section_symbol_num = 0;
    // .strtab 字符串表首地址（配合 .symtab 使用）。
    char* string_table = nullptr;
    // .symtab 符号表首地址。
    Elf64_Sym* symbol_table = nullptr;
    // 遍历节头表，提取 .symtab/.strtab/.dynsym/.dynstr 等信息。
    void parse_section_table();

    // DT_SYMTAB 指向的动态符号表虚拟地址（原值）。
    Elf64_Addr dynamic_symbol_table_offset = 0;
    // 动态符号表首地址（在 FILE_VIEW 下指向文件中对应区间）。
    Elf64_Sym* dynamic_symbol_table = nullptr;
    // 动态符号条目数量。
    Elf64_Xword dynamic_symbol_table_num = 0;
    // 动态符号单条大小（DT_SYMENT）。
    Elf64_Xword dynamic_symbol_element_size = 0;
    // DT_STRTAB 指向的动态字符串表虚拟地址（原值）。
    Elf64_Addr dynamic_string_table_offset = 0;
    // 动态字符串表首地址。
    char* dynamic_string_table = nullptr;
    // 动态字符串表总大小（DT_STRSZ）。
    unsigned long long dynamic_string_table_size = 0;

    // DT_SONAME 在动态字符串表中的偏移。
    Elf64_Addr soname_offset = 0;
    // so 名称指针（当前主要用于调试输出）。
    char* so_name = nullptr;
    // DT_GNU_HASH 的地址（原值）。
    Elf64_Addr gnu_hash_table_offset = 0;
    // GNU hash 表地址（当前仅记录，不参与完整查找流程）。
    char* gnu_hash_table = nullptr;
    // 解析 DT_* 条目并回填动态表相关字段。
    void parse_dynamic_table();

    // 从磁盘读取 ELF 文件到 elf_file_ptr。
    bool load_elf_file(const char* elf_path);

    // 打印文件布局（按地址排序，含 padding 区段）。
    void print_layout();

    // 第二阶段：迁移并扩容 Program Header Table。
    // 会输出改写后的新文件，不直接原地修改源文件。
    bool relocate_and_expand_pht(int extra_entries, const char* output_path);

    // 从动态符号表路径查找符号“文件内偏移”。
    Elf64_Addr find_symbol_offset_by_dynamic(const char* symbol_name);
    // 从节符号表路径查找符号“文件内偏移”。
    Elf64_Addr find_symbol_offset_by_section(const char* symbol_name);
    // 统一查找入口：先 dynamic 再 section。
    Elf64_Addr find_symbol_offset(const char* symbol_name);

    // 获取符号在 FILE_VIEW 下对应的内存指针（elf_file_ptr + offset）。
    char* get_symbol_file_address(const char* symbol_name);

    // 获取符号元信息（含 st_size），优先 dynamic，回退 section。
    Elf64_Sym* find_symbol_info(const char* symbol_name);

    // 扫描符号表并构建 function_list_ 缓存。
    bool build_function_list();
    // 规范命名入口：查询/构建目标函数对象。
    zFunction* getFunction(const char* function_name);
    // 历史兼容入口：等价于 getFunction（保留旧调用点）。
    zFunction* getfunction(const char* function_name);
    // 只读访问当前已构建的函数列表。
    const std::vector<zFunction>& getFunctionList() const;

private:
    // 按符号名称和大小构建 zFunction，并写入 function_list_。
    bool add_function_from_symbol(const char* symbol_name, Elf64_Xword symbol_size);
    // 在 function_list_ 里按名称检索已有函数。
    zFunction* find_function_in_list(const char* function_name);

    // .strtab 的文件偏移（当前主要用于调试）。
    Elf64_Addr string_table_offset = 0;
    // 字符串表编号（历史字段，当前流程未深度使用）。
    int string_table_num = 0;
    // 物理地址基准（section 符号偏移回退使用）。
    Elf64_Addr physical_address = 0;
    // 已解析函数缓存，生命周期绑定 zElf 实例。
    std::vector<zFunction> function_list_;
};

#endif // OVERT_ZELF_H
