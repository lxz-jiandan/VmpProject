/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - 自定义链接器接口与 soinfo 结构声明。
 * - 加固链路位置：运行时装载接口层。
 * - 输入：装载请求/符号查询。
 * - 输出：soinfo 与地址解析能力。
 */
#ifndef Z_LINKER_H
#define Z_LINKER_H

// size_t。
#include <cstddef>
// uint32_t/uint64_t。
#include <cstdint>
// ELF 类型定义（ElfW、Ehdr、Phdr、Dyn、Sym、Rela 等）。
#include <elf.h>
// link 相关声明。
#include <link.h>
// unique_ptr。
#include <memory>
// std::string。
#include <string>
// std::unordered_map。
#include <unordered_map>
// std::vector。
#include <vector>

struct soinfo {
    // so 文件名（basename），用于在 map 中索引与日志输出。
    const char* name = nullptr;

    // 映射后的内存基址、总大小、ELF load bias（运行时地址 = 链接地址 + load_bias）。
    // 运行时装载基址。
    ElfW(Addr) base = 0;
    // 映像总长度（字节）。
    size_t size = 0;
    // 装载偏移（运行时地址 = 链接地址 + load_bias）。
    ElfW(Addr) load_bias = 0;

    // 程序头表（运行时地址）及数量。
    // 程序头表地址。
    const ElfW(Phdr)* phdr = nullptr;
    // 程序头项数。
    size_t phnum = 0;

    // 程序入口（通常共享库不直接使用，但保留元信息）。
    ElfW(Addr) entry = 0;

    // 动态段及条目数。
    // 动态段首地址。
    ElfW(Dyn)* dynamic = nullptr;
    // 动态段条目数（上限用于安全校验）。
    size_t dynamic_count = 0;

    // 符号解析相关表（SysV hash / GNU hash）。
    // 符号字符串表。
    const char* strtab = nullptr;
    // 动态符号表。
    ElfW(Sym)* symtab = nullptr;
    // SysV bucket 数量。
    size_t nbucket = 0;
    // SysV chain 数量。
    size_t nchain = 0;
    // SysV bucket 指针。
    uint32_t* bucket = nullptr;
    // SysV chain 指针。
    uint32_t* chain = nullptr;

    // 重定位表（RELA 与 PLT RELA）。
    // PLT RELA 首地址。
    ElfW(Rela)* plt_rela = nullptr;
    // PLT RELA 条目数。
    size_t plt_rela_count = 0;
    // 普通 RELA 首地址。
    ElfW(Rela)* rela = nullptr;
    // 普通 RELA 条目数。
    size_t rela_count = 0;

    // GNU hash 结构。
    // GNU bucket 数量。
    size_t gnu_nbucket = 0;
    // GNU bucket 指针。
    uint32_t* gnu_bucket = nullptr;
    // GNU chain 指针。
    uint32_t* gnu_chain = nullptr;
    // bloom maskwords（查找前会预处理为掩码）。
    uint32_t gnu_maskwords = 0;
    // bloom 第二移位参数。
    uint32_t gnu_shift2 = 0;
    // bloom filter 指针。
    ElfW(Addr)* gnu_bloom_filter = nullptr;

    // 构造/析构相关回调。
    // DT_INIT 单函数。
    void (*init_func)() = nullptr;
    // DT_INIT_ARRAY 起点。
    void (**init_array)() = nullptr;
    // DT_INIT_ARRAY 数量。
    size_t init_array_count = 0;
    // DT_FINI_ARRAY 起点（当前主要记录，不主动执行）。
    void (**fini_array)() = nullptr;
    // DT_FINI_ARRAY 数量。
    size_t fini_array_count = 0;

    // DT_NEEDED 依赖库名列表，符号兜底解析时使用。
    std::vector<std::string> needed_libs;
    // DT_FLAGS 值。
    uint32_t flags = 0;
};

class zLinker {
public:
    zLinker();
    ~zLinker();

    // 端到端加载入口：打开 ELF -> 映射段 -> 解析动态段 -> 重定位 -> 调 init。
    bool LoadLibrary(const char* path);
    // 从内存字节直接加载 ELF（避免先落盘）。
    bool LoadLibraryFromMemory(const char* soName, const uint8_t* soBytes, size_t soSize);

    // 按 so 名称查询已加载模块信息（不触发加载）。
    soinfo* GetSoinfo(const char* name);

private:
    // ELF 文件读取阶段。
    // 打开并映射输入 ELF 文件。
    bool OpenElf(const char* path);
    // 从内存副本构建输入 ELF 视图。
    bool OpenElfFromMemory(const char* soName, const uint8_t* soBytes, size_t soSize);
    // 读取 ELF Header + 校验 + 程序头表。
    bool ReadElf();
    // 在 OpenElf/OpenElfFromMemory 成功后，执行统一加载流程。
    bool LoadPreparedElf(const char* soName);
    // 关闭并清理输入 ELF 相关资源。
    void CloseElf();
    // 读取 ELF Header。
    bool ReadElfHeader();
    // 校验 ELF Header 合法性与架构。
    bool VerifyElfHeader();
    // 读取程序头表。
    bool ReadProgramHeaders();

    // 内存装载阶段。
    // 预留目标地址空间并计算 load_bias。
    bool ReserveAddressSpace();
    // 把 PT_LOAD 段拷贝到目标地址空间。
    bool LoadSegments();
    // 定位运行时程序头地址。
    bool FindPhdr();
    // 恢复段最终页权限。
    bool ProtectSegments();
    // 检查程序头是否落在可加载段内。
    bool CheckPhdr(ElfW(Addr) loaded) const;
    // 计算 PT_LOAD 总跨度。
    size_t PhdrTableGetLoadSize(ElfW(Addr)* minVaddr) const;

    // soinfo 与动态段处理阶段。
    // 查询或创建 soinfo。
    soinfo* GetOrCreateSoinfo(const char* name);
    // 把当前装载状态写入 soinfo。
    bool UpdateSoinfo(soinfo* si) const;
    // 预链接阶段（动态段解析准备）。
    bool PrelinkImage(soinfo* si);
    // 解析 DT_* 动态条目。
    bool ParseDynamic(soinfo* si);
    // 预留重定位段扩展钩子。
    void ApplyRelaSections(soinfo* si) const;

    // 符号绑定/重定位阶段。
    // 执行重定位并调用构造器。
    bool LinkImage(soinfo* si);
    // 执行 RELA/PLT RELA 重定位。
    bool RelocateImage(soinfo* si);
    // 处理单条 RELA 项。
    bool ProcessRelaRelocation(soinfo* si, const ElfW(Rela)* rela);
    // 按名称解析符号地址（本地 -> needed -> 全局）。
    ElfW(Addr) FindSymbolAddress(const char* name, soinfo* si);

    // GNU hash 路径查找符号。
    ElfW(Sym)* GnuLookup(uint32_t hash, const char* name, soinfo* si) const;
    // SysV hash 路径查找符号。
    ElfW(Sym)* ElfLookup(unsigned hash, const char* name, soinfo* si) const;
    // GNU hash 计算。
    uint32_t GnuHash(const char* name) const;
    // SysV ELF hash 计算。
    unsigned ElfHash(const char* name) const;

private:
    // 输入来源类型：文件映射 or 内存副本。
    enum class InputSourceType : uint8_t {
        kNone = 0,
        kFileMmap = 1,
        kMemoryBuffer = 2,
    };

    // 当前加载任务的临时状态（每次 LoadLibrary 会刷新）。
    // 输入路径（日志与诊断使用）。
    std::string path_;
    // 输入文件 fd。
    int fd_ = -1;
    // 输入文件大小。
    size_t file_size_ = 0;
    // 输入文件只读映射地址。
    void* mapped_file_ = nullptr;
    // 输入来源类型。
    InputSourceType input_source_ = InputSourceType::kNone;
    // 内存加载时持有 ELF 字节副本，保证解析期间指针稳定。
    std::vector<uint8_t> memory_file_copy_;
    // 输入 ELF 头缓存。
    ElfW(Ehdr) header_{};
    // 输入程序头表副本。
    ElfW(Phdr)* phdr_table_ = nullptr;
    // 程序头数量。
    size_t phdr_num_ = 0;

    // 目标 so 映射区信息。
    // 运行时映像基址。
    void* load_start_ = nullptr;
    // 运行时映像总大小。
    size_t load_size_ = 0;
    // 装载偏移。
    ElfW(Addr) load_bias_ = 0;
    // 运行时程序头地址。
    const ElfW(Phdr)* loaded_phdr_ = nullptr;

    // 已加载 so 缓存，以及最后一次加载成功的 so 指针。
    // 已加载模块表（key=basename）。
    std::unordered_map<std::string, std::unique_ptr<soinfo>> soinfo_map_;
    // 最近一次成功加载的 soinfo。
    soinfo* loaded_si_ = nullptr;
};

#endif // Z_LINKER_H
