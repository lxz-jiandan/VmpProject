/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - 自定义链接器接口与 soinfo 结构声明。
 * - 加固链路位置：运行时装载接口层。
 * - 输入：装载请求/符号查询。
 * - 输出：soinfo 与地址解析能力。
 */
#ifndef Z_LINKER_H
#define Z_LINKER_H

#include <cstddef>
#include <cstdint>
#include <elf.h>
#include <link.h>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

struct soinfo {
    // so 文件名（basename），用于在 map 中索引与日志输出。
    const char* name = nullptr;

    // 映射后的内存基址、总大小、ELF load bias（运行时地址 = 链接地址 + load_bias）。
    ElfW(Addr) base = 0;
    size_t size = 0;
    ElfW(Addr) load_bias = 0;

    // 程序头表（运行时地址）及数量。
    const ElfW(Phdr)* phdr = nullptr;
    size_t phnum = 0;

    // 程序入口（通常共享库不直接使用，但保留元信息）。
    ElfW(Addr) entry = 0;

    // 动态段及条目数。
    ElfW(Dyn)* dynamic = nullptr;
    size_t dynamic_count = 0;

    // 符号解析相关表（SysV hash / GNU hash）。
    const char* strtab = nullptr;
    ElfW(Sym)* symtab = nullptr;
    size_t nbucket = 0;
    size_t nchain = 0;
    uint32_t* bucket = nullptr;
    uint32_t* chain = nullptr;

    // 重定位表（RELA 与 PLT RELA）。
    ElfW(Rela)* plt_rela = nullptr;
    size_t plt_rela_count = 0;
    ElfW(Rela)* rela = nullptr;
    size_t rela_count = 0;

    // GNU hash 结构。
    size_t gnu_nbucket = 0;
    uint32_t* gnu_bucket = nullptr;
    uint32_t* gnu_chain = nullptr;
    uint32_t gnu_maskwords = 0;
    uint32_t gnu_shift2 = 0;
    ElfW(Addr)* gnu_bloom_filter = nullptr;

    // 构造/析构相关回调。
    void (*init_func)() = nullptr;
    void (**init_array)() = nullptr;
    size_t init_array_count = 0;
    void (**fini_array)() = nullptr;
    size_t fini_array_count = 0;

    // DT_NEEDED 依赖库名列表，符号兜底解析时使用。
    std::vector<std::string> needed_libs;
    uint32_t flags = 0;
};

class zLinker {
public:
    zLinker();
    ~zLinker();

    // 端到端加载入口：打开 ELF -> 映射段 -> 解析动态段 -> 重定位 -> 调 init。
    bool LoadLibrary(const char* path);

    // 按 so 名称查询已加载模块信息（不触发加载）。
    soinfo* GetSoinfo(const char* name);

private:
    // ELF 文件读取阶段。
    bool OpenElf(const char* path);
    bool ReadElf();
    void CloseElf();
    bool ReadElfHeader();
    bool VerifyElfHeader();
    bool ReadProgramHeaders();

    // 内存装载阶段。
    bool ReserveAddressSpace();
    bool LoadSegments();
    bool FindPhdr();
    bool ProtectSegments();
    bool CheckPhdr(ElfW(Addr) loaded) const;
    size_t PhdrTableGetLoadSize(ElfW(Addr)* minVaddr) const;

    // soinfo 与动态段处理阶段。
    soinfo* GetOrCreateSoinfo(const char* name);
    bool UpdateSoinfo(soinfo* si) const;
    bool PrelinkImage(soinfo* si);
    bool ParseDynamic(soinfo* si);
    void ApplyRelaSections(soinfo* si) const;

    // 符号绑定/重定位阶段。
    bool LinkImage(soinfo* si);
    bool RelocateImage(soinfo* si);
    bool ProcessRelaRelocation(soinfo* si, const ElfW(Rela)* rela);
    ElfW(Addr) FindSymbolAddress(const char* name, soinfo* si);

    ElfW(Sym)* GnuLookup(uint32_t hash, const char* name, soinfo* si) const;
    ElfW(Sym)* ElfLookup(unsigned hash, const char* name, soinfo* si) const;
    uint32_t GnuHash(const char* name) const;
    unsigned ElfHash(const char* name) const;

private:
    // 当前加载任务的临时状态（每次 LoadLibrary 会刷新）。
    std::string path_;
    int fd_ = -1;
    size_t file_size_ = 0;
    void* mapped_file_ = nullptr;
    ElfW(Ehdr) header_{};
    ElfW(Phdr)* phdr_table_ = nullptr;
    size_t phdr_num_ = 0;

    // 目标 so 映射区信息。
    void* load_start_ = nullptr;
    size_t load_size_ = 0;
    ElfW(Addr) load_bias_ = 0;
    const ElfW(Phdr)* loaded_phdr_ = nullptr;

    // 已加载 so 缓存，以及最后一次加载成功的 so 指针。
    std::unordered_map<std::string, std::unique_ptr<soinfo>> soinfo_map_;
    soinfo* loaded_si_ = nullptr;
};

#endif // Z_LINKER_H
