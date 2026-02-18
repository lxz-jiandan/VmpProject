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
    const char* name = nullptr;
    ElfW(Addr) base = 0;
    size_t size = 0;
    ElfW(Addr) load_bias = 0;

    const ElfW(Phdr)* phdr = nullptr;
    size_t phnum = 0;

    ElfW(Addr) entry = 0;

    ElfW(Dyn)* dynamic = nullptr;
    size_t dynamic_count = 0;

    const char* strtab = nullptr;
    ElfW(Sym)* symtab = nullptr;
    size_t nbucket = 0;
    size_t nchain = 0;
    uint32_t* bucket = nullptr;
    uint32_t* chain = nullptr;

    ElfW(Rela)* plt_rela = nullptr;
    size_t plt_rela_count = 0;
    ElfW(Rela)* rela = nullptr;
    size_t rela_count = 0;

    size_t gnu_nbucket = 0;
    uint32_t* gnu_bucket = nullptr;
    uint32_t* gnu_chain = nullptr;
    uint32_t gnu_maskwords = 0;
    uint32_t gnu_shift2 = 0;
    ElfW(Addr)* gnu_bloom_filter = nullptr;

    void (*init_func)() = nullptr;
    void (**init_array)() = nullptr;
    size_t init_array_count = 0;
    void (**fini_array)() = nullptr;
    size_t fini_array_count = 0;

    std::vector<std::string> needed_libs;
    uint32_t flags = 0;
};

class zLinker {
public:
    zLinker();
    ~zLinker();

    bool LoadLibrary(const char* path);
    soinfo* GetSoinfo(const char* name);
    void* GetSymbol(const char* name);

private:
    bool OpenElf(const char* path);
    bool ReadElf();
    void CloseElf();
    bool ReadElfHeader();
    bool VerifyElfHeader();
    bool ReadProgramHeaders();

    bool ReserveAddressSpace();
    bool LoadSegments();
    bool FindPhdr();
    bool ProtectSegments();
    bool CheckPhdr(ElfW(Addr) loaded) const;
    size_t PhdrTableGetLoadSize(ElfW(Addr)* minVaddr) const;

    soinfo* GetOrCreateSoinfo(const char* name);
    bool UpdateSoinfo(soinfo* si) const;
    bool PrelinkImage(soinfo* si);
    bool ParseDynamic(soinfo* si);
    void ApplyRelaSections(soinfo* si) const;

    bool LinkImage(soinfo* si);
    bool RelocateImage(soinfo* si);
    bool ProcessRelaRelocation(soinfo* si, const ElfW(Rela)* rela);
    ElfW(Addr) FindSymbolAddress(const char* name, soinfo* si);

    ElfW(Sym)* GnuLookup(uint32_t hash, const char* name, soinfo* si) const;
    ElfW(Sym)* ElfLookup(unsigned hash, const char* name, soinfo* si) const;
    uint32_t GnuHash(const char* name) const;
    unsigned ElfHash(const char* name) const;

private:
    std::string path_;
    int fd_ = -1;
    size_t file_size_ = 0;
    void* mapped_file_ = nullptr;
    ElfW(Ehdr) header_{};
    ElfW(Phdr)* phdr_table_ = nullptr;
    size_t phdr_num_ = 0;

    void* load_start_ = nullptr;
    size_t load_size_ = 0;
    ElfW(Addr) load_bias_ = 0;
    const ElfW(Phdr)* loaded_phdr_ = nullptr;

    std::unordered_map<std::string, std::unique_ptr<soinfo>> soinfo_map_;
    soinfo* loaded_si_ = nullptr;
};

#endif // Z_LINKER_H
