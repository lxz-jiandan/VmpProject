#include "zLinker.h"

#include "zLog.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>

#if defined(__LP64__)
#define ELFW(what) ELF64_ ## what
#else
#define ELFW(what) ELF32_ ## what
#endif

namespace {

constexpr size_t kPageSize = 4096;
constexpr ElfW(Addr) kPageMask = static_cast<ElfW(Addr)>(~(kPageSize - 1));

constexpr ElfW(Word) kRelAarch64None = 0;
constexpr ElfW(Word) kRelAarch64Abs64 = 257;
constexpr ElfW(Word) kRelAarch64GlobDat = 1025;
constexpr ElfW(Word) kRelAarch64JumpSlot = 1026;
constexpr ElfW(Word) kRelAarch64Relative = 1027;
constexpr ElfW(Word) kRelAarch64IRelative = 1032;

inline ElfW(Addr) PageStart(ElfW(Addr) addr) {
    return addr & kPageMask;
}

inline ElfW(Addr) PageEnd(ElfW(Addr) addr) {
    return PageStart(addr + kPageSize - 1);
}

inline int PFlagsToProt(ElfW(Word) flags) {
    return ((flags & PF_R) ? PROT_READ : 0) |
           ((flags & PF_W) ? PROT_WRITE : 0) |
           ((flags & PF_X) ? PROT_EXEC : 0);
}

} // namespace

zLinker::zLinker() {
    std::memset(&header_, 0, sizeof(header_));
}

zLinker::~zLinker() {
    CloseElf();
    for (auto& pair : soinfo_map_) {
        if (pair.second && pair.second->name != nullptr) {
            std::free(const_cast<char*>(pair.second->name));
            pair.second->name = nullptr;
        }
    }
}

bool zLinker::OpenElf(const char* path) {
    if (path == nullptr || path[0] == '\0') {
        LOGE("OpenElf: path is null");
        return false;
    }

    CloseElf();
    path_ = path;

    struct stat sb{};
    fd_ = open(path, O_RDONLY | O_CLOEXEC);
    if (fd_ < 0) {
        LOGE("Cannot open %s: %s", path, strerror(errno));
        return false;
    }

    if (fstat(fd_, &sb) < 0) {
        LOGE("Cannot stat %s: %s", path, strerror(errno));
        CloseElf();
        return false;
    }
    file_size_ = static_cast<size_t>(sb.st_size);

    mapped_file_ = mmap(nullptr, file_size_, PROT_READ, MAP_PRIVATE, fd_, 0);
    if (mapped_file_ == MAP_FAILED) {
        LOGE("Cannot mmap %s: %s", path, strerror(errno));
        mapped_file_ = nullptr;
        CloseElf();
        return false;
    }

    return true;
}

bool zLinker::ReadElfHeader() {
    if (file_size_ < sizeof(ElfW(Ehdr))) {
        LOGE("File too small for ELF header");
        return false;
    }

    std::memcpy(&header_, mapped_file_, sizeof(header_));
    return true;
}

bool zLinker::VerifyElfHeader() {
    if (std::memcmp(header_.e_ident, ELFMAG, SELFMAG) != 0) {
        LOGE("Invalid ELF magic");
        return false;
    }

    if (header_.e_ident[EI_CLASS] != ELFCLASS64) {
        LOGE("Not a 64-bit ELF file");
        return false;
    }

    if (header_.e_machine != EM_AARCH64) {
        LOGE("Not an ARM64 ELF file");
        return false;
    }

    if (header_.e_version != EV_CURRENT) {
        LOGE("Invalid ELF version");
        return false;
    }

    if (header_.e_type != ET_DYN) {
        LOGE("Not a shared object");
        return false;
    }

    LOGD("ELF Header: type=%d, machine=%d, entry=0x%lx, phoff=0x%lx, phnum=%d",
         header_.e_type, header_.e_machine, header_.e_entry,
         header_.e_phoff, header_.e_phnum);
    return true;
}

bool zLinker::ReadProgramHeaders() {
    phdr_num_ = header_.e_phnum;
    if (phdr_num_ == 0) {
        LOGE("No program headers");
        return false;
    }

    if (header_.e_phentsize != sizeof(ElfW(Phdr))) {
        LOGE("Invalid program header size");
        return false;
    }

    const size_t size = phdr_num_ * sizeof(ElfW(Phdr));
    if (header_.e_phoff + size > file_size_) {
        LOGE("Program headers out of file bounds");
        return false;
    }

    phdr_table_ = static_cast<ElfW(Phdr)*>(std::malloc(size));
    if (phdr_table_ == nullptr) {
        LOGE("Cannot allocate memory for program headers");
        return false;
    }

    std::memcpy(phdr_table_, static_cast<char*>(mapped_file_) + header_.e_phoff, size);
    return true;
}

bool zLinker::ReadElf() {
    return ReadElfHeader() && VerifyElfHeader() && ReadProgramHeaders();
}

void zLinker::CloseElf() {
    if (mapped_file_ != nullptr) {
        munmap(mapped_file_, file_size_);
        mapped_file_ = nullptr;
    }

    if (fd_ >= 0) {
        close(fd_);
        fd_ = -1;
    }

    if (phdr_table_ != nullptr) {
        std::free(phdr_table_);
        phdr_table_ = nullptr;
    }

    file_size_ = 0;
    phdr_num_ = 0;
    path_.clear();
    std::memset(&header_, 0, sizeof(header_));
}

size_t zLinker::PhdrTableGetLoadSize(ElfW(Addr)* minVaddr) const {
    ElfW(Addr) min_addr = static_cast<ElfW(Addr)>(UINTPTR_MAX);
    ElfW(Addr) max_addr = 0;
    bool found_pt_load = false;

    for (size_t i = 0; i < phdr_num_; ++i) {
        const ElfW(Phdr)* phdr = &phdr_table_[i];
        if (phdr->p_type != PT_LOAD) {
            continue;
        }

        found_pt_load = true;
        if (phdr->p_vaddr < min_addr) {
            min_addr = phdr->p_vaddr;
        }
        if (phdr->p_vaddr + phdr->p_memsz > max_addr) {
            max_addr = phdr->p_vaddr + phdr->p_memsz;
        }
    }

    if (!found_pt_load) {
        return 0;
    }

    min_addr = PageStart(min_addr);
    max_addr = PageEnd(max_addr);
    if (minVaddr != nullptr) {
        *minVaddr = min_addr;
    }
    return static_cast<size_t>(max_addr - min_addr);
}

bool zLinker::ReserveAddressSpace() {
    ElfW(Addr) min_vaddr = 0;
    load_size_ = PhdrTableGetLoadSize(&min_vaddr);
    if (load_size_ == 0) {
        LOGE("No loadable segments");
        return false;
    }

    void* start = mmap(nullptr, load_size_, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (start == MAP_FAILED) {
        LOGE("Cannot reserve %zu bytes: %s", load_size_, strerror(errno));
        return false;
    }

    load_start_ = start;
    load_bias_ = reinterpret_cast<ElfW(Addr)>(start) - min_vaddr;
    loaded_phdr_ = nullptr;

    LOGD("Reserved address space at %p, size=0x%zx, bias=0x%lx", start, load_size_, load_bias_);
    return true;
}

bool zLinker::LoadSegments() {
    LOGD("Starting LoadSegments: phdr_num=%zu, file_size=%zu", phdr_num_, file_size_);

    for (size_t i = 0; i < phdr_num_; ++i) {
        const ElfW(Phdr)* phdr = &phdr_table_[i];
        if (phdr->p_type != PT_LOAD) {
            continue;
        }

        ElfW(Addr) seg_start = phdr->p_vaddr + load_bias_;
        ElfW(Addr) seg_end = seg_start + phdr->p_memsz;
        ElfW(Addr) seg_page_start = PageStart(seg_start);
        ElfW(Addr) seg_page_end = PageEnd(seg_end);
        ElfW(Addr) seg_file_end = seg_start + phdr->p_filesz;

        ElfW(Addr) file_end = phdr->p_offset + phdr->p_filesz;
        if (file_end > file_size_) {
            LOGE("Invalid file size: file_end=0x%lx > file_size=0x%zx", file_end, file_size_);
            return false;
        }

        if (phdr->p_filesz > 0) {
            if (mprotect(reinterpret_cast<void*>(seg_page_start),
                         seg_page_end - seg_page_start,
                         PROT_READ | PROT_WRITE) < 0) {
                LOGE("Cannot mprotect for loading: %s", strerror(errno));
                return false;
            }

            void* src = static_cast<char*>(mapped_file_) + phdr->p_offset;
            void* dst = reinterpret_cast<void*>(seg_start);

            if (static_cast<char*>(src) + phdr->p_filesz > static_cast<char*>(mapped_file_) + file_size_) {
                LOGE("Source copy would exceed file bounds");
                return false;
            }
            if (reinterpret_cast<ElfW(Addr)>(dst) + phdr->p_filesz > seg_page_end) {
                LOGE("Destination copy would exceed segment bounds");
                return false;
            }

            std::memcpy(dst, src, phdr->p_filesz);
        }

        if (phdr->p_memsz > phdr->p_filesz) {
            ElfW(Addr) bss_start = seg_start + phdr->p_filesz;
            ElfW(Addr) bss_end = seg_start + phdr->p_memsz;
            std::memset(reinterpret_cast<void*>(bss_start), 0, bss_end - bss_start);
        }

        ElfW(Addr) aligned_file_end = PageEnd(seg_file_end);
        if (seg_page_end > aligned_file_end) {
            size_t zeromap_size = static_cast<size_t>(seg_page_end - aligned_file_end);
            void* zeromap = mmap(reinterpret_cast<void*>(aligned_file_end),
                                 zeromap_size,
                                 PROT_READ | PROT_WRITE,
                                 MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
                                 -1,
                                 0);
            if (zeromap == MAP_FAILED) {
                LOGE("Cannot zero fill gap: %s", strerror(errno));
                return false;
            }
        }
    }

    return true;
}

bool zLinker::CheckPhdr(ElfW(Addr) loaded) const {
    const ElfW(Phdr)* phdr_limit = phdr_table_ + phdr_num_;
    ElfW(Addr) loaded_end = loaded + (phdr_num_ * sizeof(ElfW(Phdr)));

    for (const ElfW(Phdr)* phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
        if (phdr->p_type != PT_LOAD) {
            continue;
        }

        ElfW(Addr) seg_start = phdr->p_vaddr + load_bias_;
        ElfW(Addr) seg_end = phdr->p_filesz + seg_start;
        if (seg_start <= loaded && loaded_end <= seg_end) {
            return true;
        }
    }

    LOGE("Loaded phdr %p not in loadable segment", reinterpret_cast<void*>(loaded));
    return false;
}

bool zLinker::FindPhdr() {
    const ElfW(Phdr)* phdr_limit = phdr_table_ + phdr_num_;

    for (const ElfW(Phdr)* phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
        if (phdr->p_type == PT_PHDR) {
            ElfW(Addr) loaded = load_bias_ + phdr->p_vaddr;
            if (CheckPhdr(loaded)) {
                loaded_phdr_ = reinterpret_cast<const ElfW(Phdr)*>(loaded);
                return true;
            }
            return false;
        }
    }

    for (const ElfW(Phdr)* phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
        if (phdr->p_type == PT_LOAD && phdr->p_offset == 0) {
            ElfW(Addr) elf_addr = load_bias_ + phdr->p_vaddr;
            const ElfW(Ehdr)* ehdr = reinterpret_cast<const ElfW(Ehdr)*>(elf_addr);
            ElfW(Addr) loaded = reinterpret_cast<ElfW(Addr)>(ehdr) + ehdr->e_phoff;
            if (CheckPhdr(loaded)) {
                loaded_phdr_ = reinterpret_cast<const ElfW(Phdr)*>(loaded);
                return true;
            }
            return false;
        }
    }

    LOGD("Using original phdr_table as loaded_phdr");
    loaded_phdr_ = phdr_table_;
    return true;
}

bool zLinker::ProtectSegments() {
    for (size_t i = 0; i < phdr_num_; ++i) {
        const ElfW(Phdr)* phdr = &phdr_table_[i];
        if (phdr->p_type != PT_LOAD) {
            continue;
        }

        ElfW(Addr) seg_start = phdr->p_vaddr + load_bias_;
        ElfW(Addr) seg_page_start = PageStart(seg_start);
        ElfW(Addr) seg_page_end = PageEnd(seg_start + phdr->p_memsz);
        int prot = PFlagsToProt(phdr->p_flags);

        if (mprotect(reinterpret_cast<void*>(seg_page_start),
                     seg_page_end - seg_page_start,
                     prot) < 0) {
            LOGE("Cannot protect segment %zu: %s", i, strerror(errno));
            return false;
        }
    }
    return true;
}

soinfo* zLinker::GetOrCreateSoinfo(const char* name) {
    if (name == nullptr || name[0] == '\0') {
        return nullptr;
    }

    auto it = soinfo_map_.find(name);
    if (it != soinfo_map_.end()) {
        return it->second.get();
    }

    auto si = std::make_unique<soinfo>();
    char* dup_name = ::strdup(name);
    if (dup_name == nullptr) {
        LOGE("strdup failed for so name: %s", name);
        return nullptr;
    }
    si->name = dup_name;

    soinfo* result = si.get();
    soinfo_map_.emplace(name, std::move(si));
    return result;
}

bool zLinker::UpdateSoinfo(soinfo* si) const {
    if (si == nullptr) {
        return false;
    }

    si->base = reinterpret_cast<ElfW(Addr)>(load_start_);
    si->size = load_size_;
    si->load_bias = load_bias_;
    si->phdr = (loaded_phdr_ != nullptr) ? loaded_phdr_ : phdr_table_;
    si->phnum = phdr_num_;
    si->entry = load_bias_ + header_.e_entry;

    LOGD("Updated soinfo: base=0x%lx, size=0x%zx, bias=0x%lx, entry=0x%lx",
         si->base, si->size, si->load_bias, si->entry);
    return true;
}

bool zLinker::ParseDynamic(soinfo* si) {
    if (si == nullptr || si->phdr == nullptr) {
        LOGE("Invalid soinfo or phdr is null");
        return false;
    }

    si->dynamic = nullptr;
    si->dynamic_count = 0;
    si->strtab = nullptr;
    si->symtab = nullptr;
    si->nbucket = 0;
    si->nchain = 0;
    si->bucket = nullptr;
    si->chain = nullptr;
    si->plt_rela = nullptr;
    si->plt_rela_count = 0;
    si->rela = nullptr;
    si->rela_count = 0;
    si->gnu_nbucket = 0;
    si->gnu_bucket = nullptr;
    si->gnu_chain = nullptr;
    si->gnu_maskwords = 0;
    si->gnu_shift2 = 0;
    si->gnu_bloom_filter = nullptr;
    si->init_func = nullptr;
    si->init_array = nullptr;
    si->init_array_count = 0;
    si->fini_array = nullptr;
    si->fini_array_count = 0;
    si->needed_libs.clear();
    si->flags = 0;

    const ElfW(Phdr)* phdr_limit = si->phdr + si->phnum;
    for (const ElfW(Phdr)* phdr = si->phdr; phdr < phdr_limit; ++phdr) {
        if (phdr->p_type == PT_DYNAMIC) {
            si->dynamic = reinterpret_cast<ElfW(Dyn)*>(si->load_bias + phdr->p_vaddr);
            si->dynamic_count = phdr->p_memsz / sizeof(ElfW(Dyn));
            break;
        }
    }

    if (si->dynamic == nullptr || si->dynamic_count == 0 || si->dynamic_count > 1000) {
        LOGE("No valid PT_DYNAMIC segment");
        return false;
    }

    size_t dyn_count = 0;
    for (ElfW(Dyn)* d = si->dynamic; d->d_tag != DT_NULL && dyn_count < si->dynamic_count; ++d, ++dyn_count) {
        switch (d->d_tag) {
            case DT_SYMTAB:
                si->symtab = reinterpret_cast<ElfW(Sym)*>(si->load_bias + d->d_un.d_ptr);
                break;
            case DT_STRTAB:
                si->strtab = reinterpret_cast<const char*>(si->load_bias + d->d_un.d_ptr);
                break;
            case DT_HASH: {
                auto* hash = reinterpret_cast<uint32_t*>(si->load_bias + d->d_un.d_ptr);
                si->nbucket = hash[0];
                si->nchain = hash[1];
                si->bucket = hash + 2;
                si->chain = si->bucket + si->nbucket;
                break;
            }
            case DT_GNU_HASH: {
                auto* hash = reinterpret_cast<uint32_t*>(si->load_bias + d->d_un.d_ptr);
                si->gnu_nbucket = hash[0];
                uint32_t symbias = hash[1];
                si->gnu_maskwords = hash[2];
                si->gnu_shift2 = hash[3];
                si->gnu_bloom_filter = reinterpret_cast<ElfW(Addr)*>(hash + 4);
                si->gnu_bucket = reinterpret_cast<uint32_t*>(si->gnu_bloom_filter + si->gnu_maskwords);
                si->gnu_chain = si->gnu_bucket + si->gnu_nbucket - symbias;
                if (si->gnu_maskwords == 0 || (si->gnu_maskwords & (si->gnu_maskwords - 1)) != 0) {
                    LOGE("DT_GNU_HASH: invalid maskwords=%u", si->gnu_maskwords);
                    return false;
                }
                si->gnu_maskwords -= 1;
                break;
            }
            case DT_JMPREL:
                si->plt_rela = reinterpret_cast<ElfW(Rela)*>(si->load_bias + d->d_un.d_ptr);
                break;
            case DT_PLTRELSZ:
                si->plt_rela_count = d->d_un.d_val / sizeof(ElfW(Rela));
                break;
            case DT_RELA:
                si->rela = reinterpret_cast<ElfW(Rela)*>(si->load_bias + d->d_un.d_ptr);
                break;
            case DT_RELASZ:
                si->rela_count = d->d_un.d_val / sizeof(ElfW(Rela));
                break;
            case DT_INIT:
                si->init_func = reinterpret_cast<void (*)()>(si->load_bias + d->d_un.d_ptr);
                break;
            case DT_INIT_ARRAY:
                si->init_array = reinterpret_cast<void (**)()>(si->load_bias + d->d_un.d_ptr);
                break;
            case DT_INIT_ARRAYSZ:
                si->init_array_count = d->d_un.d_val / sizeof(void*);
                break;
            case DT_FINI_ARRAY:
                si->fini_array = reinterpret_cast<void (**)()>(si->load_bias + d->d_un.d_ptr);
                break;
            case DT_FINI_ARRAYSZ:
                si->fini_array_count = d->d_un.d_val / sizeof(void*);
                break;
            case DT_FLAGS:
                si->flags = d->d_un.d_val;
                break;
            default:
                break;
        }
    }

    if (si->strtab != nullptr) {
        dyn_count = 0;
        for (ElfW(Dyn)* d = si->dynamic; d->d_tag != DT_NULL && dyn_count < si->dynamic_count; ++d, ++dyn_count) {
            if (d->d_tag != DT_NEEDED) {
                continue;
            }
            if (d->d_un.d_val >= 65536) {
                continue;
            }
            const char* needed = si->strtab + d->d_un.d_val;
            size_t len = std::strlen(needed);
            if (len > 0 && len < 256) {
                si->needed_libs.emplace_back(needed);
            }
        }
    }

    LOGD("Dynamic parsing complete: symtab=%p, strtab=%p, needed_libs=%zu",
         si->symtab, si->strtab, si->needed_libs.size());
    return true;
}

void zLinker::ApplyRelaSections(soinfo* si) const {
    if (si == nullptr) {
        return;
    }
    LOGD("RELA sections: rela_count=%zu, plt_rela_count=%zu", si->rela_count, si->plt_rela_count);
}

bool zLinker::PrelinkImage(soinfo* si) {
    if (si == nullptr) {
        return false;
    }
    if (!ParseDynamic(si)) {
        LOGE("Failed to parse dynamic section");
        return false;
    }

    ApplyRelaSections(si);
    return true;
}

bool zLinker::ProcessRelaRelocation(soinfo* si, const ElfW(Rela)* rela) {
    if (si == nullptr || rela == nullptr) {
        return false;
    }

    ElfW(Addr) reloc = static_cast<ElfW(Addr)>(rela->r_offset + si->load_bias);
    ElfW(Word) type = ELFW(R_TYPE)(rela->r_info);
    ElfW(Word) sym = ELFW(R_SYM)(rela->r_info);

    if (reloc < si->base || reloc >= si->base + si->size) {
        LOGE("Relocation address 0x%lx out of range [0x%lx, 0x%lx)",
             reloc, si->base, si->base + si->size);
        return false;
    }

    ElfW(Addr) sym_addr = 0;
    const char* sym_name = nullptr;
    if (sym != 0) {
        if (si->symtab == nullptr) {
            LOGE("Symbol table is null");
            return false;
        }

        const ElfW(Sym)* s = &si->symtab[sym];
        if (si->strtab != nullptr && s->st_name != 0) {
            sym_name = si->strtab + s->st_name;
        }

        if (s->st_shndx != SHN_UNDEF) {
            sym_addr = s->st_value + si->load_bias;
        } else if (sym_name != nullptr) {
            sym_addr = FindSymbolAddress(sym_name, si);
        }
    }

    if (mprotect(reinterpret_cast<void*>(PageStart(reloc)), kPageSize, PROT_READ | PROT_WRITE) != 0) {
        LOGD("mprotect failed for relocation, trying anyway: %s", strerror(errno));
    }

    switch (type) {
        case kRelAarch64None:
            break;
        case kRelAarch64Abs64:
        case kRelAarch64GlobDat:
        case kRelAarch64JumpSlot:
            *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr + rela->r_addend;
            break;
        case kRelAarch64Relative:
            *reinterpret_cast<ElfW(Addr)*>(reloc) = si->load_bias + rela->r_addend;
            break;
        case kRelAarch64IRelative: {
            ElfW(Addr) resolver = si->load_bias + rela->r_addend;
            if (resolver < si->base || resolver >= si->base + si->size) {
                LOGE("Invalid resolver address: 0x%lx", resolver);
                return false;
            }
            ElfW(Addr) resolved = (reinterpret_cast<ElfW(Addr) (*)()>(resolver))();
            *reinterpret_cast<ElfW(Addr)*>(reloc) = resolved;
            break;
        }
        default:
            LOGD("Unknown relocation type %d, skipping", type);
            break;
    }

    return true;
}

bool zLinker::RelocateImage(soinfo* si) {
    if (si == nullptr) {
        LOGE("soinfo is null");
        return false;
    }

    if (si->rela != nullptr && si->rela_count > 0) {
        if (si->rela_count > 100000) {
            LOGE("RELA count too large: %zu", si->rela_count);
            return false;
        }
        for (size_t i = 0; i < si->rela_count; ++i) {
            if (!ProcessRelaRelocation(si, &si->rela[i])) {
                LOGE("Failed to process RELA relocation %zu", i);
            }
        }
    }

    if (si->plt_rela != nullptr && si->plt_rela_count > 0) {
        if (si->plt_rela_count > 10000) {
            LOGE("PLT RELA count too large: %zu", si->plt_rela_count);
            return false;
        }
        for (size_t i = 0; i < si->plt_rela_count; ++i) {
            if (!ProcessRelaRelocation(si, &si->plt_rela[i])) {
                LOGE("Failed to process PLT RELA relocation %zu", i);
            }
        }
    }

    return true;
}

bool zLinker::LinkImage(soinfo* si) {
    if (si == nullptr) {
        LOGE("soinfo is null in LinkImage");
        return false;
    }

    if (!RelocateImage(si)) {
        LOGE("Failed to relocate image");
        return false;
    }

    if (si->init_func != nullptr) {
        si->init_func();
    }

    if (si->init_array != nullptr && si->init_array_count > 0) {
        if (si->init_array_count > 1000) {
            LOGE("init_array_count too large: %zu", si->init_array_count);
            return false;
        }
        for (size_t i = 0; i < si->init_array_count; ++i) {
            void (*func)() = si->init_array[i];
            if (func != nullptr) {
                func();
            }
        }
    }

    return true;
}

ElfW(Sym)* zLinker::GnuLookup(uint32_t hash, const char* name, soinfo* si) const {
    if (si == nullptr ||
        si->gnu_bucket == nullptr ||
        si->gnu_chain == nullptr ||
        si->gnu_bloom_filter == nullptr ||
        si->symtab == nullptr ||
        si->strtab == nullptr ||
        si->gnu_nbucket == 0) {
        return nullptr;
    }

    uint32_t h2 = hash >> si->gnu_shift2;
    uint32_t bloom_mask_bits = sizeof(ElfW(Addr)) * 8;
    uint32_t word_num = (hash / bloom_mask_bits) & si->gnu_maskwords;
    ElfW(Addr) bloom_word = si->gnu_bloom_filter[word_num];

    if ((1 & (bloom_word >> (hash % bloom_mask_bits)) & (bloom_word >> (h2 % bloom_mask_bits))) == 0) {
        return nullptr;
    }

    uint32_t n = si->gnu_bucket[hash % si->gnu_nbucket];
    if (n == 0) {
        return nullptr;
    }

    do {
        ElfW(Sym)* s = si->symtab + n;
        if (((si->gnu_chain[n] ^ hash) >> 1) == 0 &&
            std::strcmp(si->strtab + s->st_name, name) == 0) {
            return s;
        }
    } while ((si->gnu_chain[n++] & 1) == 0);

    return nullptr;
}

ElfW(Sym)* zLinker::ElfLookup(unsigned hash, const char* name, soinfo* si) const {
    if (si == nullptr ||
        si->bucket == nullptr ||
        si->chain == nullptr ||
        si->symtab == nullptr ||
        si->strtab == nullptr ||
        si->nbucket == 0) {
        return nullptr;
    }

    for (unsigned n = si->bucket[hash % si->nbucket]; n != 0; n = si->chain[n]) {
        ElfW(Sym)* s = si->symtab + n;
        if (s->st_name != 0 && std::strcmp(si->strtab + s->st_name, name) == 0) {
            return s;
        }
    }
    return nullptr;
}

uint32_t zLinker::GnuHash(const char* name) const {
    uint32_t h = 5381;
    for (const uint8_t* c = reinterpret_cast<const uint8_t*>(name); *c != '\0'; ++c) {
        h += (h << 5) + *c;
    }
    return h;
}

unsigned zLinker::ElfHash(const char* name) const {
    unsigned h = 0;
    unsigned g = 0;
    for (const unsigned char* p = reinterpret_cast<const unsigned char*>(name); *p; ++p) {
        h = (h << 4) + *p;
        g = h & 0xf0000000;
        h ^= g;
        h ^= g >> 24;
    }
    return h;
}

ElfW(Addr) zLinker::FindSymbolAddress(const char* name, soinfo* si) {
    if (name == nullptr || si == nullptr) {
        return 0;
    }

    if (si->symtab != nullptr) {
        if (si->gnu_bucket != nullptr) {
            uint32_t hash = GnuHash(name);
            ElfW(Sym)* sym = GnuLookup(hash, name, si);
            if (sym != nullptr && sym->st_shndx != SHN_UNDEF) {
                return sym->st_value + si->load_bias;
            }
        }
        if (si->bucket != nullptr) {
            unsigned hash = ElfHash(name);
            ElfW(Sym)* sym = ElfLookup(hash, name, si);
            if (sym != nullptr && sym->st_shndx != SHN_UNDEF) {
                return sym->st_value + si->load_bias;
            }
        }
    }

    for (const auto& lib : si->needed_libs) {
        void* handle = dlopen(lib.c_str(), RTLD_NOW | RTLD_NOLOAD);
        if (handle == nullptr) {
            continue;
        }
        void* addr = dlsym(handle, name);
        if (addr != nullptr) {
            dlclose(handle);
            return reinterpret_cast<ElfW(Addr)>(addr);
        }
        dlclose(handle);
    }

    void* addr = dlsym(RTLD_DEFAULT, name);
    return (addr != nullptr) ? reinterpret_cast<ElfW(Addr)>(addr) : 0;
}

bool zLinker::LoadLibrary(const char* path) {
    if (path == nullptr || path[0] == '\0') {
        LOGE("zLinker::LoadLibrary path is null");
        return false;
    }

    LOGI("Loading library: %s", path);

    if (!OpenElf(path)) {
        return false;
    }
    if (!ReadElf()) {
        CloseElf();
        return false;
    }
    if (!ReserveAddressSpace()) {
        CloseElf();
        return false;
    }
    if (!LoadSegments()) {
        CloseElf();
        return false;
    }
    if (!FindPhdr()) {
        CloseElf();
        return false;
    }

    const char* basename = std::strrchr(path, '/');
    basename = (basename != nullptr) ? (basename + 1) : path;
    loaded_si_ = GetOrCreateSoinfo(basename);
    if (loaded_si_ == nullptr) {
        CloseElf();
        return false;
    }

    if (!UpdateSoinfo(loaded_si_)) {
        CloseElf();
        return false;
    }
    if (!PrelinkImage(loaded_si_)) {
        CloseElf();
        return false;
    }
    if (!ProtectSegments()) {
        CloseElf();
        return false;
    }
    if (!LinkImage(loaded_si_)) {
        CloseElf();
        return false;
    }

    CloseElf();
    LOGI("Successfully loaded %s", path);
    return true;
}

soinfo* zLinker::GetSoinfo(const char* name) {
    if (name == nullptr || name[0] == '\0') {
        return nullptr;
    }
    auto it = soinfo_map_.find(name);
    return (it == soinfo_map_.end()) ? nullptr : it->second.get();
}

void* zLinker::GetSymbol(const char* name) {
    if (loaded_si_ == nullptr) {
        LOGE("loaded_si_ is null");
        return nullptr;
    }
    if (name == nullptr || name[0] == '\0') {
        LOGE("Symbol name is null");
        return nullptr;
    }

    if (loaded_si_->symtab != nullptr) {
        if (loaded_si_->gnu_bucket != nullptr) {
            uint32_t hash = GnuHash(name);
            ElfW(Sym)* sym = GnuLookup(hash, name, loaded_si_);
            if (sym != nullptr && sym->st_shndx != SHN_UNDEF) {
                ElfW(Addr) addr = sym->st_value + loaded_si_->load_bias;
                if (addr >= loaded_si_->base && addr < loaded_si_->base + loaded_si_->size) {
                    return reinterpret_cast<void*>(addr);
                }
            }
        }

        if (loaded_si_->bucket != nullptr) {
            unsigned hash = ElfHash(name);
            ElfW(Sym)* sym = ElfLookup(hash, name, loaded_si_);
            if (sym != nullptr && sym->st_shndx != SHN_UNDEF) {
                ElfW(Addr) addr = sym->st_value + loaded_si_->load_bias;
                if (addr >= loaded_si_->base && addr < loaded_si_->base + loaded_si_->size) {
                    return reinterpret_cast<void*>(addr);
                }
            }
        }

        if (loaded_si_->gnu_bucket == nullptr &&
            loaded_si_->bucket == nullptr &&
            loaded_si_->strtab != nullptr &&
            loaded_si_->nchain > 0) {
            for (size_t i = 0; i < loaded_si_->nchain; ++i) {
                ElfW(Sym)* sym = &loaded_si_->symtab[i];
                if (sym->st_name == 0 || sym->st_shndx == SHN_UNDEF) {
                    continue;
                }
                const char* sym_name = loaded_si_->strtab + sym->st_name;
                if (std::strcmp(sym_name, name) == 0) {
                    ElfW(Addr) addr = sym->st_value + loaded_si_->load_bias;
                    if (addr >= loaded_si_->base && addr < loaded_si_->base + loaded_si_->size) {
                        return reinterpret_cast<void*>(addr);
                    }
                }
            }
        }
    }

    LOGE("Symbol %s not found", name);
    return nullptr;
}
