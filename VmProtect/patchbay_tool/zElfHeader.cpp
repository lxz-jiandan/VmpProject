#include "zElfHeader.h"
#include <cstring>

// 从原始字节拷贝 ELF 头；仅负责长度检查与复制，不做语义合法性判断。
bool zElfHeader::fromRaw(const uint8_t* data, size_t size) {
    if (!data || size < sizeof(Elf64_Ehdr)) {
        return false;
    }
    std::memcpy(&raw, data, sizeof(Elf64_Ehdr));
    return true;
}

// 校验是否为本项目支持的目标格式：ELF64 + 小端 + AArch64。
bool zElfHeader::isElf64AArch64() const {
    return raw.e_ident[EI_MAG0] == ELFMAG0 &&
           raw.e_ident[EI_MAG1] == ELFMAG1 &&
           raw.e_ident[EI_MAG2] == ELFMAG2 &&
           raw.e_ident[EI_MAG3] == ELFMAG3 &&
           raw.e_ident[EI_CLASS] == ELFCLASS64 &&
           raw.e_ident[EI_DATA] == ELFDATA2LSB &&
           raw.e_machine == EM_AARCH64;
}
