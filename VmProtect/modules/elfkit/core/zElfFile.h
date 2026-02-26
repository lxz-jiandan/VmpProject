#ifndef VMP_ELFKIT_INTERNAL_ELF_FILE_H
#define VMP_ELFKIT_INTERNAL_ELF_FILE_H

// 引入基础文件 IO 能力。
#include "zFile.h"
// 引入 ELF ABI 常量与结构定义。
#include "zElfAbi.h"

// 引入 size_t。
#include <cstddef>
// 引入定宽整数类型。
#include <cstdint>
// 引入 numeric_limits。
#include <limits>
// 引入错误描述字符串。
#include <string>
// 引入字节数组容器。
#include <vector>

// 进入内部命名空间。
namespace vmp::elfkit::internal {

// 统一 ELF64 文件视图（仅包含解析入口所需的核心表信息）。
struct ElfFileView64 {
    // 原始文件字节首地址。
    const uint8_t* fileBytes = nullptr;
    // 文件总大小。
    size_t fileSize = 0;

    // ELF Header 指针。
    const Elf64_Ehdr* elfHeader = nullptr;

    // Program Header Table 首地址与条目元信息。
    const Elf64_Phdr* programHeaders = nullptr;
    uint16_t programHeaderCount = 0;
    uint16_t programHeaderEntrySize = 0;

    // Section Header Table 首地址与条目元信息。
    const Elf64_Shdr* sectionHeaders = nullptr;
    uint16_t sectionHeaderCount = 0;
    uint16_t sectionHeaderEntrySize = 0;
    uint16_t sectionNameTableIndex = SHN_UNDEF;
};

// 通用失败返回辅助函数。
inline bool fail(std::string* error, const char* message) {
    // 有错误输出对象时写入错误文本。
    if (error) {
        *error = message ? message : "unknown error";
    }
    return false;
}

// 读取 ELF 文件到内存字节数组。
inline bool loadElfFileBytes(const char* path, std::vector<uint8_t>* out, std::string* error) {
    // 输出缓冲区指针不能为空。
    if (!out) {
        return fail(error, "null output buffer");
    }
    // 清理旧数据。
    out->clear();
    // 路径不能为空。
    if (!path || path[0] == '\0') {
        return fail(error, "invalid input path");
    }
    // 临时字节容器。
    std::vector<uint8_t> bytes;
    // 读取失败或文件为空都视为错误。
    if (!vmp::base::file::readFileBytes(path, &bytes) || bytes.empty()) {
        return fail(error, "failed to read elf file");
    }
    // 移动写入输出缓冲。
    *out = std::move(bytes);
    return true;
}

// 校验输入是否是 ELF64 + AArch64 + little-endian。
inline bool validateElf64Aarch64(const uint8_t* bytes, size_t size, std::string* error) {
    // 至少要有 ELF 头大小。
    if (!bytes || size < sizeof(Elf64_Ehdr)) {
        return fail(error, "elf file too small");
    }

    // 解释 ELF 头。
    const auto* ehdr = reinterpret_cast<const Elf64_Ehdr*>(bytes);

    // 校验 ELF magic。
    if (ehdr->e_ident[0] != ELFMAG0 || ehdr->e_ident[1] != ELFMAG1 ||
        ehdr->e_ident[2] != ELFMAG2 || ehdr->e_ident[3] != ELFMAG3) {
        return fail(error, "invalid elf magic");
    }
    // 校验 ELF class=64 位。
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        return fail(error, "unsupported elf class (expect ELF64)");
    }
    // 校验小端格式。
    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
        return fail(error, "unsupported elf endian (expect little-endian)");
    }
    // 校验目标架构是 AArch64。
    if (ehdr->e_machine != EM_AARCH64) {
        return fail(error, "unsupported machine (expect AArch64)");
    }
    return true;
}

// 校验任意“定长表”是否落在文件范围内。
inline bool validateTableRange(uint64_t offset,
                               uint64_t entrySize,
                               uint64_t entryCount,
                               size_t fileSize,
                               const char* tableName,
                               std::string* error) {
    // 0 项表直接认为合法。
    if (entryCount == 0) {
        return true;
    }
    // 每项大小不能为 0。
    if (entrySize == 0) {
        return fail(error, tableName ? tableName : "invalid table entry size");
    }
    // 起始偏移不能超过文件大小。
    if (offset > fileSize) {
        return fail(error, tableName ? tableName : "table offset out of file bounds");
    }
    // 防止 entrySize * entryCount 溢出。
    if (entryCount > (std::numeric_limits<uint64_t>::max() / entrySize)) {
        return fail(error, tableName ? tableName : "table size overflow");
    }

    // 计算表总字节数。
    const uint64_t tableBytes = entrySize * entryCount;
    // 校验完整表范围不越界。
    if (tableBytes > static_cast<uint64_t>(fileSize) - offset) {
        return fail(error, tableName ? tableName : "table range out of file bounds");
    }
    return true;
}

// 解析 ELF64+AArch64 文件的核心视图，并统一完成头表越界校验。
inline bool parseElfFileView64Aarch64(const uint8_t* bytes,
                                      size_t size,
                                      ElfFileView64* out,
                                      std::string* error) {
    // 输出对象必须有效。
    if (out == nullptr) {
        return fail(error, "null elf view output");
    }

    // 先清空输出，保证失败时状态可预期。
    *out = ElfFileView64{};

    // 先做 ELF64+AArch64 基础校验。
    if (!validateElf64Aarch64(bytes, size, error)) {
        return false;
    }

    // 解释 ELF Header。
    const auto* ehdr = reinterpret_cast<const Elf64_Ehdr*>(bytes);

    // 回填基础字段。
    out->fileBytes = bytes;
    out->fileSize = size;
    out->elfHeader = ehdr;
    out->programHeaderCount = ehdr->e_phnum;
    out->programHeaderEntrySize = ehdr->e_phentsize;
    out->sectionHeaderCount = ehdr->e_shnum;
    out->sectionHeaderEntrySize = ehdr->e_shentsize;
    out->sectionNameTableIndex = ehdr->e_shstrndx;

    // 校验 Program Header Table。
    if (!validateTableRange(ehdr->e_phoff,
                            ehdr->e_phentsize,
                            ehdr->e_phnum,
                            size,
                            "program header table out of range",
                            error)) {
        return false;
    }
    if (ehdr->e_phnum > 0) {
        out->programHeaders = reinterpret_cast<const Elf64_Phdr*>(bytes + ehdr->e_phoff);
    }

    // 校验 Section Header Table。
    if (!validateTableRange(ehdr->e_shoff,
                            ehdr->e_shentsize,
                            ehdr->e_shnum,
                            size,
                            "section header table out of range",
                            error)) {
        return false;
    }
    if (ehdr->e_shnum > 0) {
        out->sectionHeaders = reinterpret_cast<const Elf64_Shdr*>(bytes + ehdr->e_shoff);
    }
    return true;
}

// 结束内部命名空间。
}  // namespace vmp::elfkit::internal

#endif  // VMP_ELFKIT_INTERNAL_ELF_FILE_H

