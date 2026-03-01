/*
 * [VMP_FLOW_NOTE] 文件级流程注释。
 * - 文件：patchbayModel/zPatchElfValidatorBase.cpp
 * - 主要职责：基础校验实现：负责通用边界、空值与一致性前置检查。
 * - 输入：ELF 原始字节、补丁模型状态以及段/节/符号元数据。
 * - 输出：经过校验的补丁模型或重建后的 ELF 输出数据。
 * - 关键约束：
 *   1) 严格保持 ELF 布局与索引一致性，避免地址/偏移漂移。
 *   2) 失败路径必须可定位（返回值/错误信息/日志三者保持一致）。
 *   3) 本文件改动优先保证与上游调用契约兼容，不隐式改变既有语义。
 */
// 基础校验实现：负责 ELF 头、表项尺寸与基础边界检查。
#include "zPatchElfValidator.h"

// PatchElf 模型。
#include "zPatchElf.h"

// 错误字符串组装。
#include <string>

// 基础格式校验：文件头、表项尺寸、基础边界关系。
bool zElfValidator::validateBasic(const PatchElf& elf, std::string* error) {
    // 读取头模型。
    const auto& header = elf.getHeaderModel();
    // 当前工具链仅支持 64 位 AArch64，其他目标直接拒绝。
    if (!header.isElf64AArch64()) {
        if (error) {
            *error = "Only ELF64 + AArch64 is supported";
        }
        return false;
    }

    // ELF 头声明的结构尺寸必须与本工具链使用的结构大小一致。
    if (header.raw.e_ehsize != sizeof(Elf64_Ehdr) ||
        header.raw.e_phentsize != sizeof(Elf64_Phdr) ||
        header.raw.e_shentsize != sizeof(Elf64_Shdr)) {
        // 头部声明尺寸异常会导致后续偏移解析失真。
        if (error) {
            *error = "ELF header entry size mismatch";
        }
        return false;
    }

    // 当前文件镜像大小。
    const size_t file_size = elf.getFileImageSize();
    // 文件非空时校验 PHT/SHT 区间边界。
    if (file_size > 0) {
        // 计算 PHT 末端（开区间）。
        const uint64_t ph_end = (uint64_t)header.raw.e_phoff +
                                (uint64_t)header.raw.e_phentsize * header.raw.e_phnum;
        // PHT 越界直接失败。
        if (ph_end > file_size) {
            if (error) {
                *error = "Program header table out of file range";
            }
            return false;
        }

        // 计算 SHT 末端（开区间）。
        const uint64_t sh_end = (uint64_t)header.raw.e_shoff +
                                (uint64_t)header.raw.e_shentsize * header.raw.e_shnum;
        // 仅在 e_shnum>0 时校验 SHT 越界。
        if (header.raw.e_shnum > 0 && sh_end > file_size) {
            if (error) {
                *error = "Section header table out of file range";
            }
            return false;
        }
    }

    // 每个 phdr 都必须满足 memsz >= filesz（加载器基本约束）。
    for (size_t programHeaderIndex = 0;
         programHeaderIndex < elf.getProgramHeaderModel().elements.size();
         ++programHeaderIndex) {
        // 当前 phdr 违反基本关系则失败。
        if (!elf.getProgramHeaderModel().elements[programHeaderIndex].isMemFileRelationValid()) {
            if (error) {
                *error = "memsz < filesz in phdr index " + std::to_string(programHeaderIndex);
            }
            return false;
        }
    }
    // 基础校验通过。
    return true;
}

