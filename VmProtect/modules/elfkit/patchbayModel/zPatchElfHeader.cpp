/*
 * [VMP_FLOW_NOTE] 文件级流程注释。
 * - 文件：patchbayModel/zPatchElfHeader.cpp
 * - 主要职责：ELF Header 处理：负责 ELF 头字段读取、校验与重建策略。
 * - 输入：ELF 原始字节、补丁模型状态以及段/节/符号元数据。
 * - 输出：经过校验的补丁模型或重建后的 ELF 输出数据。
 * - 关键约束：
 *   1) 严格保持 ELF 布局与索引一致性，避免地址/偏移漂移。
 *   2) 失败路径必须可定位（返回值/错误信息/日志三者保持一致）。
 *   3) 本文件改动优先保证与上游调用契约兼容，不隐式改变既有语义。
 */
#include "zPatchElfHeader.h"

// memcpy。
#include <cstring>

/**
 * @file zPatchElfHeader.cpp
 * @brief ELF 文件头（Elf64_Ehdr）轻量封装实现。
 *
 * 设计约束：
 * - 本文件只负责“原始字节 -> 头结构体”的安全转换；
 * - 只做最小格式识别（ELF64 + 小端 + AArch64）；
 * - 更深层语义校验（表范围、布局一致性）交由校验模块处理。
 */

// 从原始字节拷贝 ELF 头。
bool zElfHeader::fromRaw(const uint8_t* data, size_t size) {
    // 防御式检查：输入指针必须有效。
    if (!data) {
        return false;
    }
    // 需要至少具备完整 ELF64 头长度。
    if (size < sizeof(Elf64_Ehdr)) {
        return false;
    }
    // Elf64_Ehdr 是定长 POD，可直接按字节复制。
    std::memcpy(&raw, data, sizeof(Elf64_Ehdr));
    // 复制完成。
    return true;
}

// 校验是否为本工程支持的目标格式。
bool zElfHeader::isElf64AArch64() const {
    // 依次检查 ELF 魔数（0x7F 'E' 'L' 'F'）。
    return raw.e_ident[EI_MAG0] == ELFMAG0 &&
           raw.e_ident[EI_MAG1] == ELFMAG1 &&
           raw.e_ident[EI_MAG2] == ELFMAG2 &&
           raw.e_ident[EI_MAG3] == ELFMAG3 &&
           // 检查位宽为 64 位。
           raw.e_ident[EI_CLASS] == ELFCLASS64 &&
           // 检查字节序为小端。
           raw.e_ident[EI_DATA] == ELFDATA2LSB &&
           // 检查目标机器为 AArch64。
           raw.e_machine == EM_AARCH64;
}
