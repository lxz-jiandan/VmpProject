/**
 * @file zElfLoader.cpp
 * @brief ELF 文件加载和解析模块
 *
 * 本文件实现 ELF 文件的加载与解析流程，包括：
 * 1. 文件加载 - 读取完整文件到内存（file_image_）
 * 2. ELF Header 解析 - 验证魔数、架构和基本信息
 * 3. Program Header 解析 - 构建 Program Header 模型
 * 4. Section Header 解析 - 构建 Section 模型（支持多态）
 *
 * 关键特性：
 * - 单视图架构：Model View + file_image_ 字节镜像
 * - 零复制设计：直接在文件镜像上构建模型，避免额外复制
 * - 虚拟地址转换：提供 vaddr ↔ offset 双向转换功能
 * - 多态 Section 创建：根据 section 类型自动创建特定的派生类对象
 *
 * 解析流程：
 * ```
 * load_elf_file()
 *   ├─ 读取文件到 file_image_
 *   ├─ 验证 ELF64 + AArch64
 *   ├─ 解析 Program Header Table
 *   └─ 解析 Section Header Table
 * ```
 *
 * @version 2.0 (2026-02-10)
 * @see zElf.h - 主类定义
 */

#include "zElf.h"
#include "zElfLoader.h"
#include "zLog.h"

#include <algorithm>
#include <cstdio>

namespace zElfLoader {

/**
 * @brief 加载并解析 ELF 文件（命名空间级别的便捷函数）
 *
 * 这是一个高层封装函数，执行完整的加载和解析流程。
 * 如果任何步骤失败，对象会保持在一致但不完整的状态。
 *
 * 执行流程：
 * 1. 验证参数
 * 2. 调用 load_elf_file() 加载文件并构建模型
 *
 * @param elf [输出] zElf 对象指针，必须非空
 * @param elf_path ELF 文件路径，必须非空
 * @return true 成功加载并解析，false 失败
 *
 * @note 此函数不抛出异常，所有错误通过返回值处理
 * @note 失败时，elf 对象可能处于部分解析状态
 *
 * @see zElf::load_elf_file()
 */
bool loadFileAndParse(zElf* elf, const char* elf_path) {
    if (!elf || !elf_path) {
        return false;
    }

    // 加载文件并构建 Model View。
    return elf->load_elf_file(elf_path);
}

} // namespace zElfLoader

// ============================================================================
// 构造函数和析构函数
// ============================================================================

/**
 * @brief 默认构造函数
 *
 * 创建一个空的 zElf 对象，所有指针初始化为 nullptr。
 * 需要后续调用 load_elf_file() 或 zElfLoader::loadFileAndParse() 加载文件。
 *
 * @note 使用此构造函数后，对象处于未初始化状态
 * @see zElf::load_elf_file()
 */
zElf::zElf() {
    LOGD("Default constructor called");
}

/**
 * @brief 从文件路径构造
 *
 * 便捷构造函数，自动加载并解析指定的 ELF 文件。
 * 如果加载失败，对象会被部分初始化（可查询但不完整）。
 *
 * 等价于：
 * @code
 * zElf elf;
 * zElfLoader::loadFileAndParse(&elf, elf_file_name);
 * @endcode
 *
 * @param elf_file_name ELF 文件路径，必须非空
 *
 * @note 构造函数不抛出异常，需要检查对象状态判断是否加载成功
 */
zElf::zElf(const char* elf_file_name) {
    LOGD("Constructor called with elf_file_name: %s", elf_file_name ? elf_file_name : "(null)");
    zElfLoader::loadFileAndParse(this, elf_file_name);
}

// ============================================================================
// 文件加载
// ============================================================================

/**
 * @brief 从磁盘加载 ELF 文件
 *
 * 完整的文件加载流程，包括文件读取、格式验证和 Model View 构建。
 * 这是 ELF 解析的入口函数。
 *
 * 执行步骤：
 * 1. 打开文件并读取到 file_image_（vector<uint8_t>）
 * 2. 验证 ELF 魔数、64 位格式和 AArch64 架构
 * 3. 验证 Program Header Table 在文件范围内
 * 4. 解析 Program Headers 到 ph_table_model_
 * 5. 验证 Section Header Table 在文件范围内
 * 6. 解析 Section Headers 到 sh_table_model_（多态创建特定类型的 Section）
 * 7. 清空 pending_blobs_（新加载的文件没有待注入数据）
 *
 * 支持的格式：
 * - ELF64（64 位）
 * - AArch64（ARM 64 位）
 * - 小端序（Little Endian）
 *
 * @param elf_path ELF 文件路径，必须可读
 * @return true 成功加载，false 失败（文件不存在、格式错误、内存不足等）
 *
 * @note 失败时会清空 file_image_，对象处于干净状态
 * @note 成功后 file_image_ 与 Model View 就绪
 * @warning 不支持 ELF32 或其他架构（如 x86、ARM32）
 *
 * @see zElfHeader::isElf64AArch64()
 */
bool zElf::load_elf_file(const char* elf_path) {
    if (!elf_path) {
        return false;
    }
    source_path_ = elf_path;

    // 打开文件（二进制只读模式）
    FILE* fp = std::fopen(elf_path, "rb");
    if (!fp) {
        LOGE("Failed to open file: %s", elf_path);
        return false;
    }

    // 获取文件大小
    std::fseek(fp, 0, SEEK_END);
    long size_signed = std::ftell(fp);
    std::fseek(fp, 0, SEEK_SET);
    if (size_signed <= 0) {
        std::fclose(fp);
        file_image_.clear();
        return false;  // 文件为空或 ftell 失败
    }

    // 读取整个文件到 file_image_
    const size_t file_size = (size_t)size_signed;
    file_image_.assign(file_size, 0);
    size_t read_size = std::fread(file_image_.data(), 1, file_size, fp);
    std::fclose(fp);

    if (read_size != file_size) {
        file_image_.clear();
        return false;  // 读取不完整
    }

    // 验证 ELF 格式并解析 Header
    if (!header_model_.fromRaw(file_image_.data(), file_image_.size()) || !header_model_.isElf64AArch64()) {
        file_image_.clear();
        return false;  // 不是有效的 ELF64 + AArch64 文件
    }

    const Elf64_Ehdr& header = header_model_.raw;

    // 验证并解析 Program Header Table
    if ((uint64_t)header.e_phoff + (uint64_t)header.e_phentsize * header.e_phnum > file_image_.size()) {
        file_image_.clear();
        return false;  // PHT 超出文件范围
    }
    ph_table_model_.fromRaw(reinterpret_cast<const Elf64_Phdr*>(file_image_.data() + header.e_phoff), header.e_phnum);

    // 验证并解析 Section Header Table（允许 e_shnum == 0）
    if (header.e_shnum == 0) {
        sh_table_model_.elements.clear();
    } else {
        if ((uint64_t)header.e_shoff + (uint64_t)header.e_shentsize * header.e_shnum > file_image_.size()) {
            file_image_.clear();
            return false;  // SHT 超出文件范围
        }
        if (!sh_table_model_.fromRaw(file_image_.data(),
                                     file_image_.size(),
                                     reinterpret_cast<const Elf64_Shdr*>(file_image_.data() + header.e_shoff),
                                     header.e_shnum,
                                     header.e_shstrndx)) {
            file_image_.clear();
            return false;  // Section 解析失败
        }
    }

    // 清空状态标志
    pending_blobs_.clear();        // 新加载的文件没有待注入数据
    reconstruction_dirty_ = false; // 刚加载，无需重构
    return true;
}

// ============================================================================
// 地址转换函数
// ============================================================================

/**
 * @brief 虚拟地址 → 文件偏移转换
 *
 * 遍历所有 PT_LOAD 段，查找包含 vaddr 的段，计算对应的文件偏移。
 *
 * 算法：
 * 1. 遍历所有 PT_LOAD 段
 * 2. 检查 vaddr 是否在 [p_vaddr, p_vaddr + p_memsz) 范围内
 * 3. 计算 delta = vaddr - p_vaddr
 * 4. 验证 delta < p_filesz（确保在文件范围内，不是 BSS）
 * 5. 返回 offset = p_offset + delta
 *
 * 示例：
 * ```
 * LOAD 段: offset=0x1000  vaddr=0x400000  filesz=0x2000  memsz=0x3000
 *
 * vaddr=0x400500 → offset=0x1500  (在文件范围内)
 * vaddr=0x402500 → 失败 (在 BSS 范围，无对应文件偏移)
 * ```
 *
 * @param vaddr 虚拟地址
 * @param off [输出] 文件偏移
 * @return true 成功（vaddr 被某个 PT_LOAD 映射且在文件范围内），false 失败
 *
 * @note 使用 Model View (ph_table_model_)
 * @note 只检查 PT_LOAD 段（PT_DYNAMIC 等不参与地址映射）
 *
 * @see fileOffsetToVaddr() - 反向转换
 */
bool zElf::vaddrToFileOffset(Elf64_Addr vaddr, Elf64_Off* off) const {
    if (!off) {
        return false;
    }
    for (const auto& ph : ph_table_model_.elements) {
        if (ph.type != PT_LOAD || ph.memsz == 0) {
            continue;
        }
        const uint64_t seg_start = ph.vaddr;
        const uint64_t seg_end = ph.vaddr + ph.memsz;
        if (vaddr < seg_start || vaddr >= seg_end) {
            continue;
        }
        const uint64_t delta = vaddr - seg_start;
        if (delta >= ph.filesz) {
            return false;
        }
        *off = (Elf64_Off)(ph.offset + delta);
        return true;
    }
    return false;
}

/**
 * @brief 文件偏移 → 虚拟地址转换（反向转换）
 *
 * 遍历所有 PT_LOAD 段，查找包含 off 的段，计算对应的虚拟地址。
 * 这是 vaddrToFileOffset() 的反向操作。
 *
 * 算法：
 * 1. 遍历所有 PT_LOAD 段
 * 2. 检查 off 是否在 [p_offset, p_offset + p_filesz) 范围内
 * 3. 计算 delta = off - p_offset
 * 4. 返回 vaddr = p_vaddr + delta
 *
 * 示例：
 * ```
 * LOAD 段: offset=0x1000  vaddr=0x400000  filesz=0x2000
 *
 * off=0x1500 → vaddr=0x400500  (文件偏移 +0x500 → 虚拟地址 +0x500)
 * off=0x3000 → 失败 (不在任何 LOAD 段范围内)
 * ```
 *
 * @param off 文件偏移
 * @return 虚拟地址（失败返回 0）
 *
 * @note 返回 0 可能表示失败，也可能是合法的虚拟地址 0
 * @note 只检查 PT_LOAD 段（其他段不参与地址映射）
 *
 * @see vaddrToFileOffset() - 正向转换
 */
Elf64_Addr zElf::fileOffsetToVaddr(Elf64_Off off) const {
    for (const auto& ph : ph_table_model_.elements) {
        if (ph.type != PT_LOAD || ph.filesz == 0) {
            continue;
        }
        const uint64_t seg_start = ph.offset;
        const uint64_t seg_end = ph.offset + ph.filesz;
        if (off < seg_start || off >= seg_end) {
            continue;
        }
        return (Elf64_Addr)(ph.vaddr + (off - ph.offset));
    }
    return 0;
}

// ============================================================================
// 辅助函数 - 计算当前文件和虚拟地址范围
// ============================================================================

/**
 * @brief 计算当前文件的最大结束偏移
 *
 * 遍历所有 PT_LOAD 段，找到最大的文件结束位置（p_offset + p_filesz）。
 * 这个值用于确定在哪里分配新的数据块，避免与现有内容冲突。
 *
 * 计算规则：
 * 1. 初始值为 file_image_.size()（当前文件大小）
 * 2. 遍历所有 PT_LOAD 段，更新为 max(max_end, p_offset + p_filesz)
 * 3. 返回最大的结束偏移
 *
 * 示例：
 * ```
 * file_image_.size() = 0x3000
 * LOAD 1: offset=0x0000  filesz=0x2000  → fileEnd=0x2000
 * LOAD 2: offset=0x2000  filesz=0x1500  → fileEnd=0x3500
 *
 * currentMaxFileEnd() = max(0x3000, 0x2000, 0x3500) = 0x3500
 * ```
 *
 * @return 文件的最大结束偏移（字节）
 *
 * @note 使用 Model View (ph_table_model_)
 * @note 只考虑 PT_LOAD 段（其他段不占文件空间或不需要加载）
 * @note 用于 reconstruction 时分配新数据块的起始位置
 *
 * @see zProgramTableElement::fileEnd() - 返回 offset + filesz
 * @see currentMaxLoadVaddrEnd() - 计算虚拟地址范围
 */
uint64_t zElf::currentMaxFileEnd() const {
    uint64_t max_end = file_image_.size();
    for (const auto& ph : ph_table_model_.elements) {
        if (ph.type == PT_LOAD) {
            max_end = std::max(max_end, ph.fileEnd());
        }
    }
    return max_end;
}

/**
 * @brief 计算当前最大的 LOAD 段虚拟地址结束位置
 *
 * 遍历所有 PT_LOAD 段，找到最大的虚拟地址结束位置（p_vaddr + p_memsz）。
 * 这个值用于确定新段的虚拟地址，确保不与现有段冲突。
 *
 * 计算规则：
 * 1. 初始值为 0
 * 2. 遍历所有 PT_LOAD 段，更新为 max(max_end, p_vaddr + p_memsz)
 * 3. 返回最大的虚拟地址结束位置
 *
 * 示例：
 * ```
 * LOAD 1 (RX): vaddr=0x400000  memsz=0x2000  → vaddrEnd=0x402000
 * LOAD 2 (RW): vaddr=0x410000  memsz=0x3000  → vaddrEnd=0x413000
 *
 * currentMaxLoadVaddrEnd() = max(0x402000, 0x413000) = 0x413000
 * ```
 *
 * @return 最大的虚拟地址结束位置
 *
 * @note 使用 Model View (ph_table_model_)
 * @note 只考虑 PT_LOAD 段（其他段不参与虚拟地址空间布局）
 * @note 用于 reconstruction 时分配新段的虚拟地址
 * @note 使用 p_memsz 而不是 p_filesz（包含 BSS 段等未初始化数据）
 *
 * @see zProgramTableElement::vaddrEnd() - 返回 vaddr + memsz
 * @see currentMaxFileEnd() - 计算文件偏移范围
 */
uint64_t zElf::currentMaxLoadVaddrEnd() const {
    uint64_t max_end = 0;
    for (const auto& ph : ph_table_model_.elements) {
        if (ph.type == PT_LOAD) {
            max_end = std::max(max_end, ph.vaddrEnd());
        }
    }
    return max_end;
}
