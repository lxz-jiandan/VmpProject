/**
 * @file elf_loader.cpp
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
 * loadElfFile()
 *   ├─ 读取文件到 file_image_
 *   ├─ 验证 ELF64 + AArch64
 *   ├─ 解析 Program Header Table
 *   └─ 解析 Section Header Table
 * ```
 *
 * @version 2.0 (2026-02-10)
 * @see zPatchElf.h - 主类定义
 */

#include "zPatchElf.h"
#include "zPatchElfLoader.h"
#include "zElfFile.h"
#include "zLog.h"

// max/min。
#include <algorithm>
// 错误文本和路径字符串。
#include <string>

namespace zElfLoader {

/**
 * @brief 加载并解析 ELF 文件（命名空间级别的便捷函数）
 *
 * 这是一个高层封装函数，执行完整的加载和解析流程。
 * 如果任何步骤失败，对象会保持在一致但不完整的状态。
 *
 * 执行流程：
 * 1. 验证参数
 * 2. 调用 loadElfFile() 加载文件并构建模型
 *
 * @param elf [输出] PatchElf 对象指针，必须非空
 * @param elfPath ELF 文件路径，必须非空
 * @return true 成功加载并解析，false 失败
 *
 * @note 此函数不抛出异常，所有错误通过返回值处理
 * @note 失败时，elf 对象可能处于部分解析状态
 *
 * @see PatchElf::loadElfFile()
 */
bool loadFileAndParse(PatchElf* elf, const char* elfPath) {
    // 目标对象和路径都必须有效。
    if (!elf || !elfPath) {
        return false;
    }

    // 直接调用类方法执行加载+解析。
    return elf->loadElfFile(elfPath);
}

} // namespace zElfLoader

// ============================================================================
// 构造函数和析构函数
// ============================================================================

/**
 * @brief 默认构造函数
 *
 * 创建一个空的 PatchElf 对象，所有指针初始化为 nullptr。
 * 需要后续调用 loadElfFile() 或 zElfLoader::loadFileAndParse() 加载文件。
 *
 * @note 使用此构造函数后，对象处于未初始化状态
 * @see PatchElf::loadElfFile()
 */
PatchElf::PatchElf() {
    // 仅记录日志，不做任何 I/O。
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
 * PatchElf elf;
 * zElfLoader::loadFileAndParse(&elf, elfFileName);
 * @endcode
 *
 * @param elfFileName ELF 文件路径，必须非空
 *
 * @note 构造函数不抛出异常，需要检查对象状态判断是否加载成功
 */
PatchElf::PatchElf(const char* elfFileName) {
    // 打印入参，便于多文件批处理定位。
    LOGD("Constructor called with elfFileName: %s", elfFileName ? elfFileName : "(null)");
    // 复用命名空间级别封装入口。
    zElfLoader::loadFileAndParse(this, elfFileName);
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
 * @param elfPath ELF 文件路径，必须可读
 * @return true 成功加载，false 失败（文件不存在、格式错误、内存不足等）
 *
 * @note 失败时会清空 file_image_，对象处于干净状态
 * @note 成功后 file_image_ 与 Model View 就绪
 * @warning 不支持 ELF32 或其他架构（如 x86、ARM32）
 *
 * @see zElfHeader::isElf64AArch64()
 */
bool PatchElf::loadElfFile(const char* elfPath) {
    // 错误信息输出缓冲。
    std::string elf_error;
    // 临时字节缓冲。
    std::vector<uint8_t> loaded_bytes;

    // 读取 ELF 原始字节。
    if (!vmp::elfkit::internal::loadElfFileBytes(elfPath, &loaded_bytes, &elf_error)) {
        LOGE("Failed to load elf bytes: %s", elf_error.c_str());
        return false;
    }
    // 解析统一 ELF 视图（含头表范围校验）。
    vmp::elfkit::internal::ElfFileView64 elfView;
    if (!vmp::elfkit::internal::parseElfFileView64Aarch64(
            loaded_bytes.data(), loaded_bytes.size(), &elfView, &elf_error)) {
        LOGE("Failed to parse elf file view: %s", elf_error.c_str());
        return false;
    }

    // 记录源路径（供 backup 回滚）。
    source_path_ = elfPath;
    // 写入文件镜像。
    file_image_ = std::move(loaded_bytes);

    // 从统一视图回填 ELF Header 模型。
    if (file_image_.size() < sizeof(Elf64_Ehdr)) {
        file_image_.clear();
        return false;
    }
    header_model_.raw = *reinterpret_cast<const Elf64_Ehdr*>(file_image_.data());

    // 从字节镜像解析 phdr 表模型。
    const Elf64_Phdr* phRaw = nullptr;
    if (elfView.programHeaderCount > 0) {
        phRaw = reinterpret_cast<const Elf64_Phdr*>(file_image_.data() + header_model_.raw.e_phoff);
    }
    ph_table_model_.fromRaw(phRaw, elfView.programHeaderCount);

    // 校验并解析 Section Header Table（允许 e_shnum == 0）。
    if (elfView.sectionHeaderCount == 0) {
        // 无 section 场景直接清空 section 模型。
        sh_table_model_.elements.clear();
    } else {
        const Elf64_Shdr* shRaw = reinterpret_cast<const Elf64_Shdr*>(
            file_image_.data() + header_model_.raw.e_shoff);
        // 解析 section 模型（含 shstrtab 名称解析和多态节创建）。
        if (!sh_table_model_.fromRaw(file_image_.data(),
                                     file_image_.size(),
                                     shRaw,
                                     elfView.sectionHeaderCount,
                                     elfView.sectionNameTableIndex)) {
            file_image_.clear();
            return false;  // Section 解析失败
        }
    }

    // 清空待写 blob 状态，新加载文件应无 pending 注入数据。
    pending_blobs_.clear();
    // 标记当前模型与镜像一致，无需重构。
    reconstruction_dirty_ = false;
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
bool PatchElf::vaddrToFileOffset(Elf64_Addr vaddr, Elf64_Off* off) const {
    // 输出参数不能为空。
    if (!off) {
        return false;
    }
    // 遍历所有 Program Header。
    for (const auto& ph : ph_table_model_.elements) {
        // 仅 LOAD 且 memsz>0 的段可用于地址映射。
        if (ph.type != PT_LOAD || ph.memsz == 0) {
            continue;
        }
        // 段 VA 起点。
        const uint64_t seg_start = ph.vaddr;
        // 段 VA 终点（开区间）。
        const uint64_t seg_end = ph.vaddr + ph.memsz;
        // 不在段 VA 范围内则继续。
        if (vaddr < seg_start || vaddr >= seg_end) {
            continue;
        }
        // 计算段内偏移。
        const uint64_t delta = vaddr - seg_start;
        // 超过 filesz 说明落在 BSS（无文件偏移）。
        if (delta >= ph.filesz) {
            return false;
        }
        // 计算并回写文件偏移。
        *off = (Elf64_Off)(ph.offset + delta);
        return true;
    }
    // 未找到匹配 LOAD。
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
Elf64_Addr PatchElf::fileOffsetToVaddr(Elf64_Off off) const {
    // 遍历所有 Program Header。
    for (const auto& ph : ph_table_model_.elements) {
        // 仅 LOAD 且 filesz>0 才有文件区间映射。
        if (ph.type != PT_LOAD || ph.filesz == 0) {
            continue;
        }
        // 段文件起点。
        const uint64_t seg_start = ph.offset;
        // 段文件终点（开区间）。
        const uint64_t seg_end = ph.offset + ph.filesz;
        // 当前偏移不在段内则继续。
        if (off < seg_start || off >= seg_end) {
            continue;
        }
        // 命中后按线性关系回推 VA。
        return (Elf64_Addr)(ph.vaddr + (off - ph.offset));
    }
    // 未命中返回 0。
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
 * LOAD 1: offset=0x0000  filesz=0x2000  → getFileEnd=0x2000
 * LOAD 2: offset=0x2000  filesz=0x1500  → getFileEnd=0x3500
 *
 * getMaxFileEnd() = max(0x3000, 0x2000, 0x3500) = 0x3500
 * ```
 *
 * @return 文件的最大结束偏移（字节）
 *
 * @note 使用 Model View (ph_table_model_)
 * @note 只考虑 PT_LOAD 段（其他段不占文件空间或不需要加载）
 * @note 用于 reconstruction 时分配新数据块的起始位置
 *
 * @see zProgramTableElement::getFileEnd() - 返回 offset + filesz
 * @see getMaxLoadVaddrEnd() - 计算虚拟地址范围
 */
uint64_t PatchElf::getMaxFileEnd() const {
    // 初始值取当前文件镜像大小。
    uint64_t max_end = file_image_.size();
    // 扫描所有 LOAD 段的文件结束位置。
    for (const auto& ph : ph_table_model_.elements) {
        if (ph.type == PT_LOAD) {
            max_end = std::max(max_end, ph.getFileEnd());
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
 * LOAD 1 (RX): vaddr=0x400000  memsz=0x2000  → getVaddrEnd=0x402000
 * LOAD 2 (RW): vaddr=0x410000  memsz=0x3000  → getVaddrEnd=0x413000
 *
 * getMaxLoadVaddrEnd() = max(0x402000, 0x413000) = 0x413000
 * ```
 *
 * @return 最大的虚拟地址结束位置
 *
 * @note 使用 Model View (ph_table_model_)
 * @note 只考虑 PT_LOAD 段（其他段不参与虚拟地址空间布局）
 * @note 用于 reconstruction 时分配新段的虚拟地址
 * @note 使用 p_memsz 而不是 p_filesz（包含 BSS 段等未初始化数据）
 *
 * @see zProgramTableElement::getVaddrEnd() - 返回 vaddr + memsz
 * @see getMaxFileEnd() - 计算文件偏移范围
 */
uint64_t PatchElf::getMaxLoadVaddrEnd() const {
    // 初始 VA 结束位置为 0。
    uint64_t max_end = 0;
    // 扫描所有 LOAD 段。
    for (const auto& ph : ph_table_model_.elements) {
        if (ph.type == PT_LOAD) {
            max_end = std::max(max_end, ph.getVaddrEnd());
        }
    }
    return max_end;
}

