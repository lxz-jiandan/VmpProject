/**
 * @file zPatchElf.h
 * @brief PatchElf 主类 - ELF 文件操作的统一接口
 *
 * 本类提供 ELF 文件的完整操作接口，包括：
 * - 加载和解析 ELF 文件
 * - 修改 ELF 结构（添加/删除 Section/Segment）
 * - 重构文件布局
 * - 验证文件完整性
 * - 代码和数据注入
 *
 * 设计特点：
 * 1. 单视图架构：Model View（现代 C++ 容器）+ file_image_ 字节镜像
 * 2. 延迟重构：修改操作标记 dirty，在 save 时统一重构
 * 3. 零复制加载：直接在内存中操作，避免不必要的复制
 * 4. 类型安全：使用强类型封装，避免原始指针错误
 *
 * @author VmProtect Patchbay Team
 * @version 2.0 (2026-02-10)
 */

#ifndef VMP_PATCHBAY_PATCH_ELF_H
#define VMP_PATCHBAY_PATCH_ELF_H

#include "zPatchElfTypes.h"

#include "zPatchElfHeader.h"
#include "zProgramTable.h"
#include "zSectionTable.h"
#include "zPatchElfValidator.h"
#include "zSectionEntry.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

class PatchElf;

/**
 * @class PatchElf
 * @brief ELF 文件操作主类
 *
 * 提供完整的 ELF 文件加载、编辑、验证和保存功能。
 * 支持 ELF64 + AArch64 架构，兼容 Android linker。
 */
class PatchElf {
public:
    // ========================================================================
    // 构造函数和析构函数
    // ========================================================================

    /**
     * @brief 默认构造函数
     * @note 创建空的 PatchElf 对象，需要后续调用 loadElfFile() 加载文件
     */
    PatchElf();

    /**
     * @brief 从文件构造
     * @param elf_file_name ELF 文件路径
     * @note 自动加载并解析文件
     */
    explicit PatchElf(const char* elf_file_name);

    /**
     * @brief 析构函数
     * @note 释放所有分配的内存
     */
    ~PatchElf();

    // ========================================================================
    // 公共方法 - 文件操作
    // ========================================================================

    /**
     * @brief 从文件加载 ELF
     * @param elf_path ELF 文件路径
     * @return true 成功，false 失败
     * @note 读取整个文件到 file_image_，并构建 Model View
     */
    bool loadElfFile(const char* elf_path);

    /**
     * @brief 打印 ELF 布局信息
     * @note 输出 Program Headers 和 Section Headers 的详细信息到控制台
     */
    void printLayout();

    /**
     * @brief 重定位并扩展 Program Header Table
     * @param extra_entries 需要添加的 Program Header 数量
     * @param output_path 输出文件路径
     * @return true 成功，false 失败
     * @deprecated 请使用 Model View API 进行操作
     */
    bool relocateAndExpandPht(int extra_entries, const char* output_path);

    /**
     * @brief 重构 ELF 文件
     * @return true 成功，false 失败
     * @note 重新布局所有 Headers、Sections 和 Segments
     * @note 确保满足所有 ELF 约束（offset/vaddr 同余、无冲突等）
     */
    bool reconstruct();

    /**
     * @brief 保存 ELF 文件
     * @param output_path 输出文件路径
     * @return true 成功，false 失败
     * @note 如果 reconstruction_dirty_ 为 true，会自动调用 reconstruct()
     */
    bool save(const char* output_path);

    /**
     * @brief 判断 ELF 是否已成功加载并通过基础格式检查。
     */
    bool isLoaded() const;

    /**
     * @brief 获取当前文件镜像大小。
     */
    size_t fileImageSize() const;

    /**
     * @brief 获取当前文件镜像只读指针。
     */
    const uint8_t* fileImageData() const;

    /**
     * @brief 验证 ELF 文件完整性
     * @param error [输出] 错误信息（可选）
     * @return true 验证通过，false 验证失败
     * @note 执行 6 层验证：基础、Segment布局、Section映射、符号、PLT/GOT、重解析
     */
    bool validate(std::string* error = nullptr) const;

    // ========================================================================
    // 公共方法 - Model View 访问器
    // ========================================================================

    /**
     * @brief 获取 ELF Header 模型（可修改）
     * @return ELF Header 模型引用
     */
    zElfHeader& headerModel();

    /**
     * @brief 获取 Program Header Table 模型（可修改）
     * @return Program Header Table 模型引用
     */
    zElfProgramHeaderTable& programHeaderModel();

    /**
     * @brief 获取 Section Header Table 模型（可修改）
     * @return Section Header Table 模型引用
     */
    zElfSectionHeaderTable& sectionHeaderModel();

    /**
     * @brief 获取 ELF Header 模型（只读）
     * @return ELF Header 模型常量引用
     */
    const zElfHeader& headerModel() const;

    /**
     * @brief 获取 Program Header Table 模型（只读）
     * @return Program Header Table 模型常量引用
     */
    const zElfProgramHeaderTable& programHeaderModel() const;

    /**
     * @brief 获取 Section Header Table 模型（只读）
     * @return Section Header Table 模型常量引用
     */
    const zElfSectionHeaderTable& sectionHeaderModel() const;

    // ========================================================================
    // 公共方法 - 便捷访问器（段/节）
    // ========================================================================

    /**
     * @brief 按索引获取 Program Header（可写）。
     */
    zProgramTableElement* getProgramHeader(size_t idx);

    /**
     * @brief 按索引获取 Program Header（只读）。
     */
    const zProgramTableElement* getProgramHeader(size_t idx) const;

    /**
     * @brief 按类型获取首个 Program Header（可写）。
     */
    zProgramTableElement* findFirstProgramHeader(Elf64_Word type);

    /**
     * @brief 按类型获取首个 Program Header（只读）。
     */
    const zProgramTableElement* findFirstProgramHeader(Elf64_Word type) const;

    /**
     * @brief 按类型获取全部 Program Header（可写）。
     */
    std::vector<zProgramTableElement*> findAllProgramHeaders(Elf64_Word type);

    /**
     * @brief 按类型获取全部 Program Header（只读）。
     */
    std::vector<const zProgramTableElement*> findAllProgramHeaders(Elf64_Word type) const;

    /**
     * @brief 按索引获取 Section（可写）。
     */
    zSectionTableElement* getSection(size_t idx);

    /**
     * @brief 按索引获取 Section（只读）。
     */
    const zSectionTableElement* getSection(size_t idx) const;

    /**
     * @brief 按名称获取 Section（可写）。
     */
    zSectionTableElement* findSectionByName(const std::string& section_name);

    /**
     * @brief 按名称获取 Section（只读）。
     */
    const zSectionTableElement* findSectionByName(const std::string& section_name) const;

    /**
     * @brief 追加一个 Program Header。
     * @param ph 要追加的 Program Header。
     * @param out_index [输出] 新条目索引（可选）。
     */
    bool addProgramHeader(const zProgramTableElement& ph, size_t* out_index = nullptr);

    /**
     * @brief 追加一个普通 Section（默认使用基类节模型）。
     * @param name 节名称（将写入 .shstrtab）。
     * @param type 节类型（SHT_*）。
     * @param flags 节标志（SHF_*）。
     * @param addralign 对齐（sh_addralign）。
     * @param payload 节数据（SHT_NOBITS 可为空）。
     * @param out_index [输出] 新条目索引（可选）。
     */
    bool addSectionSimple(const std::string& name,
                          Elf64_Word type,
                          Elf64_Xword flags,
                          Elf64_Xword addralign,
                          const std::vector<uint8_t>& payload,
                          size_t* out_index = nullptr);

    /**
     * @brief 给指定 Section 追加空白数据（或扩大 NOBITS）。
     */
    bool addSectionPaddingByName(const std::string& section_name, size_t pad_size);

    /**
     * @brief 给指定 Section 追加空白数据（或扩大 NOBITS）。
     */
    bool addSectionPaddingByIndex(size_t idx, size_t pad_size);

    /**
     * @brief 给指定 Program Header 增加零填充的内存大小（仅扩容 memsz）。
     */
    bool addZeroFillToSegment(size_t idx, Elf64_Xword extra_memsz);

    /**
     * @brief 追加一个段（由 p_type 指定）。
     * @param type 段类型（PT_*）。
     * @param flags_text 三字符权限串（如 "R_X"/"RW_"/"R__"）。
     * @param out_index [输出] 新段索引（可选）。
     */
    bool addSegment(Elf64_Word type,
                     const std::string& flags_text,
                     size_t* out_index = nullptr);

    /**
     * @brief 追加一个 Section 并放置到指定 PT_LOAD 内（默认 PROGBITS+ALLOC）。
     * @param name 节名称。
     * @param load_segment_idx PT_LOAD 索引。
     * @param out_index [输出] 新节索引（可选）。
     */
    bool addSection(const std::string& name,
                     size_t load_segment_idx,
                     size_t* out_index = nullptr);

    /**
     * @brief 追加一个 Section（默认放到最后一个 PT_LOAD）。
     */
    bool addSection(const std::string& name, size_t* out_index = nullptr);

    /**
     * @brief 获取第一个 PT_LOAD 索引（不存在返回 -1）。
     */
    int getFirstLoadSegment() const;

    /**
     * @brief 获取最后一个 PT_LOAD 索引（不存在返回 -1）。
     */
    int getLastLoadSegment() const;

    /**
     * @brief 重构并输出文件。
     */
    bool relocate(const std::string& output_path);

    /**
     * @brief 恢复到原始加载状态（重新解析源文件）。
     */
    bool backup();

private:
    // ========================================================================
    // 私有数据结构
    // ========================================================================

    /**
     * @struct PendingBlob
     * @brief 待注入的数据块
     * @note 用于代码注入等操作，在重构时写入文件
     */
    struct PendingBlob {
        Elf64_Off offset = 0;        ///< 文件偏移（0 表示自动分配）
        Elf64_Addr vaddr = 0;         ///< 虚拟地址（用于地址计算）
        bool executable = false;      ///< 是否可执行（影响段标志位）
        std::vector<uint8_t> bytes;  ///< 数据内容
    };

    // ========================================================================
    // 私有成员 - Model View
    // ========================================================================

    /**
     * @brief ELF Header 模型
     * @note 现代 C++ 封装，提供类型安全的操作
     */
    zElfHeader header_model_;

    /**
     * @brief Program Header Table 模型
     * @note 使用 vector<zProgramTableElement> 管理
     */
    zElfProgramHeaderTable ph_table_model_;

    /**
     * @brief Section Header Table 模型
     * @note 使用 vector<unique_ptr<zSectionTableElement>> 管理（多态）
     */
    zElfSectionHeaderTable sh_table_model_;

    /**
     * @brief 文件镜像（完整的文件内容）
     * @note Model View 的数据源，修改后需要重构
     */
    std::vector<uint8_t> file_image_;

    /**
     * @brief 原始加载路径（用于 backup 重新解析）
     */
    std::string source_path_;

    /**
     * @brief 待注入的数据块列表
     * @note 在 reconstruction 时会分配空间并写入文件
     */
    std::vector<PendingBlob> pending_blobs_;

    /**
     * @brief 重构脏标志
     * @note true 表示 Model View 已修改，需要重构后才能保存
     */
    bool reconstruction_dirty_ = false;

    // ========================================================================
    // 私有方法
    // ========================================================================

    /**
     * @brief 重构实现（内部）
     * @return true 成功，false 失败
     * @note 当前版本已移除完整重构流程，仅保留最小桩实现。
     */
    bool reconstructionImpl();

    /**
     * @brief 虚拟地址 → 文件偏移转换
     * @param vaddr 虚拟地址
     * @param off [输出] 文件偏移
     * @return true 成功（vaddr 被某个 PT_LOAD 映射），false 失败
     * @note 遍历 PT_LOAD 段，查找包含 vaddr 的段
     */
    bool vaddrToFileOffset(Elf64_Addr vaddr, Elf64_Off* off) const;

    /**
     * @brief 文件偏移 → 虚拟地址转换
     * @param off 文件偏移
     * @return 虚拟地址（失败返回 0）
     * @note 遍历 PT_LOAD 段，查找包含 offset 的段
     */
    Elf64_Addr fileOffsetToVaddr(Elf64_Off off) const;

    /**
     * @brief 获取当前文件的最大结束偏移
     * @return 最大文件偏移（所有数据的末尾）
     * @note 用于确定新数据的分配位置
     */
    uint64_t currentMaxFileEnd() const;

    /**
     * @brief 获取当前最大的 LOAD 段虚拟地址结束位置
     * @return 最大虚拟地址（所有 LOAD 段的末尾）
     * @note 用于确定新段的虚拟地址
     */
    uint64_t currentMaxLoadVaddrEnd() const;
};

#endif // VMP_PATCHBAY_PATCH_ELF_H


