#ifndef VMPROTECT_ZFUNCTION_H
#define VMPROTECT_ZFUNCTION_H

#include "elf.h"
#include "zInst.h"
#include "zFunctionData.h"
#include <string>
#include <vector>
#include <map>
#include <cstddef>
#include <cstdint>

class zFunction : public zFunctionData {
public:
    // 导出模式：文本未编码、二进制未编码、最终编码。
    enum class DumpMode {
        UNENCODED,
        UNENCODED_BIN,
        ENCODED,
    };

    // 基于现有 zFunctionData 构造函数对象。
    explicit zFunction(const zFunctionData& data);

    // 基础访问器。
    const std::string& name() const;
    Elf64_Addr offset() const;
    size_t size() const;
    const uint8_t* data() const;
    bool empty() const;

    // 反汇编分析与输出。
    zFunction& analyzeAssembly();
    const std::vector<zInst>& assemblyList() const;
    std::string assemblyInfo() const;

    // 按指定模式导出到文件。
    bool dump(const char* file_path, DumpMode mode) const;

    // 读取当前未编码缓存中的 branch_addr_list（会触发懒加载）。
    const std::vector<uint64_t>& sharedBranchAddrs() const;

    // 将 OP_BL 的局部索引重映射到全局 branch_addr_list，并替换缓存中的地址表。
    bool remapBlToSharedBranchAddrs(const std::vector<uint64_t>& shared_branch_addrs);

    // 从未编码文本/二进制直接创建 zFunction。
    static zFunction fromUnencodedTxt(const char* file_path, const std::string& function_name = "", Elf64_Addr function_offset = 0);
    static zFunction fromUnencodedBin(const char* file_path, const std::string& function_name = "", Elf64_Addr function_offset = 0);

    // 读取未编码文本/二进制到当前对象。
    bool loadUnencodedTxt(const char* file_path);
    bool loadUnencodedBin(const char* file_path);

private:
    // 确保反汇编缓存与未编码缓存可用。
    void ensure_asm_ready() const;
    void ensure_unencoded_ready() const;

    // 更新未编码缓存快照。
    void set_unencoded_cache(
        uint32_t register_count,
        std::vector<uint32_t> reg_id_list,
        uint32_t type_count,
        std::vector<uint32_t> type_tags,
        uint32_t init_value_count,
        std::map<uint64_t, std::vector<uint32_t>> inst_by_address,
        std::map<uint64_t, std::string> asm_by_address,
        uint32_t inst_count,
        uint32_t branch_count,
        std::vector<uint32_t> branch_words,
        std::vector<uint64_t> branch_addr_words
    ) const;

    // 用未编码缓存重建 asm_list_。
    void rebuild_asm_list_from_unencoded() const;

    mutable bool asm_ready_ = false;
    mutable std::vector<zInst> asm_list_;

    mutable bool unencoded_ready_ = false;
    mutable uint32_t register_count_cache_ = 0;
    mutable std::vector<uint32_t> register_ids_cache_;
    mutable uint32_t type_count_cache_ = 0;
    mutable std::vector<uint32_t> type_tags_cache_;
    mutable uint32_t init_value_count_cache_ = 0;
    mutable std::map<uint64_t, std::vector<uint32_t>> inst_words_by_addr_cache_;
    mutable std::map<uint64_t, std::string> asm_text_by_addr_cache_;
    mutable uint32_t inst_count_cache_ = 0;
    mutable uint32_t branch_count_cache_ = 0;
    mutable std::vector<uint32_t> branch_words_cache_;
    mutable std::vector<uint64_t> branch_addrs_cache_;
};

#endif

