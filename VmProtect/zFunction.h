#ifndef VMPROTECT_ZFUNCTION_H
#define VMPROTECT_ZFUNCTION_H

#include "elf.h"
#include "zInst.h"
#include <string>
#include <vector>
#include <map>
#include <cstddef>
#include <cstdint>

class zFunction {
public:
    enum class DumpMode {
        UNENCODED,
        UNENCODED_BIN,
        ENCODED,
    };

    zFunction() = default;
    zFunction(std::string function_name, Elf64_Addr function_offset, std::vector<uint8_t> function_bytes);

    const std::string& name() const;
    Elf64_Addr offset() const;
    size_t size() const;
    const uint8_t* data() const;
    bool empty() const;

    zFunction& analyzeAsm();
    zFunction& analyzeasm();
    const std::vector<zInst>& asmList() const;
    const std::vector<zInst>& asmlist() const;
    std::string getAsmInfo() const;
    std::string getasminfo() const;
    bool dump(const char* file_path, DumpMode mode) const;

    static zFunction fromUnencodedTxt(const char* file_path, const std::string& function_name = "", Elf64_Addr function_offset = 0);
    static zFunction fromUnencodedBin(const char* file_path, const std::string& function_name = "", Elf64_Addr function_offset = 0);
    bool loadUnencodedTxt(const char* file_path);
    bool loadUnencodedBin(const char* file_path);

private:
    void ensure_asm_ready() const;
    void ensure_unencoded_ready() const;
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
    void rebuild_asm_list_from_unencoded() const;

    std::string function_name_;
    Elf64_Addr function_offset_ = 0;
    std::vector<uint8_t> function_bytes_;
    mutable bool asm_ready_ = false;
    mutable std::vector<zInst> asm_list_;

    mutable bool unencoded_ready_ = false;
    mutable uint32_t unencoded_register_count_ = 0;
    mutable std::vector<uint32_t> unencoded_reg_list_;
    mutable uint32_t unencoded_type_count_ = 0;
    mutable std::vector<uint32_t> unencoded_type_tags_;
    mutable uint32_t unencoded_init_value_count_ = 0;
    mutable std::map<uint64_t, std::vector<uint32_t>> unencoded_inst_by_address_;
    mutable std::map<uint64_t, std::string> unencoded_asm_by_address_;
    mutable uint32_t unencoded_inst_count_ = 0;
    mutable uint32_t unencoded_branch_count_ = 0;
    mutable std::vector<uint32_t> unencoded_branch_words_;
    mutable std::vector<uint64_t> unencoded_branch_addr_words_;
};

#endif
