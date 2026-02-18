#ifndef VMPROTECT_ZINST_H
#define VMPROTECT_ZINST_H

#include <vector>
#include <string>
#include <cstdint>

class zInst {
public:
    zInst() = default;
    zInst(uint64_t address,
          std::vector<uint8_t> raw_bytes,
          uint32_t instruction_length,
          std::string asm_type,
          std::string disasm_text);

    uint64_t address() const;
    const std::vector<uint8_t>& rawBytes() const;
    uint32_t instructionLength() const;
    const std::string& asmType() const;
    const std::string& disasmText() const;
    std::string getInfo() const;

private:
    uint64_t address_ = 0;
    std::vector<uint8_t> raw_bytes_;
    uint32_t instruction_length_ = 0;
    std::string asm_type_;
    std::string disasm_text_;
};

#endif
