#ifndef VMPROTECT_ZINST_H
#define VMPROTECT_ZINST_H

#include <vector>
#include <string>
#include <cstdint>

class zInst {
public:
    // 空指令对象，字段均保持默认值。
    zInst() = default;

    // 构造一条反汇编指令快照。
    zInst(uint64_t address,
          std::vector<uint8_t> raw_bytes,
          uint32_t instruction_length,
          std::string asm_type,
          std::string disasm_text);

    // 基础访问器：返回指令地址、机器码、长度和反汇编信息。
    uint64_t address() const;
    const std::vector<uint8_t>& rawBytes() const;
    uint32_t instructionLength() const;
    const std::string& asmType() const;
    const std::string& disasmText() const;

    // 拼接可读字符串，便于日志打印。
    std::string getInfo() const;

private:
    uint64_t address_ = 0;
    std::vector<uint8_t> raw_bytes_;
    uint32_t instruction_length_ = 0;
    std::string asm_type_;
    std::string disasm_text_;
};

#endif
