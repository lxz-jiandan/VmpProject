#include "zInst.h"
#include <sstream>
#include <iomanip>
#include <utility>

// 通过移动构造接管机器码与反汇编文本，避免不必要拷贝。
zInst::zInst(uint64_t address,
             std::vector<uint8_t> raw_bytes,
             uint32_t instruction_length,
             std::string asm_type,
             std::string disasm_text)
    : address_(address),
      raw_bytes_(std::move(raw_bytes)),
      instruction_length_(instruction_length),
      asm_type_(std::move(asm_type)),
      disasm_text_(std::move(disasm_text)) {
}

uint64_t zInst::address() const {
    return address_;
}

const std::vector<uint8_t>& zInst::rawBytes() const {
    return raw_bytes_;
}

uint32_t zInst::instructionLength() const {
    return instruction_length_;
}

const std::string& zInst::asmType() const {
    return asm_type_;
}

const std::string& zInst::disasmText() const {
    return disasm_text_;
}

std::string zInst::getInfo() const {
    std::ostringstream oss;

    // 统一输出地址、长度和指令类型。
    oss << "addr=0x" << std::hex << address_ << std::dec;
    oss << ", len=" << instruction_length_;
    oss << ", type=" << asm_type_;
    oss << ", bytes=";

    // 机器码按两位十六进制拼接，格式与常见反汇编工具一致。
    for (size_t i = 0; i < raw_bytes_.size(); i++) {
        if (i > 0) oss << ' ';
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(raw_bytes_[i]);
    }
    oss << std::dec;
    oss << ", text=" << disasm_text_;
    return oss.str();
}
