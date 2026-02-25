/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - VM 指令结构声明。
 * - 加固链路位置：翻译表示层。
 * - 输入：指令字段（opcode/operand）。
 * - 输出：统一的 VM 指令模型。
 */
#ifndef VMPROTECT_ZINST_H
#define VMPROTECT_ZINST_H

#include <vector>   // std::vector（机器码字节容器）。
#include <string>   // std::string（文本字段）。
#include <cstdint>  // uint64_t/uint32_t。

class zInst {
public:
    // 空指令对象：
    // 使用类内默认成员初始值，不做额外初始化动作。
    zInst() = default;

    // 构造一条反汇编指令快照。
    // 参数语义：
    // 1) address：指令地址；
    // 2) raw_bytes：机器码字节；
    // 3) instruction_length：指令长度；
    // 4) asm_type：指令类别；
    // 5) disasm_text：反汇编文本。
    zInst(uint64_t address,
          std::vector<uint8_t> raw_bytes,
          uint32_t instruction_length,
          std::string asm_type,
          std::string disasm_text);

    // 基础访问器：返回指令地址、机器码、长度和反汇编信息。
    // 设计要点：
    // 1) 所有接口均为 const，保证调用不改变对象状态；
    // 2) `rawBytes()` 返回 const 引用，避免不必要复制。
    uint64_t address() const;
    const std::vector<uint8_t>& rawBytes() const;
    uint32_t instructionLength() const;
    const std::string& asmType() const;
    const std::string& disasmText() const;

    // 拼接可读字符串，便于日志打印和回归比对。
    // 格式在 cpp 中固定为：
    // addr=0x..., len=..., type=..., bytes=..., text=...
    std::string getInfo() const;

private:
    // 指令起始地址。
    uint64_t addressValue = 0;
    // 原始机器码字节。
    std::vector<uint8_t> rawBytesValue;
    // 指令长度（字节数）。
    uint32_t instructionLengthValue = 0;
    // 指令类型标签（通常对应 mnemonic）。
    std::string asmTypeValue;
    // 可读反汇编文本（通常是 mnemonic + operands）。
    std::string disasmTextValue;
};

#endif
