/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - VM 指令对象与序列化辅助实现。
 * - 加固链路位置：翻译结果落盘前处理。
 * - 输入：翻译后的 VM 指令流。
 * - 输出：可写入 txt/bin 的标准化表示。
 */
#include "zInst.h"
#include <sstream>  // std::ostringstream。
#include <iomanip>  // std::hex/std::setw/std::setfill。
#include <utility>  // std::move。

// 通过移动构造接管机器码与反汇编文本，避免不必要拷贝。
zInst::zInst(uint64_t address,
             std::vector<uint8_t> raw_bytes,
             uint32_t instruction_length,
             std::string asm_type,
             std::string disasm_text)
    // 保存地址。
    : addressValue(address),
      // 移动接管机器码字节数组（避免复制成本）。
      rawBytesValue(std::move(raw_bytes)),
      // 保存指令长度。
      instructionLengthValue(instruction_length),
      // 移动接管类型文本（例如 "add"/"bl"/"ret"）。
      asmTypeValue(std::move(asm_type)),
      // 移动接管反汇编文本（例如 "add x0, x0, #1"）。
      disasmTextValue(std::move(disasm_text)) {
    // 构造体主体无需额外逻辑。
}

uint64_t zInst::address() const {
    // 返回地址快照。
    return addressValue;
}

const std::vector<uint8_t>& zInst::rawBytes() const {
    // 返回机器码只读引用，避免额外拷贝。
    return rawBytesValue;
}

uint32_t zInst::instructionLength() const {
    // 返回指令长度。
    return instructionLengthValue;
}

const std::string& zInst::asmType() const {
    // 返回类型标签。
    return asmTypeValue;
}

const std::string& zInst::disasmText() const {
    // 返回反汇编文本。
    return disasmTextValue;
}

std::string zInst::getInfo() const {
    // 使用字符串流拼接统一输出格式，便于日志与回归脚本稳定匹配。
    std::ostringstream oss;

    // 统一输出地址、长度和指令类型。
    // 地址按十六进制显示，便于与反汇编工具对齐。
    oss << "addr=0x" << std::hex << addressValue << std::dec;
    // 输出长度。
    oss << ", len=" << instructionLengthValue;
    // 输出类型。
    oss << ", type=" << asmTypeValue;
    // 输出机器码前缀。
    oss << ", bytes=";

    // 机器码按两位十六进制拼接，格式与常见反汇编工具一致。
    for (size_t i = 0; i < rawBytesValue.size(); i++) {
        // 字节之间用空格分隔。
        if (i > 0) oss << ' ';
        // 每字节补齐两位十六进制（00~ff）。
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(rawBytesValue[i]);
    }
    // 恢复十进制流状态，避免影响后续数字输出。
    oss << std::dec;
    // 追加反汇编文本尾段。
    oss << ", text=" << disasmTextValue;
    // 返回完整信息字符串。
    return oss.str();
}
