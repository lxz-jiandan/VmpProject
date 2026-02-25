/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - zFunction 反汇编展示缓存实现（asm rebuild + lazy disasm）。
 * - 加固链路位置：离线分析可读输出路径。
 * - 输入：函数字节与未编码缓存。
 * - 输出：可读的 zInst 展示列表。
 */
#include "zFunction.h"

#include <sstream>

#include <capstone/arm64.h>
#include <capstone/capstone.h>

void zFunction::rebuildAsmListFromUnencoded() const {
    // 每次重建前先清空旧展示结果，避免残留。
    asm_list_.clear();
    // 把按地址缓存的 opcode 行重建成展示用的 zInst 列表。
    for (const auto& instEntry : inst_words_by_addr_cache_) {
        // map 键是原始指令地址。
        const uint64_t address = instEntry.first;
        // 未编码缓存不含真实原始字节，这里用 4 字节占位。
        std::vector<uint8_t> rawBytes(4, 0);
        std::string asmText;
        // 默认类型填 vm，表示这是虚拟化后的展示条目。
        std::string asmType = "vm";

        const auto asmTextIt = asm_text_by_addr_cache_.find(address);
        if (asmTextIt != asm_text_by_addr_cache_.end()) {
            asmText = asmTextIt->second;
            // 以首 token 作为 asmType（例如 mov/add/bl）。
            std::istringstream ss(asmText);
            ss >> asmType;
            if (asmType.empty()) asmType = "vm";
        }

        // 组装统一的 zInst 展示节点。
        asm_list_.emplace_back(address, std::move(rawBytes), 4u, std::move(asmType), std::move(asmText));
    }
    // 标记展示缓存可用。
    asm_ready_ = true;
}

// 确保反汇编展示列表可用：优先复用未编码缓存，其次走 Capstone。
void zFunction::ensureAsmReady() const {
    // 展示缓存已生成则直接返回。
    if (asm_ready_) {
        return;
    }

    // 未编码缓存已就绪时，直接重建展示列表，避免重复反汇编。
    if (unencoded_ready_) {
        rebuildAsmListFromUnencoded();
        return;
    }

    // 否则走真实 Capstone 反汇编路径重建展示列表。
    asm_list_.clear();
    if (!getData() || getSize() == 0) {
        asm_ready_ = true;
        return;
    }

    // 打开 Capstone 进行逐条反汇编。
    csh handle = 0;
    if (cs_open(CS_ARCH_AARCH64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        asm_ready_ = true;
        return;
    }

    cs_insn* insn = nullptr;
    const size_t instructionCount = cs_disasm(handle, getData(), getSize(), getOffset(), 0, &insn);
    // 逐条指令转成 zInst 结构，统一供 getAssemblyInfo() 输出。
    for (size_t instructionIndex = 0; instructionIndex < instructionCount; ++instructionIndex) {
        // 拿到单条反汇编结果。
        const cs_insn& instruction = insn[instructionIndex];
        std::vector<uint8_t> rawBytes(instruction.bytes, instruction.bytes + instruction.size);

        // mnemonic 作为类型，mnemonic + op_str 作为展示文本。
        std::string asmType = instruction.mnemonic ? instruction.mnemonic : "";
        std::string disasmText = asmType;
        if (instruction.op_str && instruction.op_str[0] != '\0') {
            disasmText += " ";
            disasmText += instruction.op_str;
        }

        asm_list_.emplace_back(
            instruction.address,
            std::move(rawBytes),
            static_cast<uint32_t>(instruction.size),
            std::move(asmType),
            std::move(disasmText)
        );
    }

    // 释放 Capstone 分配的指令数组。
    if (insn) {
        cs_free(insn, instructionCount);
    }
    // 关闭句柄并标记展示缓存完成。
    cs_close(&handle);
    asm_ready_ = true;
}
