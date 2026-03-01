/*
 * [VMP_FLOW_NOTE] zInstAsm 模块流程说明。
 * - 统一封装 Capstone 的打开/关闭/反汇编调用，避免上层重复处理资源细节。
 * - 统一提供反汇编文本辅助工具（mnemonic + op_str 拼装），供日志与 dump 复用。
 * - 让 zFunction 仅保留“函数级缓存与导出编排”，把汇编细节下沉到本模块。
 */
#ifndef VMPROTECT_ZINSTASM_H
#define VMPROTECT_ZINSTASM_H

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include <capstone/arm64.h>
#include <capstone/capstone.h>

// AArch64 -> VM 未编码中间结果。
// 该结构被 zFunction 的缓存路径与 dump 导出路径复用，属于翻译层与导出层之间的稳定接口。
struct zInstAsmUnencodedBytecode {
    // 函数前缀指令（与真实 ARM 地址解耦）：
    // 当前用于承载 OP_ALLOC_RETURN / OP_ALLOC_VSP 等运行时预置指令。
    // 注意：该容器中的指令不参与“地址->PC”映射，只在最终扁平指令流中位于最前面。
    std::vector<uint32_t> preludeWords;
    uint32_t registerCount = 0;
    std::vector<uint32_t> regList;
    uint32_t typeCount = 0;
    std::vector<uint32_t> typeTags;
    uint32_t initValueCount = 0;
    std::map<uint64_t, std::vector<uint32_t>> instByAddress;
    std::map<uint64_t, std::string> asmByAddress;
    uint32_t instCount = 0;
    uint32_t branchCount = 0;
    std::vector<uint32_t> branchWords;
    std::vector<uint32_t> branchLookupWords;
    std::vector<uint64_t> branchLookupAddrs;
    std::vector<uint64_t> branchAddrWords;
    bool translationOk = true;
    std::string translationError;
};

class zInstAsm {
public:
    // 打开 AArch64 Capstone 句柄。
    // 仅负责 cs_open；若失败会把 handle 置 0 并返回 false。
    static bool open(csh& handle);
    // 一步完成“打开句柄 + 开启 detail 模式”。
    // detail 模式是解析操作数(op_count/operands)所必需的前置条件。
    static bool openWithDetail(csh& handle);
    // 在已打开句柄上启用 CS_OPT_DETAIL。
    static bool enableDetail(csh handle);
    // 关闭句柄并清零，防止上层误用悬空句柄。
    static void close(csh& handle);

    // 反汇编 [code, code + size) 区间的全部指令。
    // baseAddr 作为反汇编地址基准写入 cs_insn.address。
    static size_t disasm(csh handle,
                         const uint8_t* code,
                         size_t size,
                         uint64_t baseAddr,
                         cs_insn*& outInsn);
    // 释放 disasm() 返回的指令缓存。
    static void freeInsn(cs_insn* insn, size_t count);

    // mnemonic / 文本辅助方法。
    // getMnemonic: 返回助记符字符串（空安全）。
    static std::string getMnemonic(const cs_insn& insn);
    // buildAsmText: 组装 "mnemonic op_str" 可读文本（dump/日志共用）。
    static std::string buildAsmText(const cs_insn& insn);

    // 端到端翻译入口：
    // 原始 ARM64 机器码 -> VM 未编码中间字节码结构。
    static zInstAsmUnencodedBytecode buildUnencodedBytecode(const uint8_t* code, size_t size, uint64_t baseAddr);
};

#endif
