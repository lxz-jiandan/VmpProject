#ifndef Z_FUNCTION_DATA_H
#define Z_FUNCTION_DATA_H

#include <cstddef>  // size_t。
#include <cstdint>  // 固定宽度整数类型。
#include <string>   // std::string。
#include <vector>   // std::vector。

class zFunctionData {
public:
    // 函数元信息（来自 ELF 或文本导出阶段）。
    // 函数名（调试/日志用途）。
    std::string function_name;
    // 函数地址（在 Engine 侧通常是 so 内偏移或实际地址）。
    uint64_t function_offset = 0;
    // 可选：函数原始机器码（当前主流程不强依赖）。
    std::vector<uint8_t> function_bytes;

    // 编码字节码载荷字段（供序列化/反序列化使用）。
    // 协议 marker（必须可落在 6 bit）。
    uint32_t marker = 0;
    // 寄存器槽数量。
    uint32_t register_count = 0;
    // “首段初始化指令”数量。
    uint32_t first_inst_count = 0;
    // 首段初始化 opcode 列表，长度应等于 first_inst_count。
    std::vector<uint32_t> first_inst_opcodes;
    // 外部初始化映射表：按 [targetReg, externalIndex] 成对编码。
    std::vector<uint32_t> external_init_words;
    // 类型表数量。
    uint32_t type_count = 0;
    // 类型标签数组（由 zTypeManager::createFromCode 解释）。
    std::vector<uint32_t> type_tags;
    // 内部初始化值条目数量。
    uint32_t init_value_count = 0;
    // 初始化值流（按 opcode 对应布局编码）。
    std::vector<uint32_t> init_value_words;
    // 指令 word 总数。
    uint32_t inst_count = 0;
    // 指令 word 流。
    std::vector<uint32_t> inst_words;
    // 分支表条目数量。
    uint32_t branch_count = 0;
    // 分支 ID -> PC 映射表（VM 内部使用）。
    std::vector<uint32_t> branch_words;
    // 分支 ID -> 原生地址映射表（BL/外部跳转使用）。
    std::vector<uint64_t> branch_addrs;

    // 校验当前对象是否满足编码格式约束。
    bool validate(std::string* error = nullptr) const;
    // 将字段按 6-bit 扩展规则编码为字节流。
    bool serializeEncoded(std::vector<uint8_t>& out, std::string* error = nullptr) const;
    // 从编码字节流恢复字段并校验合法性。
    static bool deserializeEncoded(const uint8_t* data, size_t len, zFunctionData& out, std::string* error = nullptr);
    // 比较两份编码字段是否一致（用于 round-trip 校验）。
    bool encodedEquals(const zFunctionData& other, std::string* error = nullptr) const;
};

#endif
