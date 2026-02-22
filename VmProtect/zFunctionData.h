/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - 函数数据容器接口定义。
 * - 加固链路位置：翻译数据接口层。
 * - 输入：函数基础元信息。
 * - 输出：统一的数据访问抽象。
 */
#ifndef VMPROTECT_ZFUNCTION_DATA_H
#define VMPROTECT_ZFUNCTION_DATA_H

#include <cstddef>  // size_t。
#include <cstdint>  // 固定宽度整数类型。
#include <string>   // std::string。
#include <vector>   // std::vector。

class zFunctionData {
public:
    // 函数元信息（来自 ELF 扫描或文本/二进制导入阶段）。
    // 函数名（主要用于日志与调试定位）。
    std::string function_name;
    // 函数地址（在 Engine 侧可能是 so 内偏移，也可能是运行时地址）。
    uint64_t function_offset = 0;
    // 可选：函数原始机器码（当前主流程并不强依赖，但用于分析/回退）。
    std::vector<uint8_t> function_bytes;

    // 编码字节码载荷字段（供序列化/反序列化使用）。
    // 协议 marker（固定 6bit，标识该编码流版本/类型）。
    uint32_t marker = 0;
    // VM 寄存器槽数量。
    uint32_t register_count = 0;
    // “首段初始化指令”数量（通常对应函数前置初始化片段）。
    uint32_t first_inst_count = 0;
    // 首段初始化 opcode 列表，长度必须等于 `first_inst_count`。
    std::vector<uint32_t> first_inst_opcodes;
    // 外部初始化映射表：按 `[targetReg, externalIndex]` 成对编码。
    // 长度应为 `2 * first_inst_count`（若该模式启用）。
    std::vector<uint32_t> external_init_words;
    // 类型表数量。
    uint32_t type_count = 0;
    // 类型标签数组（由 `zTypeManager::createFromCode` 解释）。
    std::vector<uint32_t> type_tags;
    // 内部初始化值条目数量。
    uint32_t init_value_count = 0;
    // 初始化值流（按 opcode 指定布局编码，存在可变宽度条目）。
    std::vector<uint32_t> init_value_words;
    // 指令 word 总数。
    uint32_t inst_count = 0;
    // 指令 word 流（扁平化后线性存储）。
    std::vector<uint32_t> inst_words;
    // 本地分支表条目数量。
    uint32_t branch_count = 0;
    // 分支 ID -> PC 映射表（VM 内部跳转使用）。
    std::vector<uint32_t> branch_words;
    // 分支 ID -> 原生地址映射表（BL/外部调用跳转使用）。
    std::vector<uint64_t> branch_addrs;

    // 校验当前对象是否满足编码协议约束。
    // 失败时可选写入 error 文本，便于上层定位。
    bool validate(std::string* error = nullptr) const;
    // 将字段按 6-bit 扩展规则编码为字节流。
    // 输出覆盖到 out（旧内容会被替换）。
    bool serializeEncoded(std::vector<uint8_t>& out, std::string* error = nullptr) const;
    // 从编码字节流恢复字段并校验合法性。
    // 成功时写入 out，失败时 out 可能为部分数据但会返回 false。
    static bool deserializeEncoded(const uint8_t* data, size_t len, zFunctionData& out, std::string* error = nullptr);
    // 比较两份“编码相关字段”是否一致（用于 round-trip 校验）。
    bool encodedEquals(const zFunctionData& other, std::string* error = nullptr) const;
};

#endif
