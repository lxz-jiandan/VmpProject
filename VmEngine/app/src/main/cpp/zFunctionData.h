#ifndef Z_FUNCTION_DATA_H
#define Z_FUNCTION_DATA_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

class zFunctionData {
public:
    // 函数元信息（来自 ELF 或文本导出阶段）。
    std::string function_name;
    uint64_t function_offset = 0;
    std::vector<uint8_t> function_bytes;

    // 编码字节码载荷字段（供序列化/反序列化使用）。
    uint32_t marker = 0;
    uint32_t register_count = 0;
    uint32_t first_inst_count = 0;
    std::vector<uint32_t> first_inst_opcodes;
    std::vector<uint32_t> external_init_words;
    uint32_t type_count = 0;
    std::vector<uint32_t> type_tags;
    uint32_t init_value_count = 0;
    std::vector<uint32_t> init_value_words;
    uint32_t inst_count = 0;
    std::vector<uint32_t> inst_words;
    uint32_t branch_count = 0;
    std::vector<uint32_t> branch_words;
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
