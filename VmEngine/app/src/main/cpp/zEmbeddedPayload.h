/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - 内嵌 payload 读取协议接口声明。
 * - 加固链路位置：route4 数据入口。
 * - 输入：宿主 so 与状态输出指针。
 * - 输出：payload 与读取状态。
 */
#ifndef Z_EMBEDDED_PAYLOAD_H
#define Z_EMBEDDED_PAYLOAD_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

enum class zEmbeddedPayloadReadStatus {
    // 成功读取并校验通过。
    kOk = 0,
    // 目标文件末尾未发现嵌入 footer（可按“未接入”处理）。
    kNotFound = 1,
    // 发现 footer 但格式/校验失败。
    kInvalid = 2,
};

class zEmbeddedPayload {
public:
    // route4 嵌入 footer：'VME4'
    static constexpr uint32_t kFooterMagic = 0x34454D56;
    static constexpr uint32_t kFooterVersion = 1;

    // 从 host so 末尾读取嵌入 payload（当前约定为 libdemo_expand.so 原始字节）。
    // 返回值语义：
    // - true: 读取流程执行成功（包含 kNotFound）；
    // - false: 文件读取失败或 footer/校验非法。
    static bool readEmbeddedPayloadFromHostSo(
        const std::string& host_so_path,
        std::vector<uint8_t>& out_payload,
        zEmbeddedPayloadReadStatus* out_status
    );

    // 对外暴露 CRC32，便于脚本/工具与运行时统一校验逻辑。
    static uint32_t crc32(const uint8_t* data, size_t size);
};

#endif // Z_EMBEDDED_PAYLOAD_H

