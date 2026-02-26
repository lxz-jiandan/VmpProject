// 防止头文件重复包含。
#pragma once

// 引入 size_t 定义。
#include <cstddef>
// 引入固定宽度整数定义。
#include <cstdint>
// 引入字符串类型。
#include <string>
// 引入字节数组容器。
#include <vector>

// 基础层 embedded payload 尾部协议工具命名空间。
namespace vmp::base::embedded {

// 文件尾 embedded payload 解析结果。
struct EmbeddedPayloadTailInfo {
    // 是否命中合法 embedded payload 尾部协议。
    bool hasTail = false;
    // 不含 payload/footer 的基础 ELF 主体大小。
    size_t baseSize = 0;
    // 解析出的 payload 原始字节（仅在 hasTail=true 时非空）。
    std::vector<uint8_t> payloadBytes;
};

// 返回 embedded payload footer 结构体字节大小。
size_t getEmbeddedPayloadFooterSize();

// 解析文件末尾 embedded payload：
// - 未命中协议时返回 true 且 hasTail=false；
// - 命中协议但字段/CRC 非法时返回 false。
bool parseEmbeddedPayloadTail(const std::vector<uint8_t>& fileBytes,
                              EmbeddedPayloadTailInfo* outInfo,
                              std::string* error);

// 在文件末尾追加 payload 与 footer。
// 注意：空 payload 不追加任何内容。
void appendEmbeddedPayloadTail(std::vector<uint8_t>* fileBytes,
                               const std::vector<uint8_t>& payloadBytes);

// 结束命名空间。
}  // namespace vmp::base::embedded

