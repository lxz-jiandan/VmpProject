// 防止头文件被重复包含。
#pragma once

// 引入 size_t 定义。
#include <cstddef>
// 引入固定宽度整型定义。
#include <cstdint>
// 引入字节数组容器。
#include <vector>

// 基础层 bit 编解码命名空间。
namespace vmp::base::bitcodec {

// 6-bit 小端位流写入器。
// 用于把较小整数以紧凑位流形式写入字节数组。
class BitWriter6 {
public:
    // 写入一个 6-bit 片段（仅使用低 6 位）。
    void write6(uint32_t value);
    // 写入扩展无符号整数（按 5-bit 分组 + continuation bit）。
    void writeExtU32(uint32_t value);
    // 结束写入并返回最终字节数组。
    std::vector<uint8_t> finish();

private:
    // 存放最终输出字节。
    std::vector<uint8_t> outputBytes;
    // 位缓冲区，临时累计尚未凑满 1 字节的数据。
    uint32_t bitBuffer = 0;
    // 当前位缓冲区里已占用的 bit 数。
    int bitCount = 0;
};

// 6-bit 小端位流读取器。
// 与 BitWriter6 对偶，用于从压缩位流恢复整数。
class BitReader6 {
public:
    // 构造读取器：传入数据指针与总长度（字节）。
    BitReader6(const uint8_t* data, size_t len);

    // 读取一个 6-bit 片段。
    bool read6(uint32_t* out);
    // 读取扩展无符号整数（与 writeExtU32 对偶）。
    bool readExtU32(uint32_t* out);

private:
    // 输入数据首地址。
    const uint8_t* dataPtr = nullptr;
    // 输入数据总字节数。
    size_t dataLen = 0;
    // 当前读取到的 bit 偏移。
    uint64_t bitPos = 0;
};

// 把 64-bit 数拆成两个 32-bit，再用扩展编码写入位流。
void writeU64AsU32Pair(BitWriter6* writer, uint64_t value);
// 从位流读取两个 32-bit 并合并为 64-bit。
bool readU64FromU32Pair(BitReader6* reader, uint64_t* out);

// 结束命名空间。
}  // namespace vmp::base::bitcodec
