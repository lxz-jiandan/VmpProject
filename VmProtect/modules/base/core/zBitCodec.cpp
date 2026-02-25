// 引入位流编解码接口声明。
#include "zBitCodec.h"

// 进入基础位编解码命名空间。
namespace vmp::base::bitcodec {

// 写入一个 6-bit 值。
void BitWriter6::write6(uint32_t value) {
    // 仅保留低 6 位，避免高位污染位流。
    value &= 0x3fu;
    // 把当前 6 位拼接到位缓冲区尾部。
    bitBuffer |= (value << bitCount);
    // 位缓冲区占用位数增加 6。
    bitCount += 6;
    // 每满 8 位就落盘 1 字节。
    while (bitCount >= 8) {
        // 导出低 8 位到输出字节数组。
        outputBytes.push_back(static_cast<uint8_t>(bitBuffer & 0xffu));
        // 右移丢弃已导出的 8 位。
        bitBuffer >>= 8;
        // 更新缓冲区位数。
        bitCount -= 8;
    }
}

// 写入扩展 u32：每组 5-bit 数据 + 1-bit 延续标记。
void BitWriter6::writeExtU32(uint32_t value) {
    // 小值直接写 1 组即可。
    if (value < 32u) {
        // 低 5 位直接作为 payload。
        write6(value);
        // 当前值编码完成。
        return;
    }
    // 大值按 5-bit 分组持续输出。
    while (value >= 32u) {
        // 设置 continuation bit(0x20) 表示后面还有分组。
        write6(0x20u | (value & 0x1fu));
        // 右移 5 位，处理下一组。
        value >>= 5;
    }
    // 输出最后一组（continuation bit = 0）。
    write6(value & 0x1fu);
}

// 完成写入并返回最终字节数组。
std::vector<uint8_t> BitWriter6::finish() {
    // 若仍有残余 bit，则补一个尾字节。
    if (bitCount > 0) {
        outputBytes.push_back(static_cast<uint8_t>(bitBuffer & 0xffu));
    }
    // 清空内部状态，避免后续复用时串数据。
    bitBuffer = 0;
    // 重置位计数器。
    bitCount = 0;
    // 移动返回输出，避免拷贝。
    return std::move(outputBytes);
}

// 构造读取器：保存输入基址与长度。
BitReader6::BitReader6(const uint8_t* data, const size_t len) : dataPtr(data), dataLen(len) {}

// 读取一个 6-bit 值。
bool BitReader6::read6(uint32_t* out) {
    // 输出指针不能为空。
    if (out == nullptr) {
        return false;
    }
    // 计算输入总 bit 数。
    const uint64_t totalBits = static_cast<uint64_t>(dataLen) * 8ull;
    // 越界保护：剩余 bit 不足 6 时失败。
    if (bitPos + 6ull > totalBits) {
        return false;
    }

    // 累计当前读取值。
    uint32_t value = 0;
    // 逐 bit 读取 6 次。
    for (uint32_t i = 0; i < 6u; ++i) {
        // 当前 bit 的绝对位置。
        const uint64_t pos = bitPos + i;
        // 定位到对应字节。
        const uint8_t byte = dataPtr[static_cast<size_t>(pos / 8ull)];
        // 取出该字节中的目标位。
        const uint32_t bit = (byte >> static_cast<uint32_t>(pos % 8ull)) & 0x1u;
        // 合并到输出值第 i 位。
        value |= (bit << i);
    }
    // 读取游标前进 6 位。
    bitPos += 6ull;
    // 写回输出。
    *out = value;
    // 读取成功。
    return true;
}

// 读取扩展 u32（与 writeExtU32 对偶）。
bool BitReader6::readExtU32(uint32_t* out) {
    // 输出指针不能为空。
    if (out == nullptr) {
        return false;
    }

    // 先读取第一组 6-bit。
    uint32_t chunk = 0;
    if (!read6(&chunk)) {
        return false;
    }

    // 取低 5 位作为初始值。
    uint32_t value = chunk & 0x1fu;
    // 下一组的合并位偏移从 5 开始。
    uint32_t shift = 5u;
    // 保护计数器，防止恶意流导致死循环。
    uint32_t guard = 0u;
    // continuation bit 为 1 时继续读取后续分组。
    while (chunk & 0x20u) {
        // 安全阈值：最多读取 8 组（覆盖 32-bit）。
        if (++guard > 7u) {
            return false;
        }
        // 读取下一组 6-bit。
        if (!read6(&chunk)) {
            return false;
        }
        // 把低 5 位合并到目标值。
        value |= ((chunk & 0x1fu) << shift);
        // 位偏移前进 5。
        shift += 5u;
    }
    // 返回解码值。
    *out = value;
    // 解码成功。
    return true;
}

// 把 u64 拆成低/高 32-bit 并按扩展格式写入。
void writeU64AsU32Pair(BitWriter6* writer, const uint64_t value) {
    // 写入器不能为空。
    if (writer == nullptr) {
        return;
    }
    // 取低 32 位。
    const uint32_t low = static_cast<uint32_t>(value & 0xffffffffull);
    // 取高 32 位。
    const uint32_t high = static_cast<uint32_t>((value >> 32u) & 0xffffffffull);
    // 先写低位部分。
    writer->writeExtU32(low);
    // 再写高位部分。
    writer->writeExtU32(high);
}

// 从位流读取两个扩展 u32 并组装为 u64。
bool readU64FromU32Pair(BitReader6* reader, uint64_t* out) {
    // 输入输出指针都不能为空。
    if (reader == nullptr || out == nullptr) {
        return false;
    }
    // 存放低 32 位。
    uint32_t low = 0;
    // 存放高 32 位。
    uint32_t high = 0;
    // 读取低位。
    if (!reader->readExtU32(&low)) {
        return false;
    }
    // 读取高位。
    if (!reader->readExtU32(&high)) {
        return false;
    }
    // 合并为 u64（高位左移 32）。
    *out = static_cast<uint64_t>(low) | (static_cast<uint64_t>(high) << 32u);
    // 读取成功。
    return true;
}

// 结束命名空间。
}  // namespace vmp::base::bitcodec
