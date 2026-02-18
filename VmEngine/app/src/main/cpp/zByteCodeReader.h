#ifndef Z_BYTE_CODE_READER_H
#define Z_BYTE_CODE_READER_H

#include <cstdint>

struct ByteCodeReader {
    const uint8_t* buffer;
    uint64_t size;
    uint64_t pos;
    uint64_t bits;
    uint32_t bit_count;
};


class zByteCodeReader {
public:
    // 构造字节码读取器并将内部状态初始化为空。
    zByteCodeReader();

    // 析构读取器（当前不持有外部资源，主要用于保持接口完整）。
    ~zByteCodeReader();

    // 初始化读取器
    void init(const uint8_t* buffer, uint64_t size);

    // 读取 6 位
    uint32_t read6bits();

    // 读取 6-bit 扩展整数
    uint32_t read6bitExt();

    // 检查是否还有数据
    bool hasMore() const;

    // 获取内部状态快照（只读引用），便于调试和外部观察解码进度。
    const ByteCodeReader& getState() const { return state_; }
    
    // 获取当前已消费到的字节位置。
    uint64_t getPos() const { return state_.pos; }
    
    // 获取当前缓存中尚未消费的有效位数量。
    uint32_t getBitCount() const { return state_.bit_count; }

private:
    ByteCodeReader state_;

    // 当缓存位不足时，从底层缓冲区继续补充位流。
    void refill(uint32_t needBits);
};


#endif // Z_BYTE_CODE_READER_H



