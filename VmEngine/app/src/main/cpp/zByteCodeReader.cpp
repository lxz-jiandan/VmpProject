#include "zByteCodeReader.h"
#include <cstdlib>
#include <iostream>


// 解码失败处理：输出错误信息并直接终止进程，避免继续在非法状态下运行。
static void decodeFail(const char* msg) {
    std::cerr << "[DECODE FAIL] " << msg << std::endl;
    abort();
}

// 构造读取器并将内部状态归零。
zByteCodeReader::zByteCodeReader() {
    state_.buffer = nullptr;
    state_.size = 0;
    state_.pos = 0;
    state_.bits = 0;
    state_.bit_count = 0;
}

// 析构读取器（无额外资源需要手动释放）。
zByteCodeReader::~zByteCodeReader() {
}

// 初始化位流读取状态，并预加载首块数据到 bits 缓冲。
void zByteCodeReader::init(const uint8_t* buffer, uint64_t size) {
    state_.buffer = buffer;
    state_.size = size;
    state_.pos = 0;
    state_.bits = 0;
    state_.bit_count = 0;

    if (size == 0) {
        decodeFail("bytecode_size == 0");
    }

    if (size >= 8) {
        // 预读 8 字节
        state_.bits = *reinterpret_cast<const uint64_t*>(buffer);
        state_.bit_count = 64;
        state_.pos = 8;
    } else {
        // 按字节读入
        uint64_t chunk = 0;
        for (uint64_t i = 0; i < size; i++) {
            chunk |= static_cast<uint64_t>(buffer[i]) << (8 * i);
        }
        state_.bits = chunk;
        state_.bit_count = static_cast<uint32_t>(8 * size);
        state_.pos = size;
    }

    if (state_.bit_count == 0) {
        decodeFail("bit_count == 0 after init");
    }
}

// 当缓存位不足时从输入缓冲补读，保证后续可安全读取 6 位块。
void zByteCodeReader::refill(uint32_t needBits) {
    if (state_.pos >= state_.size) {
        decodeFail("read_pos >= buffer_size during refill");
    }

    uint64_t remaining = state_.size - state_.pos;
    uint64_t readLen = (remaining >= 8) ? 8 : remaining;

    uint64_t newChunk = 0;
    if (readLen == 8) {
        newChunk = *reinterpret_cast<const uint64_t*>(state_.buffer + state_.pos);
    } else {
        // 按字节拼接
        for (uint64_t i = 0; i < readLen; i++) {
            newChunk |= static_cast<uint64_t>(state_.buffer[state_.pos + i]) << (8 * i);
        }
    }

    // 拼接
    state_.bits = (newChunk << state_.bit_count) | state_.bits;
    state_.bit_count += static_cast<uint32_t>(8 * readLen);
    state_.pos += readLen;

    if (state_.bit_count < 6) {
        decodeFail("not enough bits after refill");
    }
}

// 读取一个 6 位无符号值。
uint32_t zByteCodeReader::read6bits() {
    if (state_.bit_count < 6) {
        refill(6 - state_.bit_count);
    }

    uint32_t value = state_.bits & 0x3F;
    state_.bits >>= 6;
    state_.bit_count -= 6;
    return value;
}

// 读取变长 6-bit 扩展整数（每组 5 位数据 + 1 位续位标志）。
uint32_t zByteCodeReader::read6bitExt() {
    uint32_t first = read6bits();
    uint32_t value = first & 0x1F;  // 低 5 位
    int shift = 5;

    while (first & 0x20) {  // 扩展位
        first = read6bits();
        value |= (first & 0x1F) << shift;
        shift += 5;
    }

    return value;
}

// 判断底层缓冲或位缓存中是否仍有可读取数据。
bool zByteCodeReader::hasMore() const {
    return state_.bit_count > 0 || state_.pos < state_.size;
}




