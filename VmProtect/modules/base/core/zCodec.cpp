// 引入小端编解码接口声明。
#include "zCodec.h"

// 进入基础编解码命名空间。
namespace vmp::base::codec {

// 从 bytes[offset, offset+4) 读取小端 u32。
bool readU32Le(const std::vector<uint8_t>& bytes, const size_t offset, uint32_t* out) {
    // 输出指针不能为空，且读取区间不能越界。
    if (out == nullptr || offset + 4 > bytes.size()) {
        return false;
    }
    // 按 little-endian 组合 4 个字节。
    *out = static_cast<uint32_t>(bytes[offset]) |
           (static_cast<uint32_t>(bytes[offset + 1]) << 8) |
           (static_cast<uint32_t>(bytes[offset + 2]) << 16) |
           (static_cast<uint32_t>(bytes[offset + 3]) << 24);
    // 读取成功。
    return true;
}

// 向 bytes[offset, offset+4) 写入小端 u32。
bool writeU32Le(std::vector<uint8_t>* bytes, const size_t offset, const uint32_t value) {
    // 目标指针不能为空，且写入区间不能越界。
    if (bytes == nullptr || offset + 4 > bytes->size()) {
        return false;
    }
    // 写入最低字节。
    (*bytes)[offset] = static_cast<uint8_t>(value & 0xff);
    // 写入次低字节。
    (*bytes)[offset + 1] = static_cast<uint8_t>((value >> 8) & 0xff);
    // 写入次高字节。
    (*bytes)[offset + 2] = static_cast<uint8_t>((value >> 16) & 0xff);
    // 写入最高字节。
    (*bytes)[offset + 3] = static_cast<uint8_t>((value >> 24) & 0xff);
    // 写入成功。
    return true;
}

// 在数组末尾追加一个小端 u32。
void appendU32Le(std::vector<uint8_t>* out, const uint32_t value) {
    // 输出数组不能为空。
    if (out == nullptr) {
        return;
    }
    // 依次追加 4 个字节（低位在前）。
    out->push_back(static_cast<uint8_t>(value & 0xff));
    out->push_back(static_cast<uint8_t>((value >> 8) & 0xff));
    out->push_back(static_cast<uint8_t>((value >> 16) & 0xff));
    out->push_back(static_cast<uint8_t>((value >> 24) & 0xff));
}

// 从 bytes[offset, offset+8) 读取小端 u64。
bool readU64Le(const std::vector<uint8_t>& bytes, const size_t offset, uint64_t* out) {
    // 输出指针不能为空，且读取区间不能越界。
    if (out == nullptr || offset + 8 > bytes.size()) {
        return false;
    }
    // 按 little-endian 组合 8 个字节。
    *out = static_cast<uint64_t>(bytes[offset]) |
           (static_cast<uint64_t>(bytes[offset + 1]) << 8) |
           (static_cast<uint64_t>(bytes[offset + 2]) << 16) |
           (static_cast<uint64_t>(bytes[offset + 3]) << 24) |
           (static_cast<uint64_t>(bytes[offset + 4]) << 32) |
           (static_cast<uint64_t>(bytes[offset + 5]) << 40) |
           (static_cast<uint64_t>(bytes[offset + 6]) << 48) |
           (static_cast<uint64_t>(bytes[offset + 7]) << 56);
    // 读取成功。
    return true;
}

// 向 bytes[offset, offset+8) 写入小端 u64。
bool writeU64Le(std::vector<uint8_t>* bytes, const size_t offset, const uint64_t value) {
    // 目标数组不能为空，且写入区间不能越界。
    if (bytes == nullptr || offset + 8 > bytes->size()) {
        return false;
    }
    // 写入第 0 字节（最低位）。
    (*bytes)[offset] = static_cast<uint8_t>(value & 0xff);
    // 写入第 1 字节。
    (*bytes)[offset + 1] = static_cast<uint8_t>((value >> 8) & 0xff);
    // 写入第 2 字节。
    (*bytes)[offset + 2] = static_cast<uint8_t>((value >> 16) & 0xff);
    // 写入第 3 字节。
    (*bytes)[offset + 3] = static_cast<uint8_t>((value >> 24) & 0xff);
    // 写入第 4 字节。
    (*bytes)[offset + 4] = static_cast<uint8_t>((value >> 32) & 0xff);
    // 写入第 5 字节。
    (*bytes)[offset + 5] = static_cast<uint8_t>((value >> 40) & 0xff);
    // 写入第 6 字节。
    (*bytes)[offset + 6] = static_cast<uint8_t>((value >> 48) & 0xff);
    // 写入第 7 字节（最高位）。
    (*bytes)[offset + 7] = static_cast<uint8_t>((value >> 56) & 0xff);
    // 写入成功。
    return true;
}

// 在数组末尾追加一个小端 u64。
void appendU64Le(std::vector<uint8_t>* out, const uint64_t value) {
    // 输出数组不能为空。
    if (out == nullptr) {
        return;
    }
    // 依次写入 8 个字节（低位在前）。
    out->push_back(static_cast<uint8_t>(value & 0xff));
    out->push_back(static_cast<uint8_t>((value >> 8) & 0xff));
    out->push_back(static_cast<uint8_t>((value >> 16) & 0xff));
    out->push_back(static_cast<uint8_t>((value >> 24) & 0xff));
    out->push_back(static_cast<uint8_t>((value >> 32) & 0xff));
    out->push_back(static_cast<uint8_t>((value >> 40) & 0xff));
    out->push_back(static_cast<uint8_t>((value >> 48) & 0xff));
    out->push_back(static_cast<uint8_t>((value >> 56) & 0xff));
}

// 末尾追加 count 个 u32（小端）。
void appendU32LeArray(std::vector<uint8_t>* out, const uint32_t* values, const size_t count) {
    // 基础参数合法性检查。
    if (out == nullptr || values == nullptr || count == 0) {
        return;
    }
    // 预留容量，减少扩容次数。
    out->reserve(out->size() + count * sizeof(uint32_t));
    // 逐个追加。
    for (size_t i = 0; i < count; ++i) {
        appendU32Le(out, values[i]);
    }
}

// 末尾追加 count 个 u64（小端）。
void appendU64LeArray(std::vector<uint8_t>* out, const uint64_t* values, const size_t count) {
    // 基础参数合法性检查。
    if (out == nullptr || values == nullptr || count == 0) {
        return;
    }
    // 预留容量，减少扩容次数。
    out->reserve(out->size() + count * sizeof(uint64_t));
    // 逐个追加。
    for (size_t i = 0; i < count; ++i) {
        appendU64Le(out, values[i]);
    }
}

// 读取 u32 并前移 cursor。
bool readU32LeAdvance(const std::vector<uint8_t>& bytes, size_t* cursor, uint32_t* out) {
    // cursor 与 out 都不能为空。
    if (cursor == nullptr || out == nullptr) {
        return false;
    }
    // 先按当前 cursor 读取。
    if (!readU32Le(bytes, *cursor, out)) {
        return false;
    }
    // 游标前移 4 字节。
    *cursor += sizeof(uint32_t);
    // 读取成功。
    return true;
}

// 读取 u64 并前移 cursor。
bool readU64LeAdvance(const std::vector<uint8_t>& bytes, size_t* cursor, uint64_t* out) {
    // cursor 与 out 都不能为空。
    if (cursor == nullptr || out == nullptr) {
        return false;
    }
    // 先按当前 cursor 读取。
    if (!readU64Le(bytes, *cursor, out)) {
        return false;
    }
    // 游标前移 8 字节。
    *cursor += sizeof(uint64_t);
    // 读取成功。
    return true;
}

// 写入“长度(u32) + 原始字符串字节”。
void appendStringU32Le(std::vector<uint8_t>* out, const std::string& value) {
    // 输出数组不能为空。
    if (out == nullptr) {
        return;
    }
    // 先写入字符串长度（u32，小端）。
    appendU32Le(out, static_cast<uint32_t>(value.size()));
    // 再写入字符串本体字节（不含终止符）。
    out->insert(out->end(), value.begin(), value.end());
}

// 读取“长度(u32) + 字符串字节”，并前移 cursor。
bool readStringU32LeAdvance(const std::vector<uint8_t>& bytes, size_t* cursor, std::string* out) {
    // 基础参数校验。
    if (cursor == nullptr || out == nullptr) {
        return false;
    }
    // 承接字符串长度。
    uint32_t size = 0;
    // 先读取长度字段。
    if (!readU32LeAdvance(bytes, cursor, &size)) {
        return false;
    }
    // 检查字符串数据区是否越界。
    if (*cursor + size > bytes.size()) {
        return false;
    }
    // 按长度读取字符串（允许包含 '\0'）。
    out->assign(reinterpret_cast<const char*>(bytes.data() + *cursor), size);
    // 游标前移字符串长度。
    *cursor += size;
    // 读取成功。
    return true;
}

// 结束命名空间。
}  // namespace vmp::base::codec
