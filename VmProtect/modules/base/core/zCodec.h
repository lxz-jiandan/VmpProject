// 防止头文件重复包含。
#pragma once

// 引入 size_t 定义。
#include <cstddef>
// 引入固定宽度整数类型。
#include <cstdint>
// 引入字符串类型。
#include <string>
// 引入字节数组容器。
#include <vector>

// 基础层 little-endian 编解码工具命名空间。
namespace vmp::base::codec {

// 从字节数组按小端读取 u32。
bool readU32Le(const std::vector<uint8_t>& bytes, size_t offset, uint32_t* out);
// 向字节数组按小端写入 u32。
bool writeU32Le(std::vector<uint8_t>* bytes, size_t offset, uint32_t value);
// 末尾追加一个小端 u32。
void appendU32Le(std::vector<uint8_t>* out, uint32_t value);
// 从字节数组按小端读取 u64。
bool readU64Le(const std::vector<uint8_t>& bytes, size_t offset, uint64_t* out);
// 向字节数组按小端写入 u64。
bool writeU64Le(std::vector<uint8_t>* bytes, size_t offset, uint64_t value);
// 末尾追加一个小端 u64。
void appendU64Le(std::vector<uint8_t>* out, uint64_t value);
// 末尾追加一组小端 u32。
void appendU32LeArray(std::vector<uint8_t>* out, const uint32_t* values, size_t count);
// 末尾追加一组小端 u64。
void appendU64LeArray(std::vector<uint8_t>* out, const uint64_t* values, size_t count);
// 从 cursor 位置读取 u32 并自动前移 cursor。
bool readU32LeAdvance(const std::vector<uint8_t>& bytes, size_t* cursor, uint32_t* out);
// 从 cursor 位置读取 u64 并自动前移 cursor。
bool readU64LeAdvance(const std::vector<uint8_t>& bytes, size_t* cursor, uint64_t* out);
// 写入“长度(u32)+原始字符串字节”。
void appendStringU32Le(std::vector<uint8_t>* out, const std::string& value);
// 读取“长度(u32)+原始字符串字节”，并前移 cursor。
bool readStringU32LeAdvance(const std::vector<uint8_t>& bytes, size_t* cursor, std::string* out);

// 结束命名空间。
}  // namespace vmp::base::codec
