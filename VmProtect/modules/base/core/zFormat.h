// 防止头文件重复包含。
#pragma once

// 引入 size_t。
#include <cstddef>
// 引入定宽整数类型。
#include <cstdint>
// 引入可变参数类型 va_list。
#include <cstdarg>
// 引入字符串类型。
#include <string>

// 基础层文本/字节格式化工具命名空间。
namespace vmp::base::format {

// 使用现成 va_list 格式化字符串。
// 语义：失败返回空串，不抛异常。
std::string vformat(const char* fmt, va_list args);

// printf 风格格式化入口。
// 语义：失败返回空串，不抛异常。
std::string format(const char* fmt, ...);

// 生成十六进制字节预览文本（例如 "01 02 ff ..."）。
// 语义：当 data==nullptr 或 size==0 时返回 "empty"。
std::string hexBytesPreview(const uint8_t* data, size_t size, size_t maxBytes = 24);

// 把 64 位无符号整数格式化为十六进制文本。
// 语义：withPrefix=true 时返回 "0x..."，否则返回纯十六进制数字。
std::string hexU64(uint64_t value, bool withPrefix = true, bool upper = false);

// 结束命名空间。
}  // namespace vmp::base::format
