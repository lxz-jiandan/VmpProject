// 防止头文件重复包含。
#pragma once

// 引入固定宽度整数。
#include <cstdint>
// 引入字符串类型。
#include <string>
// 引入字节数组容器。
#include <vector>

// 顶层 vmp 命名空间（提供对 base::io 的薄封装）。
namespace vmp {

// 判断路径是否存在且为普通文件。
bool fileExists(const std::string& path);
// 确保目录存在（不存在则创建）。
bool ensureDirectory(const std::string& path);
// 读取文件为字节数组。
bool readFileBytes(const char* path, std::vector<uint8_t>& out);
// 将字节数组写入文件（覆盖模式）。
bool writeFileBytes(const std::string& path, const std::vector<uint8_t>& data);

// 结束命名空间。
}  // namespace vmp
