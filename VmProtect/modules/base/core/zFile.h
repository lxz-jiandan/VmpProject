// 防止头文件重复包含。
#pragma once

// 引入固定宽度整数定义。
#include <cstdint>
// 引入字符串类型。
#include <string>
// 引入字节数组容器。
#include <vector>

// 基础层文件 IO 工具命名空间。
namespace vmp::base::file {

// 判断路径是否存在且为普通文件。
bool fileExists(const std::string& path);
// 确保目录存在（不存在则递归创建）。
bool ensureDirectory(const std::string& path);
// 读取文件为字节数组。
bool readFileBytes(const char* path, std::vector<uint8_t>* out);
// 把字节数组写入文件（覆盖写）。
bool writeFileBytes(const std::string& path, const std::vector<uint8_t>& data);

// 结束命名空间。
}  // namespace vmp::base::file

