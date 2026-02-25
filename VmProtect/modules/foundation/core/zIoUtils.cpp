// 引入本文件接口声明。
#include "zIoUtils.h"

// 引入基础 IO 实现。
#include "zIo.h"

// 进入顶层命名空间。
namespace vmp {

// 转发到 base::io::fileExists。
bool fileExists(const std::string& path) {
    return base::io::fileExists(path);
}

// 转发到 base::io::ensureDirectory。
bool ensureDirectory(const std::string& path) {
    return base::io::ensureDirectory(path);
}

// 转发到 base::io::readFileBytes（适配引用参数）。
bool readFileBytes(const char* path, std::vector<uint8_t>& out) {
    return base::io::readFileBytes(path, &out);
}

// 转发到 base::io::writeFileBytes。
bool writeFileBytes(const std::string& path, const std::vector<uint8_t>& data) {
    return base::io::writeFileBytes(path, data);
}

// 结束命名空间。
}  // namespace vmp
