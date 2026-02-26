// 引入基础文件 IO 接口声明。
#include "zFile.h"

// 引入文件系统 API。
#include <filesystem>
// 引入输入文件流。
#include <fstream>

// 文件系统命名空间别名，缩短代码书写。
namespace fs = std::filesystem;

// 进入基础 IO 命名空间。
namespace vmp::base::file {

// 判断 path 是否存在且是普通文件。
bool fileExists(const std::string& path) {
    // 使用 error_code 避免抛异常。
    std::error_code ec;
    // 路径非空 + 存在 + 类型为 regular file。
    return !path.empty() && fs::exists(path, ec) && fs::is_regular_file(path, ec);
}

// 确保目录存在；若不存在则递归创建。
bool ensureDirectory(const std::string& path) {
    // 使用 error_code 避免抛异常。
    std::error_code ec;
    // 空路径直接失败。
    if (path.empty()) {
        return false;
    }
    // 目录已存在时仅校验它确实是目录。
    if (fs::exists(path, ec)) {
        return fs::is_directory(path, ec);
    }
    // 不存在则递归创建。
    return fs::create_directories(path, ec);
}

// 读取文件到字节数组。
bool readFileBytes(const char* path, std::vector<uint8_t>* out) {
    // 输出容器不能为空。
    if (out == nullptr) {
        return false;
    }
    // 每次读取前先清空旧数据。
    out->clear();
    // 路径为空时失败。
    if (path == nullptr || path[0] == '\0') {
        return false;
    }

    // 以二进制模式打开输入流。
    std::ifstream in(path, std::ios::binary);
    // 打开失败直接返回。
    if (!in) {
        return false;
    }
    // 光标移到文件末尾，准备计算总长度。
    in.seekg(0, std::ios::end);
    // 获取文件总长度。
    const std::streamoff size = in.tellg();
    // 若长度异常则失败。
    if (size < 0) {
        return false;
    }
    // 光标回到文件开头。
    in.seekg(0, std::ios::beg);

    // 预分配输出数组大小。
    out->resize(static_cast<size_t>(size));
    // 非空文件才执行读取。
    if (!out->empty()) {
        in.read(reinterpret_cast<char*>(out->data()),
                static_cast<std::streamsize>(out->size()));
    }
    // 读取状态必须为真。
    return static_cast<bool>(in);
}

// 把字节数组写入目标文件（覆盖模式）。
bool writeFileBytes(const std::string& path, const std::vector<uint8_t>& data) {
    // 空路径直接失败。
    if (path.empty()) {
        return false;
    }

    // 使用 error_code 避免目录创建抛异常。
    std::error_code ec;
    // 构造输出路径对象。
    const fs::path outPath(path);
    // 若存在父目录则确保它存在。
    if (outPath.has_parent_path()) {
        fs::create_directories(outPath.parent_path(), ec);
        // 创建目录失败则返回。
        if (ec) {
            return false;
        }
    }

    // 以二进制 + 截断模式打开输出流。
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    // 打开失败直接返回。
    if (!out) {
        return false;
    }
    // 仅在数据非空时执行写入。
    if (!data.empty()) {
        out.write(reinterpret_cast<const char*>(data.data()),
                  static_cast<std::streamsize>(data.size()));
    }
    // 写入状态必须为真。
    return static_cast<bool>(out);
}

// 结束命名空间。
}  // namespace vmp::base::file

