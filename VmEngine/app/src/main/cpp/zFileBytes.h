#pragma once

// size_t。
#include <cstddef>
// uint8_t。
#include <cstdint>
// memcpy。
#include <cstring>
// std::string。
#include <string>
// is_trivially_copyable。
#include <type_traits>
// std::vector。
#include <vector>

namespace zFileBytes {

// 读取整个文件到字节数组。
bool readFileBytes(const std::string& path, std::vector<uint8_t>& out);
// 把字节数组完整写入文件（覆盖写）。
bool writeFileBytes(const std::string& path, const std::vector<uint8_t>& data);

// 从 bytes[offset] 读取一个 POD 结构体副本。
template <typename T>
bool readPodAt(const std::vector<uint8_t>& bytes, size_t offset, T& out) {
    // 只允许平凡可拷贝类型，避免对象语义破坏。
    static_assert(std::is_trivially_copyable<T>::value, "readPodAt requires trivially copyable T");
    // 偏移越界或剩余长度不足都直接失败。
    if (offset > bytes.size() || bytes.size() - offset < sizeof(T)) {
        return false;
    }
    // 按字节复制到输出对象。
    std::memcpy(&out, bytes.data() + offset, sizeof(T));
    return true;
}

} // namespace zFileBytes
