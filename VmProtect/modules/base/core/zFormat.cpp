// 引入声明。
#include "zFormat.h"

// 引入 std::min。
#include <algorithm>
// 引入 snprintf。
#include <cstdio>
// 引入 std::ostringstream。
#include <sstream>
// 引入 std::hex/std::setw/std::setfill。
#include <iomanip>
// 引入临时字符缓冲。
#include <vector>

namespace vmp::base::format {  // 流程注记：该语句参与当前阶段的语义实现。

std::string vformat(const char* fmt, va_list args) {  // 处理阶段入口：进入该函数或代码块的主流程。
    // 格式串为空时直接返回空串。
    if (fmt == nullptr) {  // 分支守卫：满足前置条件后再进入后续处理路径。
        return std::string();
    }

    // 拷贝参数列表用于“先测长、再输出”的两阶段流程。
    va_list args_for_size;
    va_copy(args_for_size, args);
    const int required = std::vsnprintf(nullptr, 0, fmt, args_for_size);
    va_end(args_for_size);
    // 负值表示格式化失败。
    if (required < 0) {
        return std::string();
    }

    // +1 给末尾 '\0' 预留空间。
    std::vector<char> buffer(static_cast<size_t>(required) + 1u, '\0');
    // 再拷贝一份参数列表做实际输出。
    va_list args_for_write;
    va_copy(args_for_write, args);
    const int written = std::vsnprintf(buffer.data(), buffer.size(), fmt, args_for_write);
    va_end(args_for_write);
    // 写入失败时返回空串。
    if (written < 0) {
        return std::string();
    }
    return std::string(buffer.data(), static_cast<size_t>(written));
}

std::string format(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    const std::string text = vformat(fmt, args);
    va_end(args);
    return text;
}

std::string hexBytesPreview(const uint8_t* data, size_t size, size_t maxBytes) {
    // 空输入统一返回 empty，避免调用方再判空。
    if (data == nullptr || size == 0) {
        return "empty";
    }
    const size_t count = std::min(size, maxBytes);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < count; ++i) {
        if (i != 0) {
            oss << ' ';
        }
        oss << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    if (size > count) {
        oss << " ...";
    }
    return oss.str();
}

std::string hexU64(uint64_t value, bool withPrefix, bool upper) {
    char buffer[32] = {0};
    const char* fmt = nullptr;
    if (withPrefix) {
        fmt = upper ? "0x%llX" : "0x%llx";
    } else {
        fmt = upper ? "%llX" : "%llx";
    }
    const int written = std::snprintf(buffer, sizeof(buffer), fmt, static_cast<unsigned long long>(value));
    if (written < 0) {
        return std::string();
    }
    return std::string(buffer, static_cast<size_t>(written));
}

}  // namespace vmp::base::format
