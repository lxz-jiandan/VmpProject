// 引入字节区间工具接口声明。
#include "zBytes.h"

// 引入 memcpy/memset。
#include <cstring>

// 进入基础字节工具命名空间。
namespace vmp::base::bytes {

// 内部辅助命名空间，仅当前编译单元可见。
namespace {

// 统一构造区域错误消息。
bool setRegionError(const char* name, const char* message, std::string* error) {
    // 调用方提供 error 输出时回填具体内容。
    if (error) {
        // 错误格式统一为 "<region> <message>"。
        *error = std::string(name ? name : "region") + " " + message;
    }
    // 便于直接 return 的失败返回值。
    return false;
}

// 结束匿名命名空间。
}  // namespace

// 校验区域：允许 cap==0 的“空区域”通过。
bool validateRegionAllowEmpty(const uint32_t header_size,
                              const uint32_t total_size,
                              const uint32_t off,
                              const uint32_t cap,
                              const char* name,
                              std::string* error) {
    // 空容量视为“未启用此区域”，直接合法。
    if (cap == 0) {
        return true;
    }
    // 起始偏移不能落在 header 之前。
    if (off < header_size) {
        return setRegionError(name, "off before header", error);
    }
    // 计算区域结束位置（使用 u64 防溢出）。
    const uint64_t end = static_cast<uint64_t>(off) + static_cast<uint64_t>(cap);
    // 结束位置不能越过总大小。
    if (end > total_size) {
        return setRegionError(name, "range out of total", error);
    }
    // 校验通过。
    return true;
}

// 校验区域：要求 used <= cap。
bool validateUsedRegion(const uint32_t header_size,
                        const uint32_t total_size,
                        const uint32_t off,
                        const uint32_t cap,
                        const uint32_t used,
                        const char* name,
                        std::string* error) {
    // 起始偏移不能落在 header 之前。
    if (off < header_size) {
        return setRegionError(name, "off before header", error);
    }
    // 计算容量区域结束位置。
    const uint64_t end = static_cast<uint64_t>(off) + static_cast<uint64_t>(cap);
    // 容量区域不能越界。
    if (end > total_size) {
        return setRegionError(name, "cap out of total", error);
    }
    // 已使用长度不能超过容量。
    if (used > cap) {
        return setRegionError(name, "used exceeds cap", error);
    }
    // 校验通过。
    return true;
}

// 将 payload 写到指定区域，并把剩余字节补零。
bool writeRegionPadded(std::vector<uint8_t>* bytes,
                       const uint64_t base_off,
                       const uint32_t off,
                       const uint32_t cap,
                       const std::vector<uint8_t>& payload,
                       std::string* error) {
    // 目标缓冲区不能为空。
    if (bytes == nullptr) {
        // 回填错误信息。
        if (error) {
            *error = "target bytes is null";
        }
        // 返回失败。
        return false;
    }
    // payload 不能超过容量。
    if (payload.size() > cap) {
        // 回填错误信息。
        if (error) {
            *error = "payload exceeds cap";
        }
        // 返回失败。
        return false;
    }

    // 计算绝对写入起始偏移。
    const uint64_t absOffsetU64 = base_off + static_cast<uint64_t>(off);
    // 计算绝对写入结束偏移。
    const uint64_t absEndU64 = absOffsetU64 + static_cast<uint64_t>(cap);
    // 边界检查：起始与结束都必须在目标数组范围内。
    if (absOffsetU64 > bytes->size() || absEndU64 > bytes->size()) {
        // 回填错误信息。
        if (error) {
            *error = "write region out of target bytes";
        }
        // 返回失败。
        return false;
    }

    // 转为 size_t，便于后续指针运算。
    const size_t absOffset = static_cast<size_t>(absOffsetU64);
    // 先拷贝有效 payload。
    if (!payload.empty()) {
        std::memcpy(bytes->data() + absOffset, payload.data(), payload.size());
    }
    // 再把剩余区域补零，保证“固定容量区域”语义稳定。
    if (cap > payload.size()) {
        std::memset(bytes->data() + absOffset + payload.size(), 0, cap - payload.size());
    }
    // 写入成功。
    return true;
}

// 结束命名空间。
}  // namespace vmp::base::bytes
