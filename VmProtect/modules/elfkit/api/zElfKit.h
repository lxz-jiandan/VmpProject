// 防止头文件重复包含。
#pragma once

// 引入 size_t。
#include <cstddef>
// 引入定宽整数。
#include <cstdint>
// 引入字符串类型。
#include <string>
// 引入动态数组容器。
#include <vector>

// 进入 elfkit API 命名空间。
namespace vmp::elfkit {

// 函数 dump 模式。
enum class DumpMode {
    // 文本格式，未编码指令流。
    kUnencoded,
    // 二进制格式，未编码字节。
    kUnencodedBin,
    // 二进制格式，编码后的字节。
    kEncoded,
};

// 函数视图：对内部 zFunction 的轻量外观封装。
class FunctionView {
public:
    // 默认构造，表示无效视图。
    FunctionView() = default;

    // 视图是否指向有效函数对象。
    bool isValid() const;
    // 函数名。
    const std::string& getName() const;
    // 函数文件偏移。
    uint64_t getOffset() const;
    // 函数字节长度。
    size_t getSize() const;
    // 函数字节数据指针。
    const uint8_t* getData() const;

    // 准备翻译中间态。
    bool prepareTranslation(std::string* error = nullptr) const;
    // 按指定模式导出函数内容。
    bool dump(const char* filePath, DumpMode mode) const;
    // 获取共享分支地址列表。
    const std::vector<uint64_t>& getSharedBranchAddrs() const;
    // 将 BL 指令重映射到共享分支地址列表。
    bool remapBlToSharedBranchAddrs(const std::vector<uint64_t>& sharedBranchAddrs) const;

private:
    // 仅允许 ElfImage 构造有效视图。
    friend class ElfImage;
    // 由内部实现指针构造视图。
    explicit FunctionView(void* implPtr);
    // 内部实现对象指针（zFunction*）。
    void* impl_ptr_ = nullptr;
};

// ELF 图像封装：负责加载、查询和函数枚举。
class ElfImage {
public:
    // 按路径加载 ELF。
    explicit ElfImage(const char* elfPath);
    // 释放内部资源。
    ~ElfImage();

    // 禁止拷贝，避免双重释放。
    ElfImage(const ElfImage&) = delete;
    // 禁止拷贝赋值，避免双重释放。
    ElfImage& operator=(const ElfImage&) = delete;
    // 允许移动构造。
    ElfImage(ElfImage&& other) noexcept;
    // 允许移动赋值。
    ElfImage& operator=(ElfImage&& other) noexcept;

    // ELF 是否加载成功。
    bool isLoaded() const;
    // 按符号名查找函数。
    FunctionView getFunction(const std::string& symbolName);
    // 列举全部函数视图。
    std::vector<FunctionView> getFunctions();

private:
    // pImpl 前置声明。
    class Impl;
    // pImpl 指针。
    Impl* impl_ = nullptr;
};

// 结束命名空间。
}  // namespace vmp::elfkit


