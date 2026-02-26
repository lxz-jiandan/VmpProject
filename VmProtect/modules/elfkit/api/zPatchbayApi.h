// 防止头文件重复包含。
#pragma once

// 引入 patchbay API 稳定数据类型。
#include "zPatchbayApiTypes.h"

// 引入字符串类型。
#include <string>
// 引入动态数组容器。
#include <vector>

// 进入命名空间。
namespace vmp::elfkit {

// PatchElfImage：面向 patchbay 场景的 ELF 只读访问器。
class PatchElfImage {
public:
    // 按路径加载 ELF。
    explicit PatchElfImage(const char* elfPath);
    // 析构释放资源。
    ~PatchElfImage();

    // 禁止拷贝。
    PatchElfImage(const PatchElfImage&) = delete;
    // 禁止拷贝赋值。
    PatchElfImage& operator=(const PatchElfImage&) = delete;
    // 支持移动构造。
    PatchElfImage(PatchElfImage&& other) noexcept;
    // 支持移动赋值。
    PatchElfImage& operator=(PatchElfImage&& other) noexcept;

    // ELF 是否加载成功。
    bool isLoaded() const;
    // 执行结构校验。
    bool validate(std::string* error = nullptr) const;

    // 解析指定符号（优先 .symtab，回退 .dynsym）。
    bool resolveSymbol(const char* symbolName, PatchSymbolInfo* outInfo) const;

    // 收集已定义动态导出（含 value）。
    bool collectDefinedDynamicExportInfos(std::vector<PatchDynamicExportInfo>* outExports,
                                          std::string* error) const;

    // 查询 patchbay 所需关键节集合。
    bool queryRequiredSections(PatchRequiredSections* out, std::string* error) const;

private:
    // pImpl 前置声明。
    class Impl;
    // pImpl 指针。
    Impl* impl_ = nullptr;
};

// 结束命名空间。
}  // namespace vmp::elfkit
