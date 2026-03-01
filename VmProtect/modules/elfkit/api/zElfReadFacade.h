/*
 * [VMP_FLOW_NOTE] 文件级流程注释。
 * - 文件：api/zElfReadFacade.h
 * - 主要职责：ELF 只读门面层：对底层解析细节做收敛，向上层暴露稳定读取接口。
 * - 输入：上层调用参数、文件路径与功能选择配置。
 * - 输出：稳定的接口声明、类型约束和调用契约。
 * - 关键约束：
 *   1) 严格保持 ELF 布局与索引一致性，避免地址/偏移漂移。
 *   2) 失败路径必须可定位（返回值/错误信息/日志三者保持一致）。
 *   3) 本文件改动优先保证与上游调用契约兼容，不隐式改变既有语义。
 */
// 防止头文件重复包含。
#pragma once

// 引入 patchbay 只读查询所需稳定数据类型。
#include "zPatchbayApiTypes.h"

// 引入字符串类型。
#include <string>
// 引入数组容器。
#include <vector>

// 进入命名空间。
namespace vmp::elfkit {

// zElfReadFacade：对 patchbay 只读查询能力的窄封装。
// 设计目标：
// 1) patchbay app/domain 只依赖一个入口类；
// 2) 屏蔽底层 PatchElfImage 后续演进细节；
// 3) 保持现有行为不变，便于渐进迁移。
class zElfReadFacade {
public:
    // 按路径加载 ELF。
    explicit zElfReadFacade(const char* elfPath);
    // 析构释放内部对象。
    ~zElfReadFacade();
    // 禁止拷贝。
    zElfReadFacade(const zElfReadFacade&) = delete;
    // 禁止拷贝赋值。
    zElfReadFacade& operator=(const zElfReadFacade&) = delete;
    // 支持移动构造。
    zElfReadFacade(zElfReadFacade&& other) noexcept;
    // 支持移动赋值。
    zElfReadFacade& operator=(zElfReadFacade&& other) noexcept;

    // ELF 是否加载成功。
    bool isLoaded() const;

    // 执行结构校验。
    bool validate(std::string* error = nullptr) const;

    // 解析指定符号。
    bool resolveSymbol(const char* symbolName, PatchSymbolInfo* outInfo) const;

    // 收集已定义动态导出（含 value）。
    bool collectDefinedDynamicExportInfos(std::vector<PatchDynamicExportInfo>* outExports,
                                          std::string* error) const;

    // 查询 patchbay 关键节快照。
    bool queryRequiredSections(PatchRequiredSections* out, std::string* error) const;

private:
    // 内部实现对象，屏蔽底层 PatchElfImage。
    class Impl;
    // 内部实现指针。
    Impl* impl_ = nullptr;
};

// 结束命名空间。
}  // namespace vmp::elfkit
