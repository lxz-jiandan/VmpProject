// 防止头文件重复包含。
#pragma once

// 引入 patchbay 只读 ELF API 类型定义。
#include "zPatchbayApi.h"

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
    explicit zElfReadFacade(const char* elfPath) : image_(elfPath) {}

    // ELF 是否加载成功。
    bool isLoaded() const { return image_.isLoaded(); }

    // 执行结构校验。
    bool validate(std::string* error = nullptr) const { return image_.validate(error); }

    // 解析指定符号。
    bool resolveSymbol(const char* symbolName, PatchSymbolInfo* outInfo) const {
        return image_.resolveSymbol(symbolName, outInfo);
    }

    // 收集已定义动态导出（含 value）。
    bool collectDefinedDynamicExportInfos(std::vector<PatchDynamicExportInfo>* outExports,
                                          std::string* error) const {
        return image_.collectDefinedDynamicExportInfos(outExports, error);
    }

    // 查询 patchbay 关键节快照。
    bool queryRequiredSections(PatchRequiredSections* out, std::string* error) const {
        return image_.queryRequiredSections(out, error);
    }

private:
    // 底层只读 ELF 对象。
    PatchElfImage image_;
};

// 结束命名空间。
}  // namespace vmp::elfkit
