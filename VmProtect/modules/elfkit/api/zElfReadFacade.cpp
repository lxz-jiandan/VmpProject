/*
 * [VMP_FLOW_NOTE] 文件级流程注释。
 * - 文件：api/zElfReadFacade.cpp
 * - 主要职责：ELF 只读门面层：对底层解析细节做收敛，向上层暴露稳定读取接口。
 * - 输入：上层调用参数、文件路径与功能选择配置。
 * - 输出：面向调用方的执行结果、错误状态及可追踪日志。
 * - 关键约束：
 *   1) 严格保持 ELF 布局与索引一致性，避免地址/偏移漂移。
 *   2) 失败路径必须可定位（返回值/错误信息/日志三者保持一致）。
 *   3) 本文件改动优先保证与上游调用契约兼容，不隐式改变既有语义。
 */
// 引入门面声明。
#include "zElfReadFacade.h"

// 引入底层 patchbay 只读 ELF 实现。
#include "zPatchbayApi.h"

namespace vmp::elfkit {

// 门面内部实现：仅持有底层 PatchElfImage。
class zElfReadFacade::Impl {
public:
    explicit Impl(const char* elfPath) : image(elfPath) {}

    PatchElfImage image;
};

zElfReadFacade::zElfReadFacade(const char* elfPath)
    : impl_(new Impl(elfPath)) {}

zElfReadFacade::~zElfReadFacade() {
    delete impl_;
    impl_ = nullptr;
}

zElfReadFacade::zElfReadFacade(zElfReadFacade&& other) noexcept
    : impl_(other.impl_) {
    other.impl_ = nullptr;
}

zElfReadFacade& zElfReadFacade::operator=(zElfReadFacade&& other) noexcept {
    if (this == &other) {
        return *this;
    }
    delete impl_;
    impl_ = other.impl_;
    other.impl_ = nullptr;
    return *this;
}

bool zElfReadFacade::isLoaded() const {
    return impl_ != nullptr && impl_->image.isLoaded();
}

bool zElfReadFacade::validate(std::string* error) const {
    if (impl_ == nullptr) {
        if (error != nullptr) {
            *error = "zElfReadFacade is moved-from";
        }
        return false;
    }
    return impl_->image.validate(error);
}

bool zElfReadFacade::resolveSymbol(const char* symbolName, PatchSymbolInfo* outInfo) const {
    if (impl_ == nullptr) {
        return false;
    }
    return impl_->image.resolveSymbol(symbolName, outInfo);
}

bool zElfReadFacade::collectDefinedDynamicExportInfos(std::vector<PatchDynamicExportInfo>* outExports,
                                                      std::string* error) const {
    if (impl_ == nullptr) {
        if (error != nullptr) {
            *error = "zElfReadFacade is moved-from";
        }
        return false;
    }
    return impl_->image.collectDefinedDynamicExportInfos(outExports, error);
}

bool zElfReadFacade::queryRequiredSections(PatchRequiredSections* out, std::string* error) const {
    if (impl_ == nullptr) {
        if (error != nullptr) {
            *error = "zElfReadFacade is moved-from";
        }
        return false;
    }
    return impl_->image.queryRequiredSections(out, error);
}

}  // namespace vmp::elfkit

