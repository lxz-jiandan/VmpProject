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

