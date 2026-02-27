#include "zPatchbayRules.h"

// 判断是否为 C++ mangled 名（Itanium ABI）。
static bool isCxxMangledSymbol(const std::string& name) {
    // Itanium C++ ABI 下，C++ 符号通常以 "_Z" 开头。
    return name.rfind("_Z", 0) == 0;
}

// 判断 mangled 名中是否位于 vm 命名空间。
static bool isVmNamespaceCxxSymbol(const std::string& name) {
    // 根命名空间 vm 在 mangled 名里编码为 "N2vm"。
    // 示例：_ZN2vm3Foo3barEv / _ZNK2vm3Foo3barEv / _ZTIN2vm3FooE
    return name.find("N2vm") != std::string::npos;
}

// 校验 vmengine 输入导出是否满足命名规则。
bool validateVmengineExportNamingRules(const std::vector<std::string>& inputExports,
                                       std::string* error) {
    // 规则：
    // 1) C 导出必须以 vm_ 开头；
    // 2) C++ 导出必须位于 vm namespace（mangled 包含 N2vm）。
    for (const std::string& name : inputExports) {
        // C++ 符号按 namespace 规则校验。
        if (isCxxMangledSymbol(name)) {
            if (!isVmNamespaceCxxSymbol(name)) {
                if (error != nullptr) {
                    *error = "invalid vmengine C++ export (must be under vm namespace): " + name;
                }
                return false;
            }
            continue;
        }
        // C 符号必须以 vm_ 起始。
        if (name.rfind("vm_", 0) != 0) {
            if (error != nullptr) {
                *error = "invalid vmengine C export (must start with vm_): " + name;
            }
            return false;
        }
    }
    return true;
}
