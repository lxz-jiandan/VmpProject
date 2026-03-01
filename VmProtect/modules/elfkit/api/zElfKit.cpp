/*
 * [VMP_FLOW_NOTE] 文件级流程注释。
 * - 文件：api/zElfKit.cpp
 * - 主要职责：elfkit 对外主入口：负责编排 ELF 读取、函数提取、导出与保护流程。
 * - 输入：上层调用参数、文件路径与功能选择配置。
 * - 输出：面向调用方的执行结果、错误状态及可追踪日志。
 * - 关键约束：
 *   1) 严格保持 ELF 布局与索引一致性，避免地址/偏移漂移。
 *   2) 失败路径必须可定位（返回值/错误信息/日志三者保持一致）。
 *   3) 本文件改动优先保证与上游调用契约兼容，不隐式改变既有语义。
 */
#include "zElfKit.h"

// 引入底层 ELF 解析对象。
#include "zElf.h"
// 引入底层函数对象。
#include "zFunction.h"

// 引入 move 工具。
#include <utility>
// 引入动态数组容器。
#include <vector>

// 进入命名空间。
namespace vmp::elfkit {

// 匿名命名空间：内部桥接工具。
namespace {

// 将统一 void* 转为可写 zFunction*。
zFunction* toMutableFunction(void* implPtr) {
    // 该指针由底层 zElf::getFunction 返回，类型在本模块内可控。
    return reinterpret_cast<zFunction*>(implPtr);
}

// 将统一 void* 转为只读 zFunction*。
const zFunction* toConstFunction(void* implPtr) {
    // 只读访问路径复用同一底层对象地址。
    return reinterpret_cast<const zFunction*>(implPtr);
}

// 将新 API 的 DumpMode 转换为旧实现枚举。
zFunction::DumpMode toLegacyDumpMode(const DumpMode mode) {
    switch (mode) {
        case DumpMode::kUnencoded:
            return zFunction::DumpMode::UNENCODED;
        case DumpMode::kUnencodedBin:
            return zFunction::DumpMode::UNENCODED_BIN;
        case DumpMode::kEncoded:
            return zFunction::DumpMode::ENCODED;
    }
    // 理论不可达，防御性回退。
    // 若未来枚举扩展但未同步映射，这里默认走编码输出。
    return zFunction::DumpMode::ENCODED;
}

// 返回全局空字符串引用，避免返回悬垂引用。
const std::string& emptyName() {
    // 静态对象生命周期覆盖整个进程，返回引用安全。
    static const std::string kEmptyName;
    return kEmptyName;
}

// 返回全局空地址数组引用，避免返回悬垂引用。
const std::vector<uint64_t>& emptyBranchAddrs() {
    // 静态空数组用于避免临时对象引用悬垂。
    static const std::vector<uint64_t> kEmpty;
    return kEmpty;
}

// 结束匿名命名空间。
}  // namespace

// pImpl 定义：当前仅持有一个 zElf 对象。
class ElfImage::Impl {
public:
    // 按路径构造内部 zElf。
    explicit Impl(const char* path) : elf(path) {}

    // 底层 ELF 对象。
    zElf elf;
};

// 由内部实现指针构造 FunctionView。
FunctionView::FunctionView(void* implPtr) : impl_ptr_(implPtr) {}

// 判断视图是否有效。
bool FunctionView::isValid() const {
    // impl_ptr_ 非空即可认为底层对象可访问。
    return impl_ptr_ != nullptr;
}

// 获取函数名。
const std::string& FunctionView::getName() const {
    // 先转只读对象，失败时返回静态空字符串。
    const zFunction* function = toConstFunction(impl_ptr_);
    return function ? function->getName() : emptyName();
}

// 获取函数偏移。
uint64_t FunctionView::getOffset() const {
    // 统一转成 uint64_t，屏蔽底层返回类型差异。
    const zFunction* function = toConstFunction(impl_ptr_);
    return function ? static_cast<uint64_t>(function->getOffset()) : 0;
}

// 获取函数大小。
size_t FunctionView::getSize() const {
    // 无效对象返回 0，调用方可据此做空检查。
    const zFunction* function = toConstFunction(impl_ptr_);
    return function ? function->getSize() : 0;
}

// 获取函数数据指针。
const uint8_t* FunctionView::getData() const {
    // data 指向底层函数字节缓存，不做拷贝。
    const zFunction* function = toConstFunction(impl_ptr_);
    return function ? function->getData() : nullptr;
}

// 准备翻译中间态。
bool FunctionView::prepareTranslation(std::string* error) const {
    // prepareTranslation 会更新函数内部翻译状态，因此需要可写对象。
    zFunction* function = toMutableFunction(impl_ptr_);
    return function ? function->prepareTranslation(error) : false;
}

// 按模式导出函数。
bool FunctionView::dump(const char* filePath, const DumpMode mode) const {
    // 新 API 模式先映射到旧实现模式，再委托底层 dump。
    zFunction* function = toMutableFunction(impl_ptr_);
    return function ? function->dump(filePath, toLegacyDumpMode(mode)) : false;
}

// 获取共享分支地址列表。
const std::vector<uint64_t>& FunctionView::getSharedBranchAddrs() const {
    // 无对象时返回静态空数组，避免 nullptr 语义。
    zFunction* function = toMutableFunction(impl_ptr_);
    return function ? function->getSharedBranchAddrs() : emptyBranchAddrs();
}

// 执行 BL 重映射。
bool FunctionView::remapBlToSharedBranchAddrs(const std::vector<uint64_t>& sharedBranchAddrs) const {
    // 该操作会改写分支映射，因此需要可写对象。
    zFunction* function = toMutableFunction(impl_ptr_);
    return function ? function->remapBlToSharedBranchAddrs(sharedBranchAddrs) : false;
}

// 构造 ElfImage 并分配 pImpl。
ElfImage::ElfImage(const char* elfPath)
    // pImpl 在构造时一次性创建，后续由移动语义转移所有权。
    : impl_(new Impl(elfPath)) {}

// 析构并释放 pImpl。
ElfImage::~ElfImage() {
    // 与构造配对释放 pImpl。
    delete impl_;
    // 置空防止析构后误用。
    impl_ = nullptr;
}

// 移动构造：窃取 pImpl 所有权。
ElfImage::ElfImage(ElfImage&& other) noexcept
    : impl_(other.impl_) {
    // 被移动对象释放所有权，置空即可。
    other.impl_ = nullptr;
}

// 移动赋值：先释放自身再窃取对方 pImpl。
ElfImage& ElfImage::operator=(ElfImage&& other) noexcept {
    if (this == &other) {
        // 自移动保护。
        return *this;
    }
    // 先释放旧资源。
    delete impl_;
    // 再接管对方资源。
    impl_ = other.impl_;
    // 对方置空，避免双重释放。
    other.impl_ = nullptr;
    return *this;
}

// 判断 ELF 是否已加载。
bool ElfImage::isLoaded() const {
    // 同时检查 pImpl、文件指针与文件大小，避免半初始化状态。
    return impl_ != nullptr && impl_->elf.elf_file_ptr != nullptr && impl_->elf.file_size > 0;
}

// 按符号名查找函数。
FunctionView ElfImage::getFunction(const std::string& symbolName) {
    if (!impl_) {
        // 未初始化时返回空视图。
        return FunctionView();
    }
    // getFunction 返回底层对象地址，直接封装成 FunctionView。
    return FunctionView(impl_->elf.getFunction(symbolName.c_str()));
}

// 列举全部函数视图。
std::vector<FunctionView> ElfImage::getFunctions() {
    std::vector<FunctionView> out;
    if (!impl_) {
        // 未初始化直接返回空列表。
        return out;
    }
    // 获取底层函数列表并逐个包装为 FunctionView。
    const std::vector<zFunction>& functions = impl_->elf.getFunctionList();
    // 预分配容量，避免 반복扩容。
    out.reserve(functions.size());
    for (const zFunction& function : functions) {
        // 底层接口需要非常量指针，这里仅做视图封装，不改变对象生命周期。
        out.emplace_back(FunctionView(const_cast<zFunction*>(&function)));
    }
    return out;
}

// 结束命名空间。
}  // namespace vmp::elfkit

