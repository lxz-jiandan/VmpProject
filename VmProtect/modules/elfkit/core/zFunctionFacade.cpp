/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - zFunction 门面方法实现（访问器、展示、翻译状态暴露、branch 重映射）。
 * - 加固链路位置：离线翻译 API 的轻量门面层。
 * - 输入：zFunction 内部缓存 + 外部共享 branch 地址表。
 * - 输出：对上层稳定可复用的查询/控制接口。
 */
#include "zFunction.h"

// 日志接口：用于在门面层输出失败原因，便于上层诊断。
#include "zLog.h"

// 字符串拼接：用于 assemblyInfo 的多行文本输出。
#include <sstream>
// 哈希映射：用于把目标地址快速映射到共享分支索引。
#include <unordered_map>

namespace {

// BL 的 VM 操作码常量。
// 放在门面实现单元，避免在头文件暴露内部枚举细节。
constexpr uint32_t kOpBlOpcode = 55;

}  // namespace

// 用 zFunctionData 做基类初始化，保持函数数据与门面对象一致。
zFunction::zFunction(const zFunctionData& data)
    : zFunctionData(data) {
}

// 返回函数名引用，不做拷贝。
const std::string& zFunction::name() const {
    return function_name;
}

// 返回函数在 so 中的偏移地址。
Elf64_Addr zFunction::offset() const {
    return function_offset;
}

// 返回函数机器码字节长度。
size_t zFunction::size() const {
    return function_bytes.size();
}

// 返回函数机器码首地址；空函数返回 nullptr。
const uint8_t* zFunction::data() const {
    return function_bytes.empty() ? nullptr : function_bytes.data();
}

// 返回函数是否为空（无机器码）。
bool zFunction::empty() const {
    return function_bytes.empty();
}

// 主动触发一次反汇编缓存构建，便于链式调用。
zFunction& zFunction::analyzeAssembly() {
    // 保证 asm_list_ 已准备好。
    ensureAsmReady();
    // 返回自身，支持 `func.analyzeAssembly().assemblyInfo()` 风格。
    return *this;
}

// 返回反汇编指令列表（只读）。
const std::vector<zInst>& zFunction::assemblyList() const {
    // 按需懒加载，避免无谓解析。
    ensureAsmReady();
    // 返回缓存引用，避免拷贝。
    return asm_list_;
}

// 导出整段反汇编文本，供日志或文件输出。
std::string zFunction::assemblyInfo() const {
    // 确保汇编缓存已就绪。
    ensureAsmReady();
    // 用 string stream 逐条拼接，控制换行格式。
    std::ostringstream oss;
    // 顺序遍历每条反汇编指令。
    for (size_t i = 0; i < asm_list_.size(); i++) {
        // 从第二行开始补换行，首行不补。
        if (i > 0) {
            oss << "\n";
        }
        // 追加当前指令文本。
        oss << asm_list_[i].getInfo();
    }
    // 返回拼接结果。
    return oss.str();
}

// 准备翻译缓存并返回状态；可选输出错误字符串。
bool zFunction::prepareTranslation(std::string* error) const {
    // 触发“未编码缓存”懒加载。
    ensureUnencodedReady();
    // 缓存构建失败时返回 false，并可回传错误原因。
    if (!unencoded_translate_ok_) {
        if (error != nullptr) {
            *error = unencoded_translate_error_;
        }
        return false;
    }
    // 成功路径清理外部错误字符串，避免上层误读旧错误。
    if (error != nullptr) {
        error->clear();
    }
    // 翻译缓存可用。
    return true;
}

// 返回最近一次翻译失败原因（成功时可能为空）。
const std::string& zFunction::lastTranslationError() const {
    return unencoded_translate_error_;
}

// 返回当前函数的共享 branch 地址缓存。
const std::vector<uint64_t>& zFunction::sharedBranchAddrs() const {
    // 先确保翻译缓存有效。
    ensureUnencodedReady();
    // 翻译失败时返回静态空数组，并记录日志。
    if (!unencoded_translate_ok_) {
        static const std::vector<uint64_t> kEmpty;
        LOGE("sharedBranchAddrs unavailable for %s: %s",
             function_name.c_str(),
             unencoded_translate_error_.c_str());
        return kEmpty;
    }
    // 成功时返回真实缓存引用。
    return branch_addrs_cache_;
}

// 把本函数中 BL 指令的“本地索引”重写成“共享地址表索引”。
bool zFunction::remapBlToSharedBranchAddrs(const std::vector<uint64_t>& shared_branch_addrs) {
    // 先确保有可用翻译缓存。
    ensureUnencodedReady();
    // 缓存不可用时直接失败。
    if (!unencoded_translate_ok_) {
        LOGE("remapBlToSharedBranchAddrs failed for %s: %s",
             function_name.c_str(),
             unencoded_translate_error_.c_str());
        return false;
    }
    // 若目标共享表为空，则只有“当前函数完全不含 BL”才允许成功。
    if (shared_branch_addrs.empty()) {
        // 扫描所有指令字流，检测是否有 BL。
        for (const auto& kv : inst_words_by_addr_cache_) {
            const std::vector<uint32_t>& words = kv.second;
            // 一旦存在 BL，说明无法映射到空共享表，应失败返回。
            if (!words.empty() && words[0] == kOpBlOpcode) {
                return false;
            }
        }
        // 无 BL 时可安全清空本地 branch 地址缓存。
        branch_addrs_cache_.clear();
        return true;
    }

    // 构建“地址 -> 共享索引”映射，便于 O(1) 查找。
    std::unordered_map<uint64_t, uint32_t> global_index_map;
    // 预留容量，降低 rehash 成本。
    global_index_map.reserve(shared_branch_addrs.size());
    // 顺序写入共享地址表索引。
    for (uint32_t i = 0; i < static_cast<uint32_t>(shared_branch_addrs.size()); ++i) {
        global_index_map.emplace(shared_branch_addrs[i], i);
    }

    // 遍历每条缓存指令，定位 BL 并重写其索引参数。
    for (auto& kv : inst_words_by_addr_cache_) {
        std::vector<uint32_t>& words = kv.second;
        // 非 BL 或空指令直接跳过。
        if (words.empty() || words[0] != kOpBlOpcode) {
            continue;
        }
        // BL 至少应包含“opcode + index”两个 word。
        if (words.size() < 2) {
            return false;
        }
        // 读取本地索引。
        const uint32_t local_index = words[1];
        // 本地索引越界代表缓存不一致，直接失败。
        if (local_index >= branch_addrs_cache_.size()) {
            return false;
        }
        // 读取本地索引对应的真实目标地址。
        const uint64_t target_addr = branch_addrs_cache_[local_index];
        // 在共享映射中查找该目标地址。
        auto it = global_index_map.find(target_addr);
        // 共享表不存在该地址时无法重映射。
        if (it == global_index_map.end()) {
            return false;
        }
        // 用共享索引覆盖原本地索引。
        words[1] = it->second;
    }

    // 全部重写成功后，把缓存地址表切换为共享表。
    branch_addrs_cache_ = shared_branch_addrs;
    return true;
}
