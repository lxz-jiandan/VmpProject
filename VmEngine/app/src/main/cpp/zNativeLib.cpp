/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - JNI_OnLoad 回归总控，串联多条执行路线与 takeover 校验。
 * - 加固链路位置：运行时入口编排层。
 * - 输入：assets + expand so + 内嵌 payload + 符号清单。
 * - 输出：各路线回归结果与 JNI 初始化状态。
 */
#include <jni.h>  // JNI_OnLoad / JNIEnv / JavaVM。

#include <cerrno>         // errno / strerror。
#include <cctype>         // std::isspace。
#include <cstdint>        // uint64_t / uintptr_t。
#include <cstdlib>        // std::strtoull。
#include <cstring>        // std::strerror。
#include <dlfcn.h>        // dladdr。
#include <fcntl.h>        // open。
#include <memory>         // std::unique_ptr / std::make_unique。
#include <new>            // placement new。
#include <sstream>        // std::stringstream。
#include <string>         // std::string。
#include <type_traits>    // std::aligned_storage。
#include <unordered_map>  // 名称/地址索引。
#include <unordered_set>  // 差分用例过滤集合。
#include <unistd.h>       // write / close。
#include <vector>         // 动态数组容器。

#include "zAssestManager.h"  // assets 读写与解包。
#include "zEmbeddedPayload.h"  // route4 嵌入 payload 读取。
#include "zFunction.h"       // zFunction 装载与地址绑定。
#include "zLog.h"            // LOGI/LOGE。
#include "zSoBinBundle.h"    // expand so 容器读取。
#include "zSymbolTakeover.h" // route4 L2 导出符号接管。
#include "zVmEngine.h"       // VM 执行入口。

// 保存解包后的 base so 绝对路径，供 zLinker 执行与后续日志定位复用。
static std::string g_libdemo_so_path;
// 保存解包后的 expand so 绝对路径，供 expand 容器读取流程复用。
static std::string g_libdemo_expand_so_path;
// 保存 route4 从 vmengine.so 内嵌 payload 落盘后的 expand so 路径。
static std::string g_libdemo_expand_embedded_so_path;

// 资产名：基础 so（文本/编码 bin 路线都基于它执行）。
constexpr const char* kAssetBaseSo = "libdemo.so";
// 资产名：expand so（编码容器路线使用）。
constexpr const char* kAssetExpandSo = "libdemo_expand.so";
// route4 运行时落盘的 expand so 文件名。
constexpr const char* kEmbeddedExpandSoName = "libdemo_expand_embedded.so";
// 资产名：所有函数共享的一份 branch 地址列表。
constexpr const char* kAssetBranchAddrList = "branch_addr_list.txt";
// 字符串返回值用例函数名，用于覆盖对象返回（sret）路径。
constexpr const char* kStringCaseFunctionName = "fun_cpp_make_string";
// 字符串用例的文本资产。
constexpr const char* kStringCaseTxtAsset = "fun_cpp_make_string.txt";
// 字符串用例的编码资产。
constexpr const char* kStringCaseBinAsset = "fun_cpp_make_string.bin";
// 基础算术用例的固定期望值，防止“三路一致但整体错误”。
constexpr uint64_t kExpectedResult = 30;

namespace {

struct FunctionCaseConfig {
    // 回归函数名（也是日志标识）。
    const char* function_name;
    // 未编码路线读取的文本文件名。
    const char* txt_asset;
    // 编码路线读取的 bin 文件名。
    const char* bin_asset;
};

struct FunctionCaseResult {
    // 以未编码路线为基准记录地址和期望结果，后两条路线做一致性比对。
    // 函数名。
    std::string function_name;
    // 基准路线解析得到的函数地址。
    uint64_t fun_addr = 0;
    // 基准路线执行结果（字符串用例不使用该字段）。
    uint64_t expected_result = 0;
};

enum class EmbeddedExpandRouteStatus {
    kPass = 0,
    kSkipNoPayload = 1,
    kFail = 2,
};

const FunctionCaseConfig kFunctionCases[] = {
    // 固定顺序用于三条路线逐项对齐；带全局写入副作用的用例放在列表末尾。
    {"fun_for", "fun_for.txt", "fun_for.bin"},  // 基础 for 循环。
    {"fun_add", "fun_add.txt", "fun_add.bin"},  // 基础整数加法。
    {"fun_for_add", "fun_for_add.txt", "fun_for_add.bin"},  // 固定值守门用例。
    {"fun_if_sub", "fun_if_sub.txt", "fun_if_sub.bin"},  // if 分支 + 减法路径。
    {"fun_countdown_muladd", "fun_countdown_muladd.txt", "fun_countdown_muladd.bin"},  // 递减循环 + 乘加。
    {"fun_loop_call_mix", "fun_loop_call_mix.txt", "fun_loop_call_mix.bin"},  // 循环中调用子函数。
    {"fun_call_chain", "fun_call_chain.txt", "fun_call_chain.bin"},  // 多层调用链。
    {"fun_branch_call", "fun_branch_call.txt", "fun_branch_call.bin"},  // 分支后调用路径。
    {"fun_cpp_string_len", "fun_cpp_string_len.txt", "fun_cpp_string_len.bin"},  // C++ string 长度读取。
    {"fun_cpp_vector_sum", "fun_cpp_vector_sum.txt", "fun_cpp_vector_sum.bin"},  // C++ vector 求和。
    {"fun_cpp_virtual_mix", "fun_cpp_virtual_mix.txt", "fun_cpp_virtual_mix.bin"},  // 虚函数分派混合路径。
    {"fun_global_data_mix", "fun_global_data_mix.txt", "fun_global_data_mix.bin"},  // 全局数据读写混合。
    {"fun_static_local_table", "fun_static_local_table.txt", "fun_static_local_table.bin"},  // 静态局部表访问。
    {"fun_global_struct_acc", "fun_global_struct_acc.txt", "fun_global_struct_acc.bin"},  // 全局结构体字段累计。
    {"fun_class_static_member", "fun_class_static_member.txt", "fun_class_static_member.bin"},  // 类静态成员读写。
    {"fun_multi_branch_path", "fun_multi_branch_path.txt", "fun_multi_branch_path.bin"},  // 多分支路径覆盖。
    {"fun_switch_dispatch", "fun_switch_dispatch.txt", "fun_switch_dispatch.bin"},  // switch 派发路径。
    {"fun_bitmask_branch", "fun_bitmask_branch.txt", "fun_bitmask_branch.bin"},  // 位运算 + 分支。
    {"fun_global_table_rw", "fun_global_table_rw.txt", "fun_global_table_rw.bin"},  // 全局表读写。
    {"fun_global_mutable_state", "fun_global_mutable_state.txt", "fun_global_mutable_state.bin"},  // 全局可变状态。
};

// 统一空白裁剪工具：
// 输入保持只读，返回一个新字符串，不修改原值。
std::string trimCopy(const std::string& value) {
    // 只做前后空白裁剪，不改中间内容。
    // begin 指向首个非空白字符。
    size_t begin = 0;
    // 跳过前导空白。
    while (begin < value.size() && std::isspace(static_cast<unsigned char>(value[begin])) != 0) {
        ++begin;
    }

    // end 从末尾开始回退，定位最后一个非空白字符的后一位。
    size_t end = value.size();
    // 跳过尾随空白。
    while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1])) != 0) {
        --end;
    }
    // 返回裁剪后的新字符串。
    return value.substr(begin, end - begin);
}

// 解析 `branch_addr_list.txt`：
// 支持两种信息：
// 1) 可选 `branch_addr_count = N;`
// 2) 必选 `branch_addr_list = {...};`
// 返回 true 表示解析成功且（若有 count）数量一致。
bool parseSharedBranchAddrListText(const std::vector<uint8_t>& text_data, std::vector<uint64_t>& out_branch_addrs) {
    // 每次解析前先清空输出，避免残留旧数据。
    out_branch_addrs.clear();
    // 输入为空直接失败。
    if (text_data.empty()) {
        return false;
    }

    // 把字节数组转换为文本，后续统一用字符串查找/切片解析。
    const std::string text(reinterpret_cast<const char*>(text_data.data()), text_data.size());

    // 兼容 "branch_addr_count = N;" 可选字段，存在时做数量一致性校验。
    // 标记是否解析到了 count 字段。
    bool has_expected_count = false;
    // 解析出的期望数量。
    uint64_t expected_count = 0;
    // 定位 count 字段名。
    size_t count_pos = text.find("branch_addr_count");
    // 找到字段才继续解析等号和分号。
    if (count_pos != std::string::npos) {
        // 定位 '='。
        size_t eq = text.find('=', count_pos);
        // 定位 ';'。
        size_t sc = text.find(';', eq);
        // 仅当边界合法时再切片。
        if (eq != std::string::npos && sc != std::string::npos && sc > eq) {
            // 取出等号与分号之间的内容并裁剪空白。
            std::string count_str = trimCopy(text.substr(eq + 1, sc - eq - 1));
            // 非空才做数字解析。
            if (!count_str.empty()) {
                // strtoull 支持十进制和 0x 前缀十六进制。
                expected_count = std::strtoull(count_str.c_str(), nullptr, 0);
                // 标记 count 生效，后面将启用一致性校验。
                has_expected_count = true;
            }
        }
    }

    // 定位 branch 列表字段名。
    size_t list_pos = text.find("branch_addr_list");
    // 未找到列表字段则失败。
    if (list_pos == std::string::npos) {
        return false;
    }
    // 定位列表左花括号。
    size_t l = text.find('{', list_pos);
    // 定位列表右花括号。
    size_t r = text.find('}', l == std::string::npos ? list_pos : l + 1);
    // 括号不完整或区间非法则失败。
    if (l == std::string::npos || r == std::string::npos || r <= l) {
        return false;
    }

    // 取出花括号内部内容。
    std::string body = text.substr(l + 1, r - l - 1);
    // 构建字符串流，按逗号分割 token。
    std::stringstream ss(body);
    // 承接每个 token。
    std::string token;
    // 按十进制/十六进制自动解析，允许逗号后带空白。
    while (std::getline(ss, token, ',')) {
        // 去除 token 前后空白。
        std::string trimmed = trimCopy(token);
        // 空 token 跳过。
        if (trimmed.empty()) {
            continue;
        }
        // 解析地址值。
        uint64_t addr = std::strtoull(trimmed.c_str(), nullptr, 0);
        // 写入输出数组。
        out_branch_addrs.push_back(addr);
    }

    // 如果存在 count 字段，则校验数量一致。
    if (has_expected_count && expected_count != out_branch_addrs.size()) {
        LOGE("parseSharedBranchAddrListText count mismatch: expected=%llu actual=%llu",
             static_cast<unsigned long long>(expected_count),
             static_cast<unsigned long long>(out_branch_addrs.size()));
        return false;
    }
    // 解析成功。
    return true;
}

// 从 assets 读取共享 branch 地址表并解析到向量。
// 失败会打印明确错误来源（读取失败 / 文本格式失败）。
bool loadSharedBranchAddrsFromAsset(JNIEnv* env, const char* asset_name, std::vector<uint64_t>& out_branch_addrs) {
    // branch_addr_list 是所有函数共享的一份索引表，先完整读取再一次性下发给 VM。
    // 承接 asset 原始文本字节。
    std::vector<uint8_t> text_data;
    // 从 assets 中读取文件。
    if (!zAssetManager::loadAssetDataByFileName(env, asset_name, text_data)) {
        LOGE("loadSharedBranchAddrsFromAsset failed to read asset: %s", asset_name);
        return false;
    }
    // 解析文本中的 branch 列表。
    if (!parseSharedBranchAddrListText(text_data, out_branch_addrs)) {
        LOGE("loadSharedBranchAddrsFromAsset failed to parse asset: %s", asset_name);
        return false;
    }
    // 成功返回。
    return true;
}

// 构造默认执行参数：
// 当前所有回归函数统一用 (2,4)，后续若需函数级参数可在此扩展。
zParams buildDefaultParams(const char* function_name) {
    // 本函数当前不区分函数名，保留参数是为了后续可按函数定制入参。
    (void)function_name;
    // 三条路线统一使用同一组参数，验证编码链路一致性。
    return zParams(std::vector<uint64_t>{2, 4});
}

// 生成字符串用例期望值：
// 与 demo::fun_cpp_make_string 的语义保持一致：A{a}:{b}。
std::string buildExpectedStringCaseResult(const zParams& params) {
    // 与 demo 中 fun_cpp_make_string 的语义保持一致：A{a}:{b}
    // 读取第一个参数，不存在则按 0。
    const int a = (params.values.size() > 0) ? static_cast<int>(params.values[0]) : 0;
    // 读取第二个参数，不存在则按 0。
    const int b = (params.values.size() > 1) ? static_cast<int>(params.values[1]) : 0;
    // 拼接期望字符串。
    return std::string("A") + std::to_string(a) + ":" + std::to_string(b);
}

} // namespace

// 准备单条路线所需的 so：
// 1) 从 assets 解包到文件系统；
// 2) 交给自定义 linker 加载。
bool prepareRouteLibrary(JNIEnv* env, zVmEngine& engine, const char* asset_so_name, std::string& out_path) {
    // 每条路线都从 asset 解包出独立 so，再交给自定义 linker 装载。
    // 先把 so 从 assets 解压到应用可访问路径。
    if (!zAssetManager::extractAssetToFile(env, asset_so_name, out_path)) {
        LOGE("extract asset failed: %s", asset_so_name);
        return false;
    }
    // 再交给 VM 的自定义 linker 进行加载和重定位。
    if (!engine.LoadLibrary(out_path.c_str())) {
        LOGE("custom linker load failed: %s", out_path.c_str());
        return false;
    }
    // 准备成功。
    return true;
}

// 执行 uint64 返回值用例：
// - 输入：函数地址 + 路线标记 + so 名称；
// - 输出：可选回写到 out_result；
// - 判定：仅保证调用成功，结果正确性由外层比对。
bool executeCase(
    zVmEngine& engine,
    const char* so_name,
    const char* route_tag,
    const char* function_name,
    uint64_t fun_addr,
    uint64_t* out_result
) {
    // 函数地址必须有效。
    if (fun_addr == 0) {
        LOGE("[%s][%s] invalid fun_addr=0", route_tag, function_name);
        return false;
    }
    // so 名称必须有效。
    if (so_name == nullptr || so_name[0] == '\0') {
        LOGE("[%s][%s] invalid so_name", route_tag, function_name);
        return false;
    }

    // 构造统一入参。
    zParams params = buildDefaultParams(function_name);
    // 默认结果缓冲。
    uint64_t result = 0;
    // execute 返回主返回寄存器值；同时 retBuffer 允许 VM 在需要时写回对象/聚合返回。
    result = engine.execute(&result, so_name, fun_addr, params);
    // 记录执行日志。
    LOGI("[%s][%s] execute by fun_addr=0x%llx result=%llu",
         route_tag,
         function_name,
         static_cast<unsigned long long>(fun_addr),
         static_cast<unsigned long long>(result));
    // 如果调用方提供输出指针，则回传结果。
    if (out_result != nullptr) {
        *out_result = result;
    }
    // 执行成功。
    return true;
}

// 执行字符串返回值用例（sret 路径）：
// - 通过 placement-new 提供对象存储；
// - execute 后读取对象值并显式析构；
// - 与期望字符串比对。
bool executeStringCase(
    zVmEngine& engine,
    const char* so_name,
    const char* route_tag,
    const char* function_name,
    uint64_t fun_addr
) {
    // 字符串用例也先做基础参数校验。
    if (fun_addr == 0) {
        LOGE("[%s][%s] invalid fun_addr=0", route_tag, function_name);
        return false;
    }
    // so 名称必须非空。
    if (so_name == nullptr || so_name[0] == '\0') {
        LOGE("[%s][%s] invalid so_name", route_tag, function_name);
        return false;
    }

    // 构造统一入参。
    zParams params = buildDefaultParams(function_name);
    // 为 std::string 预留一块对齐后的栈内存，避免额外堆分配。
    using StringStorage = typename std::aligned_storage<sizeof(std::string), alignof(std::string)>::type;
    // 原位存储区清零初始化。
    StringStorage storage{};
    // 先原位构造一份对象，VM 可直接把返回对象写入该地址，随后统一走显式析构。
    std::string* out = new (&storage) std::string();
    // 记录输出对象地址，方便日志排查。
    const uint64_t out_ptr = reinterpret_cast<uint64_t>(out);
    // 执行函数：ret 为寄存器返回值，out 承接对象内容。
    const uint64_t ret = engine.execute(out, so_name, fun_addr, params);
    // 基于入参构造期望字符串。
    const std::string expected = buildExpectedStringCaseResult(params);

    // 拷贝出实际字符串值，随后手动析构 placement-new 对象。
    const std::string actual = *out;
    // 手动析构，匹配上面的 placement new。
    out->~basic_string();
    // 打印详细日志，包含 ret/out 指针和值。
    LOGI("[%s][%s] execute by fun_addr=0x%llx ret_ptr=0x%llx out_ptr=0x%llx value=%s",
         route_tag,
         function_name,
         static_cast<unsigned long long>(fun_addr),
         static_cast<unsigned long long>(ret),
         static_cast<unsigned long long>(out_ptr),
         actual.c_str());

    // 结果不一致即判失败。
    if (actual != expected) {
        LOGE("[%s][%s] string mismatch: actual=%s expected=%s",
             route_tag,
             function_name,
             actual.c_str(),
             expected.c_str());
        return false;
    }
    // 字符串回归成功。
    return true;
}

bool resolveCurrentLibraryPath(void* symbol, std::string& out_path) {
    out_path.clear();
    if (symbol == nullptr) {
        return false;
    }

    Dl_info info{};
    if (dladdr(symbol, &info) == 0 || info.dli_fname == nullptr || info.dli_fname[0] == '\0') {
        return false;
    }
    out_path = info.dli_fname;
    return true;
}

bool writeBytesToFile(const std::string& path, const std::vector<uint8_t>& data) {
    if (path.empty()) {
        return false;
    }

    int fd = open(path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (fd < 0) {
        LOGE("writeBytesToFile open failed: %s errno=%d", path.c_str(), errno);
        return false;
    }

    const uint8_t* ptr = data.empty() ? nullptr : data.data();
    size_t remain = data.size();
    while (remain > 0) {
        ssize_t wrote = write(fd, ptr, remain);
        if (wrote <= 0) {
            LOGE("writeBytesToFile write failed: %s errno=%d", path.c_str(), errno);
            close(fd);
            return false;
        }
        ptr += wrote;
        remain -= static_cast<size_t>(wrote);
    }

    close(fd);
    return true;
}

// 直接执行 so 内原生函数，并与 VM 基准结果做差分校验。
bool test_nativeVsVm(JNIEnv* env, zVmEngine& engine, const std::vector<FunctionCaseResult>& reference_cases) {
    // env 当前不直接使用，保留参数与其它路线签名一致。
    (void)env;
    if (reference_cases.empty()) {
        LOGE("[route_native_vs_vm] reference_cases is empty");
        return false;
    }

    soinfo* so_info = engine.GetSoinfo(kAssetBaseSo);
    if (so_info == nullptr || so_info->base == 0) {
        LOGE("[route_native_vs_vm] soinfo unavailable for %s", kAssetBaseSo);
        return false;
    }

    std::unordered_map<std::string, FunctionCaseResult> case_map;
    for (const FunctionCaseResult& item : reference_cases) {
        case_map[item.function_name] = item;
    }

    using NativeBinaryFn = uint64_t (*)(uint64_t, uint64_t);
    const std::unordered_set<std::string> stateful_cases = {
        "fun_global_data_mix",
        "fun_static_local_table",
        "fun_global_struct_acc",
        "fun_class_static_member",
        "fun_global_table_rw",
        "fun_global_mutable_state",
    };
    for (const FunctionCaseConfig& config : kFunctionCases) {
        const std::string case_name = config.function_name == nullptr ? std::string() : std::string(config.function_name);
        if (stateful_cases.find(case_name) != stateful_cases.end()) {
            LOGI("[route_native_vs_vm][%s] skip stateful case", case_name.c_str());
            continue;
        }
        auto it = case_map.find(case_name);
        if (it == case_map.end()) {
            LOGE("[route_native_vs_vm] missing reference case: %s", case_name.c_str());
            return false;
        }

        const zParams params = buildDefaultParams(case_name.c_str());
        const uint64_t arg0 = (params.values.size() > 0) ? params.values[0] : 0;
        const uint64_t arg1 = (params.values.size() > 1) ? params.values[1] : 0;
        const uintptr_t fn_addr = static_cast<uintptr_t>(so_info->base + it->second.fun_addr);
        NativeBinaryFn native_fn = reinterpret_cast<NativeBinaryFn>(fn_addr);

        const uint64_t native_result = native_fn(arg0, arg1);
        LOGI("[route_native_vs_vm][%s] native= %llu vm_baseline=%llu fun_addr=0x%llx",
             case_name.c_str(),
             static_cast<unsigned long long>(native_result),
             static_cast<unsigned long long>(it->second.expected_result),
             static_cast<unsigned long long>(it->second.fun_addr));
        if (native_result != it->second.expected_result) {
            LOGE("[route_native_vs_vm][%s] mismatch native=%llu vm=%llu",
                 case_name.c_str(),
                 static_cast<unsigned long long>(native_result),
                 static_cast<unsigned long long>(it->second.expected_result));
            return false;
        }
    }

    auto string_case_it = case_map.find(kStringCaseFunctionName);
    if (string_case_it == case_map.end()) {
        LOGE("[route_native_vs_vm] missing reference case: %s", kStringCaseFunctionName);
        return false;
    }
    using NativeStringFn = std::string (*)(int, int);
    const zParams string_params = buildDefaultParams(kStringCaseFunctionName);
    const int a = (string_params.values.size() > 0) ? static_cast<int>(string_params.values[0]) : 0;
    const int b = (string_params.values.size() > 1) ? static_cast<int>(string_params.values[1]) : 0;
    const uintptr_t string_fn_addr = static_cast<uintptr_t>(so_info->base + string_case_it->second.fun_addr);
    NativeStringFn native_string_fn = reinterpret_cast<NativeStringFn>(string_fn_addr);
    const std::string native_string = native_string_fn(a, b);
    const std::string expected_string = buildExpectedStringCaseResult(string_params);

    LOGI("[route_native_vs_vm][%s] native=%s expected=%s fun_addr=0x%llx",
         kStringCaseFunctionName,
         native_string.c_str(),
         expected_string.c_str(),
         static_cast<unsigned long long>(string_case_it->second.fun_addr));
    if (native_string != expected_string) {
        LOGE("[route_native_vs_vm][%s] mismatch native=%s expected=%s",
             kStringCaseFunctionName,
             native_string.c_str(),
             expected_string.c_str());
        return false;
    }
    return true;
}

// 路线1：加载未编码文本（fun_xxx.txt）并执行。
// 该路线产出 reference_cases，作为其它路线的对齐基准。
bool test_loadUnencodedText(JNIEnv* env, zVmEngine& engine, std::vector<FunctionCaseResult>& out_cases) {
    // 每轮先清空输出基准列表。
    out_cases.clear();
    // 路线1：文本反汇编结果直接进 VM，作为后续两条编码路线的基准。
    if (!prepareRouteLibrary(env, engine, kAssetBaseSo, g_libdemo_so_path)) {
        LOGE("[route_unencoded_text] prepareRouteLibrary failed");
        return false;
    }

    // 读取共享 branch 地址表。
    std::vector<uint64_t> shared_branch_addrs;
    if (!loadSharedBranchAddrsFromAsset(env, kAssetBranchAddrList, shared_branch_addrs)) {
        LOGE("[route_unencoded_text] loadSharedBranchAddrsFromAsset failed: %s", kAssetBranchAddrList);
        return false;
    }
    // 基准路线按 libdemo.so 维度注册共享 branch 地址。
    engine.setSharedBranchAddrs(kAssetBaseSo, std::move(shared_branch_addrs));

    // 遍历所有 uint64 返回值用例。
    for (const FunctionCaseConfig& config : kFunctionCases) {
        // 承接文本资产数据。
        std::vector<uint8_t> text_data;
        // 读取单函数文本文件。
        if (!zAssetManager::loadAssetDataByFileName(env, config.txt_asset, text_data)) {
            LOGE("[route_unencoded_text] loadAssetDataByFileName failed: %s", config.txt_asset);
            return false;
        }

        // 创建函数对象。
        std::unique_ptr<zFunction> function = std::make_unique<zFunction>();
        // 按文本格式解析函数。
        if (!function->loadUnencodedText(reinterpret_cast<const char*>(text_data.data()), text_data.size())) {
            LOGE("[route_unencoded_text] loadUnencodedText failed: %s", config.txt_asset);
            return false;
        }

        // 解析得到函数地址。
        const uint64_t fun_addr = function->functionAddress();
        // 地址无效则失败。
        if (fun_addr == 0) {
            LOGE("[route_unencoded_text] invalid fun_addr=0 for %s", config.function_name);
            return false;
        }

        // 缓存到 VM，供 execute 按地址调度。
        if (!engine.cacheFunction(std::move(function))) {
            LOGE("[route_unencoded_text] cacheFunction failed: %s fun_addr=0x%llx",
                 config.function_name,
                 static_cast<unsigned long long>(fun_addr));
            return false;
        }

        // 初始化基准结果项。
        FunctionCaseResult result_case;
        // 填入函数名。
        result_case.function_name = config.function_name;
        // 填入函数地址。
        result_case.fun_addr = fun_addr;
        // 记录基准输出，后两条路线按同 fun_addr + 同入参做逐项对比。
        if (!executeCase(
                engine,
                kAssetBaseSo,
                "route_unencoded_text",
                config.function_name,
                fun_addr,
                &result_case.expected_result)) {
            return false;
        }

        // 保留关键入口固定预期值校验，避免“跨路线一致但全错”的情况。
        // 当前用 fun_for_add 作为固定值守门用例。
        if (result_case.function_name == "fun_for_add" && result_case.expected_result != kExpectedResult) {
            LOGE("[route_unencoded_text][%s] unexpected result=%llu expected=%llu",
                 config.function_name,
                 static_cast<unsigned long long>(result_case.expected_result),
                 static_cast<unsigned long long>(kExpectedResult));
            return false;
        }
        // 保存基准结果，供后续两条路线比对。
        out_cases.push_back(result_case);
    }

    // 下面单独处理 string 返回值用例（不走 uint64 比对）。
    std::vector<uint8_t> string_case_txt_data;
    // 读取字符串文本资产。
    if (!zAssetManager::loadAssetDataByFileName(env, kStringCaseTxtAsset, string_case_txt_data)) {
        LOGE("[route_unencoded_text] loadAssetDataByFileName failed: %s", kStringCaseTxtAsset);
        return false;
    }
    // 创建字符串函数对象。
    std::unique_ptr<zFunction> string_case_function = std::make_unique<zFunction>();
    // 解析字符串函数文本。
    if (!string_case_function->loadUnencodedText(reinterpret_cast<const char*>(string_case_txt_data.data()),
                                                 string_case_txt_data.size())) {
        LOGE("[route_unencoded_text] loadUnencodedText failed: %s", kStringCaseTxtAsset);
        return false;
    }
    // 读取字符串函数地址。
    const uint64_t string_case_fun_addr = string_case_function->functionAddress();
    // 地址非法则失败。
    if (string_case_fun_addr == 0) {
        LOGE("[route_unencoded_text] invalid fun_addr=0 for %s", kStringCaseFunctionName);
        return false;
    }
    // 缓存字符串函数到 VM。
    if (!engine.cacheFunction(std::move(string_case_function))) {
        LOGE("[route_unencoded_text] cacheFunction failed: %s fun_addr=0x%llx",
             kStringCaseFunctionName,
             static_cast<unsigned long long>(string_case_fun_addr));
        return false;
    }
    // 执行并校验字符串内容。
    if (!executeStringCase(
            engine,
            kAssetBaseSo,
            "route_unencoded_text",
            kStringCaseFunctionName,
            string_case_fun_addr)) {
        return false;
    }
    // string 用例不做 uint64 比对，仅保留地址用于后续两条路线复测。
    out_cases.push_back(FunctionCaseResult{std::string(kStringCaseFunctionName), string_case_fun_addr, 0});
    // 路线1成功。
    return true;
}

// 路线2：加载 assets 中的编码 bin（fun_xxx.bin）并执行。
// 以路线1的 `fun_addr + expected_result` 做逐项对齐校验。
bool test_loadEncodedAssetBin(JNIEnv* env, zVmEngine& engine, const std::vector<FunctionCaseResult>& reference_cases) {
    // 必须先有基准结果，编码路线才能做对齐比对。
    if (reference_cases.empty()) {
        LOGE("[route_encoded_asset_bin] reference_cases is empty");
        return false;
    }

    // 按函数名回填基准数据，确保每个编码用例都能对齐到同一 fun_addr。
    std::unordered_map<std::string, FunctionCaseResult> case_map;
    // 构建 name -> baseline 的快速索引。
    for (const FunctionCaseResult& item : reference_cases) {
        case_map[item.function_name] = item;
    }

    // 准备 base so。
    if (!prepareRouteLibrary(env, engine, kAssetBaseSo, g_libdemo_so_path)) {
        LOGE("[route_encoded_asset_bin] prepareRouteLibrary failed");
        return false;
    }

    // 读取共享 branch 表。
    std::vector<uint64_t> shared_branch_addrs;
    if (!loadSharedBranchAddrsFromAsset(env, kAssetBranchAddrList, shared_branch_addrs)) {
        LOGE("[route_encoded_asset_bin] loadSharedBranchAddrsFromAsset failed: %s", kAssetBranchAddrList);
        return false;
    }
    // 编码 bin 仍复用 libdemo.so 的共享 branch 表。
    engine.setSharedBranchAddrs(kAssetBaseSo, std::move(shared_branch_addrs));

    // 遍历所有 uint64 返回值用例，读取 bin 并执行回归。
    for (const FunctionCaseConfig& config : kFunctionCases) {
        // 查找对应基准项。
        auto it = case_map.find(config.function_name);
        // 缺失基准直接失败，避免“盲跑”。
        if (it == case_map.end()) {
            LOGE("[route_encoded_asset_bin] missing reference case: %s", config.function_name);
            return false;
        }

        // 承接编码数据。
        std::vector<uint8_t> encoded_data;
        // 读取单函数 bin。
        if (!zAssetManager::loadAssetDataByFileName(env, config.bin_asset, encoded_data)) {
            LOGE("[route_encoded_asset_bin] loadAssetDataByFileName failed: %s", config.bin_asset);
            return false;
        }

        // 创建函数对象。
        std::unique_ptr<zFunction> function = std::make_unique<zFunction>();
        // 加载编码格式。
        if (!function->loadEncodedData(encoded_data.data(), encoded_data.size())) {
            LOGE("[route_encoded_asset_bin] loadEncodedData failed: %s", config.bin_asset);
            return false;
        }

        // 统一按未编码路线 fun_addr 做回归。
        function->setFunctionAddress(it->second.fun_addr);
        // 缓存到 VM。
        if (!engine.cacheFunction(std::move(function))) {
            LOGE("[route_encoded_asset_bin] cacheFunction failed: %s fun_addr=0x%llx",
                 config.function_name,
                 static_cast<unsigned long long>(it->second.fun_addr));
            return false;
        }

        // 执行并获取结果。
        uint64_t result = 0;
        if (!executeCase(
                engine,
                kAssetBaseSo,
                "route_encoded_asset_bin",
                config.function_name,
                it->second.fun_addr,
                &result)) {
            return false;
        }
        // 与基准结果逐项比对。
        if (result != it->second.expected_result) {
            LOGE("[route_encoded_asset_bin][%s] unexpected result=%llu expected=%llu",
                 config.function_name,
                 static_cast<unsigned long long>(result),
                 static_cast<unsigned long long>(it->second.expected_result));
            return false;
        }
    }

    // 单独回归 string 返回值用例。
    auto string_case_it = case_map.find(kStringCaseFunctionName);
    // 缺基准则失败。
    if (string_case_it == case_map.end()) {
        LOGE("[route_encoded_asset_bin] missing reference case: %s", kStringCaseFunctionName);
        return false;
    }
    // 承接字符串函数编码数据。
    std::vector<uint8_t> string_case_bin_data;
    // 读取字符串函数 bin。
    if (!zAssetManager::loadAssetDataByFileName(env, kStringCaseBinAsset, string_case_bin_data)) {
        LOGE("[route_encoded_asset_bin] loadAssetDataByFileName failed: %s", kStringCaseBinAsset);
        return false;
    }
    // 创建字符串函数对象。
    std::unique_ptr<zFunction> string_case_function = std::make_unique<zFunction>();
    // 解析字符串函数编码数据。
    if (!string_case_function->loadEncodedData(string_case_bin_data.data(), string_case_bin_data.size())) {
        LOGE("[route_encoded_asset_bin] loadEncodedData failed: %s", kStringCaseBinAsset);
        return false;
    }
    // 绑定基准地址，确保三路线地址一致。
    string_case_function->setFunctionAddress(string_case_it->second.fun_addr);
    // 写入 VM 缓存。
    if (!engine.cacheFunction(std::move(string_case_function))) {
        LOGE("[route_encoded_asset_bin] cacheFunction failed: %s fun_addr=0x%llx",
             kStringCaseFunctionName,
             static_cast<unsigned long long>(string_case_it->second.fun_addr));
        return false;
    }
    // 执行字符串比对。
    if (!executeStringCase(
            engine,
            kAssetBaseSo,
            "route_encoded_asset_bin",
            kStringCaseFunctionName,
            string_case_it->second.fun_addr)) {
        return false;
    }
    // 路线2成功。
    return true;
}

bool runExpandedSoRoute(
    zVmEngine& engine,
    const char* so_name,
    const char* route_tag,
    const std::string& expand_so_path,
    const std::vector<FunctionCaseResult>& reference_cases
) {
    // 承接容器解出的函数条目。
    std::vector<zSoBinEntry> entries;
    // 承接容器中的共享 branch 列表。
    std::vector<uint64_t> shared_branch_addrs;
    if (!zSoBinBundleReader::readFromExpandedSo(expand_so_path, entries, shared_branch_addrs)) {
        LOGE("[%s] readFromExpandedSo failed: %s", route_tag, expand_so_path.c_str());
        return false;
    }
    if (entries.empty()) {
        LOGE("[%s] readFromExpandedSo returned empty payload list", route_tag);
        return false;
    }
    // 该路线使用当前 so_name 维度保存共享 branch 表。
    engine.setSharedBranchAddrs(so_name, std::move(shared_branch_addrs));

    // 记录已成功加载的 fun_addr，便于后续完整性校验。
    std::unordered_map<uint64_t, std::string> loaded_fun_map;
    for (const zSoBinEntry& entry : entries) {
        std::unique_ptr<zFunction> function = std::make_unique<zFunction>();
        if (!function->loadEncodedData(entry.encoded_data.data(), entry.encoded_data.size())) {
            LOGE("[%s] loadEncodedData failed: fun_addr=0x%llx",
                 route_tag,
                 static_cast<unsigned long long>(entry.fun_addr));
            return false;
        }
        function->setFunctionAddress(entry.fun_addr);
        if (!engine.cacheFunction(std::move(function))) {
            LOGE("[%s] cacheFunction failed: fun_addr=0x%llx",
                 route_tag,
                 static_cast<unsigned long long>(entry.fun_addr));
            return false;
        }
        loaded_fun_map[entry.fun_addr] = "loaded";
    }

    for (const FunctionCaseResult& item : reference_cases) {
        if (item.function_name == kStringCaseFunctionName) {
            continue;
        }
        if (loaded_fun_map.find(item.fun_addr) == loaded_fun_map.end()) {
            LOGE("[%s] missing function in expanded so: %s fun_addr=0x%llx",
                 route_tag,
                 item.function_name.c_str(),
                 static_cast<unsigned long long>(item.fun_addr));
            return false;
        }

        uint64_t result = 0;
        if (!executeCase(
                engine,
                so_name,
                route_tag,
                item.function_name.c_str(),
                item.fun_addr,
                &result)) {
            return false;
        }
        if (result != item.expected_result) {
            LOGE("[%s][%s] unexpected result=%llu expected=%llu",
                 route_tag,
                 item.function_name.c_str(),
                 static_cast<unsigned long long>(result),
                 static_cast<unsigned long long>(item.expected_result));
            return false;
        }
    }

    uint64_t string_case_fun_addr = 0;
    for (const FunctionCaseResult& item : reference_cases) {
        if (item.function_name == kStringCaseFunctionName) {
            string_case_fun_addr = item.fun_addr;
            break;
        }
    }
    if (string_case_fun_addr == 0) {
        LOGE("[%s] missing reference case: %s", route_tag, kStringCaseFunctionName);
        return false;
    }
    if (loaded_fun_map.find(string_case_fun_addr) == loaded_fun_map.end()) {
        LOGE("[%s] missing function in expanded so: %s fun_addr=0x%llx",
             route_tag,
             kStringCaseFunctionName,
             static_cast<unsigned long long>(string_case_fun_addr));
        return false;
    }
    if (!executeStringCase(
            engine,
            so_name,
            route_tag,
            kStringCaseFunctionName,
            string_case_fun_addr)) {
        return false;
    }
    return true;
}

// 路线3：从 `libdemo_expand.so` 尾部容器读取编码数据并执行。
// 同样以路线1基准做逐项对齐，覆盖“容器读取 + 执行”整条链路。
bool test_loadEncodedExpandedSo(JNIEnv* env, zVmEngine& engine, const std::vector<FunctionCaseResult>& reference_cases) {
    if (reference_cases.empty()) {
        LOGE("[route_encoded_expand_so] reference_cases is empty");
        return false;
    }
    if (!prepareRouteLibrary(env, engine, kAssetExpandSo, g_libdemo_expand_so_path)) {
        LOGE("[route_encoded_expand_so] prepareRouteLibrary failed");
        return false;
    }
    return runExpandedSoRoute(
        engine,
        kAssetExpandSo,
        "route_encoded_expand_so",
        g_libdemo_expand_so_path,
        reference_cases
    );
}

// 路线4（L1）：从当前 `libvmengine.so` 末尾读取内嵌的 `libdemo_expand.so`，落盘后执行。
EmbeddedExpandRouteStatus test_loadEmbeddedExpandedSo(
    JNIEnv* env,
    zVmEngine& engine,
    const std::vector<FunctionCaseResult>& reference_cases
) {
    if (reference_cases.empty()) {
        LOGE("[route_embedded_expand_so] reference_cases is empty");
        return EmbeddedExpandRouteStatus::kFail;
    }

    std::string vmengine_path;
    if (!resolveCurrentLibraryPath(reinterpret_cast<void*>(&test_loadEmbeddedExpandedSo), vmengine_path)) {
        LOGE("[route_embedded_expand_so] resolveCurrentLibraryPath failed");
        return EmbeddedExpandRouteStatus::kFail;
    }

    std::vector<uint8_t> embedded_payload;
    zEmbeddedPayloadReadStatus read_status = zEmbeddedPayloadReadStatus::kInvalid;
    if (!zEmbeddedPayload::readEmbeddedPayloadFromHostSo(vmengine_path, embedded_payload, &read_status)) {
        LOGE("[route_embedded_expand_so] readEmbeddedPayloadFromHostSo failed: %s", vmengine_path.c_str());
        return EmbeddedExpandRouteStatus::kFail;
    }
    if (read_status == zEmbeddedPayloadReadStatus::kNotFound) {
        LOGI("[route_embedded_expand_so] skip: embedded payload not found in %s", vmengine_path.c_str());
        return EmbeddedExpandRouteStatus::kSkipNoPayload;
    }
    if (embedded_payload.empty()) {
        LOGE("[route_embedded_expand_so] embedded payload is empty");
        return EmbeddedExpandRouteStatus::kFail;
    }

    std::string files_dir;
    if (!zAssetManager::getCurrentFilesDirPath(env, files_dir)) {
        LOGE("[route_embedded_expand_so] getCurrentFilesDirPath failed");
        return EmbeddedExpandRouteStatus::kFail;
    }
    if (!files_dir.empty() && files_dir.back() != '/') {
        files_dir.push_back('/');
    }
    g_libdemo_expand_embedded_so_path = files_dir + kEmbeddedExpandSoName;

    if (!writeBytesToFile(g_libdemo_expand_embedded_so_path, embedded_payload)) {
        LOGE("[route_embedded_expand_so] write payload failed: %s", g_libdemo_expand_embedded_so_path.c_str());
        return EmbeddedExpandRouteStatus::kFail;
    }
    if (!engine.LoadLibrary(g_libdemo_expand_embedded_so_path.c_str())) {
        LOGE("[route_embedded_expand_so] custom linker load failed: %s", g_libdemo_expand_embedded_so_path.c_str());
        return EmbeddedExpandRouteStatus::kFail;
    }

    if (!runExpandedSoRoute(
            engine,
            kEmbeddedExpandSoName,
            "route_embedded_expand_so",
            g_libdemo_expand_embedded_so_path,
            reference_cases)) {
        return EmbeddedExpandRouteStatus::kFail;
    }
    return EmbeddedExpandRouteStatus::kPass;
}

bool initSymbolTakeover(
    const std::vector<FunctionCaseResult>& reference_cases,
    EmbeddedExpandRouteStatus embedded_status
) {
    if (reference_cases.empty()) {
        LOGE("[route_symbol_takeover] reference_cases is empty");
        return false;
    }

    std::unordered_map<std::string, uint64_t> fun_addr_map;
    for (const FunctionCaseResult& item : reference_cases) {
        fun_addr_map[item.function_name] = item.fun_addr;
    }

    const size_t takeover_symbol_count = zSymbolTakeoverSymbolCount();
    if (takeover_symbol_count == 0) {
        LOGE("[route_symbol_takeover] generated symbol list is empty");
        return false;
    }
    std::vector<zTakeoverSymbolEntry> entries;
    entries.reserve(takeover_symbol_count);
    for (size_t i = 0; i < takeover_symbol_count; ++i) {
        const char* symbol_name = zSymbolTakeoverSymbolNameAt(i);
        auto it = fun_addr_map.find(symbol_name == nullptr ? std::string() : std::string(symbol_name));
        if (it == fun_addr_map.end() || it->second == 0) {
            LOGE("[route_symbol_takeover] missing fun_addr for %s", symbol_name == nullptr ? "(null)" : symbol_name);
            return false;
        }
        entries.push_back(zTakeoverSymbolEntry{symbol_name, it->second});
    }

    zTakeoverConfig config{};
    if (embedded_status == EmbeddedExpandRouteStatus::kPass) {
        config.primary_so_name = kEmbeddedExpandSoName;
        config.fallback_so_name = kAssetExpandSo;
    } else {
        config.primary_so_name = kAssetExpandSo;
        config.fallback_so_name = kAssetBaseSo;
    }

    return zSymbolTakeoverInit(config, entries.data(), entries.size());
}

bool reloadTakeoverSoForCleanState(zVmEngine& engine, EmbeddedExpandRouteStatus embedded_status) {
    // 为 symbol takeover 准备“全新映像”，避免前序路线调用污染全局/静态状态。
    if (embedded_status == EmbeddedExpandRouteStatus::kPass) {
        if (g_libdemo_expand_embedded_so_path.empty()) {
            LOGE("[route_symbol_takeover] reload failed: embedded so path is empty");
            return false;
        }
        if (!engine.LoadLibrary(g_libdemo_expand_embedded_so_path.c_str())) {
            LOGE("[route_symbol_takeover] reload failed: %s", g_libdemo_expand_embedded_so_path.c_str());
            return false;
        }
        LOGI("[route_symbol_takeover] reloaded takeover so for clean state: %s", g_libdemo_expand_embedded_so_path.c_str());
        return true;
    }

    if (!g_libdemo_expand_so_path.empty()) {
        if (!engine.LoadLibrary(g_libdemo_expand_so_path.c_str())) {
            LOGE("[route_symbol_takeover] reload failed: %s", g_libdemo_expand_so_path.c_str());
            return false;
        }
        LOGI("[route_symbol_takeover] reloaded takeover so for clean state: %s", g_libdemo_expand_so_path.c_str());
        return true;
    }

    if (!g_libdemo_so_path.empty()) {
        if (!engine.LoadLibrary(g_libdemo_so_path.c_str())) {
            LOGE("[route_symbol_takeover] reload failed: %s", g_libdemo_so_path.c_str());
            return false;
        }
        LOGI("[route_symbol_takeover] reloaded takeover so for clean state: %s", g_libdemo_so_path.c_str());
        return true;
    }

    LOGE("[route_symbol_takeover] reload failed: no available so path");
    return false;
}

bool test_symbolTakeover(const std::vector<FunctionCaseResult>& reference_cases) {
    if (reference_cases.empty()) {
        LOGE("[route_symbol_takeover] reference_cases is empty");
        return false;
    }
    if (!zSymbolTakeoverIsReady()) {
        LOGE("[route_symbol_takeover] takeover state is not ready");
        return false;
    }

    std::unordered_map<std::string, FunctionCaseResult> case_map;
    for (const FunctionCaseResult& item : reference_cases) {
        case_map[item.function_name] = item;
    }
    const char* active_so_name = zSymbolTakeoverActiveSoName();
    std::string current_so_path;
    void* self_handle = nullptr;
    if (resolveCurrentLibraryPath(reinterpret_cast<void*>(&test_symbolTakeover), current_so_path)) {
        self_handle = dlopen(current_so_path.c_str(), RTLD_NOW | RTLD_LOCAL);
    }

    const size_t takeover_symbol_count = zSymbolTakeoverSymbolCount();
    if (takeover_symbol_count == 0) {
        LOGE("[route_symbol_takeover] generated symbol list is empty");
        if (self_handle != nullptr) {
            dlclose(self_handle);
        }
        return false;
    }
    using SymbolBinaryFn = int (*)(int, int);
    size_t validated_count = 0;
    for (size_t i = 0; i < takeover_symbol_count; ++i) {
        const char* symbol_name = zSymbolTakeoverSymbolNameAt(i);
        const std::string symbol_name_value = symbol_name == nullptr ? std::string() : std::string(symbol_name);
        auto it = case_map.find(symbol_name_value);
        if (it == case_map.end()) {
            LOGE("[route_symbol_takeover] missing reference case: %s", symbol_name == nullptr ? "(null)" : symbol_name);
            if (self_handle != nullptr) {
                dlclose(self_handle);
            }
            return false;
        }

        void* sym = nullptr;
        if (self_handle != nullptr) {
            sym = dlsym(self_handle, symbol_name);
        }
        if (sym == nullptr) {
            sym = dlsym(RTLD_DEFAULT, symbol_name);
        }
        if (sym == nullptr) {
            LOGE("[route_symbol_takeover] dlsym failed: %s", symbol_name);
            if (self_handle != nullptr) {
                dlclose(self_handle);
            }
            return false;
        }

        SymbolBinaryFn symbol_fn = reinterpret_cast<SymbolBinaryFn>(sym);
        const int result = symbol_fn(2, 4);
        const int expected = static_cast<int>(it->second.expected_result);
        LOGI("[route_symbol_takeover][%s] symbol=%p result=%d expected=%d expected_source=route1_baseline active_so=%s",
             symbol_name,
             sym,
             result,
             expected,
             active_so_name == nullptr ? "(null)" : active_so_name);
        if (result != expected) {
            LOGE("[route_symbol_takeover][%s] mismatch result=%d expected=%d",
                 symbol_name,
                 result,
                 expected);
            if (self_handle != nullptr) {
                dlclose(self_handle);
            }
            return false;
        }
        ++validated_count;
    }
    LOGI("[route_symbol_takeover] parity summary: validated=%llu total=%llu",
         static_cast<unsigned long long>(validated_count),
         static_cast<unsigned long long>(takeover_symbol_count));
    if (validated_count != takeover_symbol_count) {
        LOGE("[route_symbol_takeover] validated count mismatch: validated=%llu total=%llu",
             static_cast<unsigned long long>(validated_count),
             static_cast<unsigned long long>(takeover_symbol_count));
        if (self_handle != nullptr) {
            dlclose(self_handle);
        }
        return false;
    }
    if (self_handle != nullptr) {
        dlclose(self_handle);
    }
    return true;
}

// JNI 入口：
// 在库加载阶段一次性完成三条路线回归，任一路线失败即拒绝加载（返回 JNI_ERR）。
extern "C" JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    // 本文件不使用 reserved。
    (void)reserved;

    // 1) 校验并获取 JNIEnv。JNI_OnLoad 失败必须返回 JNI_ERR。
    // 声明 env 指针。
    JNIEnv* env = nullptr;
    // vm 为空、GetEnv 失败或 env 为空都视为初始化失败。
    if (vm == nullptr || vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK || env == nullptr) {
        return JNI_ERR;
    }

    // 获取 VM 单例。
    zVmEngine& engine = zVmEngine::getInstance();
    // 每次进程加载都从干净状态开始，避免上次缓存污染回归结果。
    // 清空函数缓存。
    engine.clearCache();
    // 清空 base so 的共享 branch 缓存。
    engine.clearSharedBranchAddrs(kAssetBaseSo);
    // 清空 expand so 的共享 branch 缓存。
    engine.clearSharedBranchAddrs(kAssetExpandSo);
    // 清空 route4 内嵌 expand so 的共享 branch 缓存。
    engine.clearSharedBranchAddrs(kEmbeddedExpandSoName);
    // 清空符号接管状态，防止进程内重复加载残留旧映射。
    zSymbolTakeoverClear();

    // 承接路线1产生的基准数据。
    std::vector<FunctionCaseResult> reference_cases;

    // 路线1：未编码文本（assets txt + 共享 branch_addr_list.txt）。
    // 执行基准路线。
    const bool ok_unencoded = test_loadUnencodedText(env, engine, reference_cases);
    // 打印路线1结果。
    LOGI("route_unencoded_text result=%d", ok_unencoded ? 1 : 0);

    // 路线1.5：直接调用原生 so 函数，与 VM 基准结果做差分比对。
    const bool ok_native_vs_vm = test_nativeVsVm(env, engine, reference_cases);
    LOGI("route_native_vs_vm result=%d", ok_native_vs_vm ? 1 : 0);

    // 路线2：编码 bin（assets bin + 共享 branch_addr_list.txt）。
    // 执行编码 bin 路线。
    const bool ok_encoded_asset = test_loadEncodedAssetBin(env, engine, reference_cases);
    // 打印路线2结果。
    LOGI("route_encoded_asset_bin result=%d", ok_encoded_asset ? 1 : 0);

    // 路线3：编码 bin（libdemo_expand.so 尾部容器 + 共享 branch_addr_list）。
    // 执行 expand so 容器路线。
    const bool ok_encoded_expand = test_loadEncodedExpandedSo(env, engine, reference_cases);
    // 打印路线3结果。
    LOGI("route_encoded_expand_so result=%d", ok_encoded_expand ? 1 : 0);

    // 路线4（L1）：libvmengine.so 尾部内嵌 expand so（未嵌入可跳过）。
    const EmbeddedExpandRouteStatus embedded_status = test_loadEmbeddedExpandedSo(env, engine, reference_cases);
    const bool ok_embedded_expand = (embedded_status != EmbeddedExpandRouteStatus::kFail);
    LOGI("route_embedded_expand_so result=%d state=%d",
         ok_embedded_expand ? 1 : 0,
         static_cast<int>(embedded_status));

    // 为接管回归准备干净 so 状态，避免 route1/2/3/4 的前序执行污染全局数据。
    const bool ok_takeover_reload = reloadTakeoverSoForCleanState(engine, embedded_status);

    // 路线4（L2 MVP）：在 libvmengine.so 导出 fun_add/fun_for/fun_if_sub 并转发到 VM。
    const bool ok_takeover_init = ok_takeover_reload && initSymbolTakeover(reference_cases, embedded_status);
    const bool ok_symbol_takeover = ok_takeover_init && test_symbolTakeover(reference_cases);
    LOGI("route_symbol_takeover result=%d", ok_symbol_takeover ? 1 : 0);

    // 任一路线失败，JNI_OnLoad 必须返回 JNI_ERR。
    if (!(ok_unencoded && ok_native_vs_vm && ok_encoded_asset && ok_encoded_expand && ok_embedded_expand && ok_symbol_takeover)) {
        LOGE("JNI_OnLoad route regression failed: unencoded=%d native_vs_vm=%d asset_bin=%d expand_so=%d embedded_expand=%d embedded_state=%d takeover_reload=%d symbol_takeover=%d takeover_init=%d",
             ok_unencoded ? 1 : 0,
             ok_native_vs_vm ? 1 : 0,
             ok_encoded_asset ? 1 : 0,
             ok_encoded_expand ? 1 : 0,
             ok_embedded_expand ? 1 : 0,
             static_cast<int>(embedded_status),
             ok_takeover_reload ? 1 : 0,
             ok_symbol_takeover ? 1 : 0,
             ok_takeover_init ? 1 : 0);
        return JNI_ERR;
    }

    // 三条路线都通过，返回 JNI 版本号，表示 native 初始化成功。
    return JNI_VERSION_1_6;
}
