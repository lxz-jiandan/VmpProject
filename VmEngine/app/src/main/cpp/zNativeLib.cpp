#include <jni.h>

#include <cctype>
#include <cstdlib>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "zAssestManager.h"
#include "zFunction.h"
#include "zLog.h"
#include "zSoBinBundle.h"
#include "zVmEngine.h"

// 保存解包后的 so 绝对路径，供 zLinker 和 bundle 解析复用。
static std::string g_libdemo_so_path;
static std::string g_libdemo_expand_so_path;

constexpr const char* kAssetBaseSo = "libdemo.so";
constexpr const char* kAssetExpandSo = "libdemo_expand.so";
constexpr const char* kAssetBranchAddrList = "branch_addr_list.txt";
constexpr uint64_t kExpectedResult = 30;

namespace {

struct FunctionCaseConfig {
    const char* function_name;
    const char* txt_asset;
    const char* bin_asset;
};

struct FunctionCaseResult {
    std::string function_name;
    uint64_t fun_addr = 0;
    uint64_t expected_result = 0;
};

const FunctionCaseConfig kFunctionCases[] = {
    {"fun_for", "fun_for.txt", "fun_for.bin"},
    {"fun_add", "fun_add.txt", "fun_add.bin"},
    {"fun_for_add", "fun_for_add.txt", "fun_for_add.bin"},
    {"fun_if_sub", "fun_if_sub.txt", "fun_if_sub.bin"},
    {"fun_countdown_muladd", "fun_countdown_muladd.txt", "fun_countdown_muladd.bin"},
    {"fun_loop_call_mix", "fun_loop_call_mix.txt", "fun_loop_call_mix.bin"},
    {"fun_call_chain", "fun_call_chain.txt", "fun_call_chain.bin"},
    {"fun_branch_call", "fun_branch_call.txt", "fun_branch_call.bin"},
    {"fun_cpp_string_len", "fun_cpp_string_len.txt", "fun_cpp_string_len.bin"},
    {"fun_cpp_virtual_mix", "fun_cpp_virtual_mix.txt", "fun_cpp_virtual_mix.bin"},
};

std::string trimCopy(const std::string& value) {
    size_t begin = 0;
    while (begin < value.size() && std::isspace(static_cast<unsigned char>(value[begin])) != 0) {
        ++begin;
    }

    size_t end = value.size();
    while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1])) != 0) {
        --end;
    }
    return value.substr(begin, end - begin);
}

bool parseSharedBranchAddrListText(const std::vector<uint8_t>& text_data, std::vector<uint64_t>& out_branch_addrs) {
    out_branch_addrs.clear();
    if (text_data.empty()) {
        return false;
    }

    const std::string text(reinterpret_cast<const char*>(text_data.data()), text_data.size());

    bool has_expected_count = false;
    uint64_t expected_count = 0;
    size_t count_pos = text.find("branch_addr_count");
    if (count_pos != std::string::npos) {
        size_t eq = text.find('=', count_pos);
        size_t sc = text.find(';', eq);
        if (eq != std::string::npos && sc != std::string::npos && sc > eq) {
            std::string count_str = trimCopy(text.substr(eq + 1, sc - eq - 1));
            if (!count_str.empty()) {
                expected_count = std::strtoull(count_str.c_str(), nullptr, 0);
                has_expected_count = true;
            }
        }
    }

    size_t list_pos = text.find("branch_addr_list");
    if (list_pos == std::string::npos) {
        return false;
    }
    size_t l = text.find('{', list_pos);
    size_t r = text.find('}', l == std::string::npos ? list_pos : l + 1);
    if (l == std::string::npos || r == std::string::npos || r <= l) {
        return false;
    }

    std::string body = text.substr(l + 1, r - l - 1);
    std::stringstream ss(body);
    std::string token;
    while (std::getline(ss, token, ',')) {
        std::string trimmed = trimCopy(token);
        if (trimmed.empty()) {
            continue;
        }
        uint64_t addr = std::strtoull(trimmed.c_str(), nullptr, 0);
        out_branch_addrs.push_back(addr);
    }

    if (has_expected_count && expected_count != out_branch_addrs.size()) {
        LOGE("parseSharedBranchAddrListText count mismatch: expected=%llu actual=%llu",
             static_cast<unsigned long long>(expected_count),
             static_cast<unsigned long long>(out_branch_addrs.size()));
        return false;
    }
    return true;
}

bool loadSharedBranchAddrsFromAsset(JNIEnv* env, const char* asset_name, std::vector<uint64_t>& out_branch_addrs) {
    std::vector<uint8_t> text_data;
    if (!zAssetManager::loadAssetDataByFileName(env, asset_name, text_data)) {
        LOGE("loadSharedBranchAddrsFromAsset failed to read asset: %s", asset_name);
        return false;
    }
    if (!parseSharedBranchAddrListText(text_data, out_branch_addrs)) {
        LOGE("loadSharedBranchAddrsFromAsset failed to parse asset: %s", asset_name);
        return false;
    }
    return true;
}

zParams buildDefaultParams(const char* function_name) {
    (void)function_name;
    // 三条路线统一使用同一组参数，验证编码链路一致性。
    return zParams(std::vector<uint64_t>{2, 4});
}

} // namespace

bool prepareRouteLibrary(JNIEnv* env, zVmEngine& engine, const char* asset_so_name, std::string& out_path) {
    if (!zAssetManager::extractAssetToFile(env, asset_so_name, out_path)) {
        LOGE("extract asset failed: %s", asset_so_name);
        return false;
    }
    if (!engine.LoadLibrary(out_path.c_str())) {
        LOGE("custom linker load failed: %s", out_path.c_str());
        return false;
    }
    return true;
}

bool executeCase(
    zVmEngine& engine,
    const char* so_name,
    const char* route_tag,
    const char* function_name,
    uint64_t fun_addr,
    uint64_t* out_result
) {
    if (fun_addr == 0) {
        LOGE("[%s][%s] invalid fun_addr=0", route_tag, function_name);
        return false;
    }
    if (so_name == nullptr || so_name[0] == '\0') {
        LOGE("[%s][%s] invalid so_name", route_tag, function_name);
        return false;
    }

    zParams params = buildDefaultParams(function_name);
    uint64_t result = 0;
    result = engine.execute(&result, so_name, fun_addr, params);
    LOGI("[%s][%s] execute by fun_addr=0x%llx result=%llu",
         route_tag,
         function_name,
         static_cast<unsigned long long>(fun_addr),
         static_cast<unsigned long long>(result));
    if (out_result != nullptr) {
        *out_result = result;
    }
    return true;
}

bool test_loadUnencodedText(JNIEnv* env, zVmEngine& engine, std::vector<FunctionCaseResult>& out_cases) {
    out_cases.clear();
    if (!prepareRouteLibrary(env, engine, kAssetBaseSo, g_libdemo_so_path)) {
        LOGE("[route_unencoded_text] prepareRouteLibrary failed");
        return false;
    }

    std::vector<uint64_t> shared_branch_addrs;
    if (!loadSharedBranchAddrsFromAsset(env, kAssetBranchAddrList, shared_branch_addrs)) {
        LOGE("[route_unencoded_text] loadSharedBranchAddrsFromAsset failed: %s", kAssetBranchAddrList);
        return false;
    }
    engine.setSharedBranchAddrs(kAssetBaseSo, std::move(shared_branch_addrs));

    for (const FunctionCaseConfig& config : kFunctionCases) {
        std::vector<uint8_t> text_data;
        if (!zAssetManager::loadAssetDataByFileName(env, config.txt_asset, text_data)) {
            LOGE("[route_unencoded_text] loadAssetDataByFileName failed: %s", config.txt_asset);
            return false;
        }

        std::unique_ptr<zFunction> function = std::make_unique<zFunction>();
        if (!function->loadUnencodedText(reinterpret_cast<const char*>(text_data.data()), text_data.size())) {
            LOGE("[route_unencoded_text] loadUnencodedText failed: %s", config.txt_asset);
            return false;
        }

        const uint64_t fun_addr = function->functionAddress();
        if (fun_addr == 0) {
            LOGE("[route_unencoded_text] invalid fun_addr=0 for %s", config.function_name);
            return false;
        }

        if (!engine.cacheFunction(std::move(function))) {
            LOGE("[route_unencoded_text] cacheFunction failed: %s fun_addr=0x%llx",
                 config.function_name,
                 static_cast<unsigned long long>(fun_addr));
            return false;
        }

        FunctionCaseResult result_case;
        result_case.function_name = config.function_name;
        result_case.fun_addr = fun_addr;
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
        if (result_case.function_name == "fun_for_add" && result_case.expected_result != kExpectedResult) {
            LOGE("[route_unencoded_text][%s] unexpected result=%llu expected=%llu",
                 config.function_name,
                 static_cast<unsigned long long>(result_case.expected_result),
                 static_cast<unsigned long long>(kExpectedResult));
            return false;
        }
        out_cases.push_back(result_case);
    }
    return true;
}

bool test_loadEncodedAssetBin(JNIEnv* env, zVmEngine& engine, const std::vector<FunctionCaseResult>& reference_cases) {
    if (reference_cases.empty()) {
        LOGE("[route_encoded_asset_bin] reference_cases is empty");
        return false;
    }

    std::unordered_map<std::string, FunctionCaseResult> case_map;
    for (const FunctionCaseResult& item : reference_cases) {
        case_map[item.function_name] = item;
    }

    if (!prepareRouteLibrary(env, engine, kAssetBaseSo, g_libdemo_so_path)) {
        LOGE("[route_encoded_asset_bin] prepareRouteLibrary failed");
        return false;
    }

    std::vector<uint64_t> shared_branch_addrs;
    if (!loadSharedBranchAddrsFromAsset(env, kAssetBranchAddrList, shared_branch_addrs)) {
        LOGE("[route_encoded_asset_bin] loadSharedBranchAddrsFromAsset failed: %s", kAssetBranchAddrList);
        return false;
    }
    engine.setSharedBranchAddrs(kAssetBaseSo, std::move(shared_branch_addrs));

    for (const FunctionCaseConfig& config : kFunctionCases) {
        auto it = case_map.find(config.function_name);
        if (it == case_map.end()) {
            LOGE("[route_encoded_asset_bin] missing reference case: %s", config.function_name);
            return false;
        }

        std::vector<uint8_t> encoded_data;
        if (!zAssetManager::loadAssetDataByFileName(env, config.bin_asset, encoded_data)) {
            LOGE("[route_encoded_asset_bin] loadAssetDataByFileName failed: %s", config.bin_asset);
            return false;
        }

        std::unique_ptr<zFunction> function = std::make_unique<zFunction>();
        if (!function->loadEncodedData(encoded_data.data(), encoded_data.size())) {
            LOGE("[route_encoded_asset_bin] loadEncodedData failed: %s", config.bin_asset);
            return false;
        }

        // 统一按未编码路线 fun_addr 做回归。
        function->setFunctionAddress(it->second.fun_addr);
        if (!engine.cacheFunction(std::move(function))) {
            LOGE("[route_encoded_asset_bin] cacheFunction failed: %s fun_addr=0x%llx",
                 config.function_name,
                 static_cast<unsigned long long>(it->second.fun_addr));
            return false;
        }

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
        if (result != it->second.expected_result) {
            LOGE("[route_encoded_asset_bin][%s] unexpected result=%llu expected=%llu",
                 config.function_name,
                 static_cast<unsigned long long>(result),
                 static_cast<unsigned long long>(it->second.expected_result));
            return false;
        }
    }
    return true;
}

bool test_loadEncodedExpandedSo(JNIEnv* env, zVmEngine& engine, const std::vector<FunctionCaseResult>& reference_cases) {
    if (reference_cases.empty()) {
        LOGE("[route_encoded_expand_so] reference_cases is empty");
        return false;
    }

    if (!prepareRouteLibrary(env, engine, kAssetExpandSo, g_libdemo_expand_so_path)) {
        LOGE("[route_encoded_expand_so] prepareRouteLibrary failed");
        return false;
    }

    std::vector<zSoBinEntry> entries;
    std::vector<uint64_t> shared_branch_addrs;
    if (!zSoBinBundleReader::readFromExpandedSo(g_libdemo_expand_so_path, entries, shared_branch_addrs)) {
        LOGE("[route_encoded_expand_so] readFromExpandedSo failed: %s", g_libdemo_expand_so_path.c_str());
        return false;
    }
    if (entries.empty()) {
        LOGE("[route_encoded_expand_so] readFromExpandedSo returned empty payload list");
        return false;
    }
    engine.setSharedBranchAddrs(kAssetExpandSo, std::move(shared_branch_addrs));

    std::unordered_map<uint64_t, std::string> loaded_fun_map;
    for (const zSoBinEntry& entry : entries) {
        std::unique_ptr<zFunction> function = std::make_unique<zFunction>();
        if (!function->loadEncodedData(entry.encoded_data.data(), entry.encoded_data.size())) {
            LOGE("[route_encoded_expand_so] loadEncodedData failed: fun_addr=0x%llx",
                 static_cast<unsigned long long>(entry.fun_addr));
            return false;
        }

        function->setFunctionAddress(entry.fun_addr);
        if (!engine.cacheFunction(std::move(function))) {
            LOGE("[route_encoded_expand_so] cacheFunction failed: fun_addr=0x%llx",
                 static_cast<unsigned long long>(entry.fun_addr));
            return false;
        }
        loaded_fun_map[entry.fun_addr] = "loaded";
    }

    for (const FunctionCaseResult& item : reference_cases) {
        if (loaded_fun_map.find(item.fun_addr) == loaded_fun_map.end()) {
            LOGE("[route_encoded_expand_so] missing function in expanded so: %s fun_addr=0x%llx",
                 item.function_name.c_str(),
                 static_cast<unsigned long long>(item.fun_addr));
            return false;
        }

        uint64_t result = 0;
        if (!executeCase(
                engine,
                kAssetExpandSo,
                "route_encoded_expand_so",
                item.function_name.c_str(),
                item.fun_addr,
                &result)) {
            return false;
        }
        if (result != item.expected_result) {
            LOGE("[route_encoded_expand_so][%s] unexpected result=%llu expected=%llu",
                 item.function_name.c_str(),
                 static_cast<unsigned long long>(result),
                 static_cast<unsigned long long>(item.expected_result));
            return false;
        }
    }
    return true;
}

extern "C" JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    (void)reserved;

    // 1) 校验并获取 JNIEnv。JNI_OnLoad 失败必须返回 JNI_ERR。
    JNIEnv* env = nullptr;
    if (vm == nullptr || vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK || env == nullptr) {
        return JNI_ERR;
    }

    zVmEngine& engine = zVmEngine::getInstance();
    engine.clearCache();
    engine.clearSharedBranchAddrs(kAssetBaseSo);
    engine.clearSharedBranchAddrs(kAssetExpandSo);

    std::vector<FunctionCaseResult> reference_cases;

    // 路线1：未编码文本（assets txt + 共享 branch_addr_list.txt）。
    const bool ok_unencoded = test_loadUnencodedText(env, engine, reference_cases);
    LOGI("route_unencoded_text result=%d", ok_unencoded ? 1 : 0);

    // 路线2：编码 bin（assets bin + 共享 branch_addr_list.txt）。
    const bool ok_encoded_asset = test_loadEncodedAssetBin(env, engine, reference_cases);
    LOGI("route_encoded_asset_bin result=%d", ok_encoded_asset ? 1 : 0);

    // 路线3：编码 bin（libdemo_expand.so 尾部容器 + 共享 branch_addr_list）。
    const bool ok_encoded_expand = test_loadEncodedExpandedSo(env, engine, reference_cases);
    LOGI("route_encoded_expand_so result=%d", ok_encoded_expand ? 1 : 0);

    if (!(ok_unencoded && ok_encoded_asset && ok_encoded_expand)) {
        LOGE("JNI_OnLoad route regression failed: unencoded=%d asset_bin=%d expand_so=%d",
             ok_unencoded ? 1 : 0,
             ok_encoded_asset ? 1 : 0,
             ok_encoded_expand ? 1 : 0);
        return JNI_ERR;
    }

    return JNI_VERSION_1_6;
}
