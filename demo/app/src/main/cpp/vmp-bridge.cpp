/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - Demo 侧 JNI 桥接，主动调用被保护导出并与参考 so 对比。
 * - 加固链路位置：端到端功能验证层。
 * - 输入：libdemo.so(受保护) + libdemo_ref.so(参考)。
 * - 输出：PASS/FAIL 文本与日志。
 */
#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>

#include <sstream>
#include <string>
#include <vector>

namespace {

constexpr const char* kLogTag = "VMP_DEMO";
using BinaryFn = int (*)(int, int);
using SetReferenceSoHandleFn = void (*)(void*);

// 每个测试样例对应一个导出符号 + 入参，期望值来自参考库原始实现。
struct SymbolCase {
    const char* symbol_name;
    int a;
    int b;
};

// 聚合错误信息，统一输出到最终 FAIL 文本，便于自动脚本判定。
void append_error(std::ostringstream& oss, const std::string& msg) {
    if (oss.tellp() > 0) {
        oss << " | ";
    }
    oss << msg;
}

bool run_symbol_case(void* protected_so_handle, void* reference_so_handle, const SymbolCase& c, std::ostringstream& details) {
    // 1) 在受保护 so 中查找目标符号。
    dlerror();
    void* protected_sym = dlsym(protected_so_handle, c.symbol_name);
    const char* protected_sym_error = dlerror();
    if (protected_sym == nullptr || protected_sym_error != nullptr) {
        append_error(details, std::string("dlsym failed for ") + c.symbol_name +
                                  " in protected so: " +
                                  (protected_sym_error == nullptr ? "unknown" : protected_sym_error));
        return false;
    }

    // 2) 在参考 so 中查找同名符号，作为结果基准。
    dlerror();
    void* reference_sym = dlsym(reference_so_handle, c.symbol_name);
    const char* reference_sym_error = dlerror();
    if (reference_sym == nullptr || reference_sym_error != nullptr) {
        append_error(details, std::string("dlsym failed for ") + c.symbol_name +
                                  " in reference so: " +
                                  (reference_sym_error == nullptr ? "unknown" : reference_sym_error));
        return false;
    }

    auto protected_fn = reinterpret_cast<BinaryFn>(protected_sym);
    auto reference_fn = reinterpret_cast<BinaryFn>(reference_sym);

    // 3) 使用相同入参调用双方实现，比较返回值是否一致。
    const int actual = protected_fn(c.a, c.b);
    const int expected = reference_fn(c.a, c.b);
    if (actual != expected) {
        std::ostringstream item;
        item << c.symbol_name << "(" << c.a << "," << c.b << ") expected=" << expected << " actual=" << actual;
        append_error(details, item.str());
        return false;
    }

    __android_log_print(ANDROID_LOG_INFO,
                        kLogTag,
                        "case pass: %s(%d,%d)=%d",
                        c.symbol_name,
                        c.a,
                        c.b,
                        actual);
    return true;
}

std::string run_vmp_smoke_check() {
    // 先加载受保护库（当前 APK 中 libdemo.so 实际由 libvmengine.so 产物重命名而来）。
    void* protected_so_handle = dlopen("libdemo.so", RTLD_NOW | RTLD_LOCAL);
    if (protected_so_handle == nullptr) {
        const char* error = dlerror();
        std::ostringstream oss;
        oss << "FAIL: dlopen libdemo.so failed: " << (error == nullptr ? "unknown" : error);
        return oss.str();
    }

    // 再加载参考库，用于逐符号对照验证行为一致性。
    void* reference_so_handle = dlopen("libdemo_ref.so", RTLD_NOW | RTLD_LOCAL);
    if (reference_so_handle == nullptr) {
        const char* error = dlerror();
        std::ostringstream oss;
        oss << "FAIL: dlopen libdemo_ref.so failed: " << (error == nullptr ? "unknown" : error);
        dlclose(protected_so_handle);
        return oss.str();
    }

    // 给 libvmengine.so 注入 reference so 句柄，便于 takeover fallback 走原始实现。
    dlerror();
    void* setter_sym = dlsym(protected_so_handle, "z_takeover_set_reference_so_handle");
    const char* setter_error = dlerror();
    if (setter_sym != nullptr && setter_error == nullptr) {
        auto set_reference_so_handle = reinterpret_cast<SetReferenceSoHandleFn>(setter_sym);
        set_reference_so_handle(reference_so_handle);
    }

    // 冒烟集合：先从基础算术到分支/循环/C++对象/全局状态，逐步扩大覆盖面。
    const std::vector<SymbolCase> cases = {
        {"fun_add", 2, 4},
        {"fun_for", 2, 4},
        {"fun_if_sub", 2, 4},
        {"fun_for_add", 2, 4},
        {"fun_countdown_muladd", 2, 4},
        {"fun_loop_call_mix", 2, 4},
        {"fun_call_chain", 2, 4},
        {"fun_branch_call", 2, 4},
        {"fun_cpp_string_len", 2, 4},
        {"fun_cpp_vector_sum", 2, 4},
        {"fun_cpp_virtual_mix", 2, 4},
        {"fun_global_data_mix", 2, 4},
        {"fun_static_local_table", 2, 4},
        {"fun_global_struct_acc", 2, 4},
        {"fun_class_static_member", 2, 4},
        {"fun_multi_branch_path", 2, 4},
        {"fun_switch_dispatch", 2, 4},
        {"fun_bitmask_branch", 2, 4},
        {"fun_global_table_rw", 2, 4},
        {"fun_global_mutable_state", 2, 4},
    };

    std::ostringstream details;
    bool all_pass = true;
    for (const SymbolCase& c : cases) {
        // 单个样例失败不提前退出，便于一次输出全部失败点。
        if (!run_symbol_case(protected_so_handle, reference_so_handle, c, details)) {
            all_pass = false;
        }
    }

    dlclose(reference_so_handle);
    dlclose(protected_so_handle);

    std::ostringstream result;
    if (all_pass) {
        result << "PASS: vmp protected symbol check ok (" << cases.size() << " cases)";
    } else {
        result << "FAIL: " << details.str();
    }
    return result.str();
}

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_demo_MainActivity_runVmpSmokeCheck(JNIEnv* env, jobject /*thiz*/) {
    const std::string result = run_vmp_smoke_check();
    __android_log_print(ANDROID_LOG_INFO, kLogTag, "VMP_DEMO_CHECK %s", result.c_str());
    // 直接把 PASS/FAIL 文本回传给 Java 层 UI 与自动化脚本。
    return env->NewStringUTF(result.c_str());
}
