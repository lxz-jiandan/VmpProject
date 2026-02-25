/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - Demo 侧 JNI 桥接：调用受保护导出函数并与参考 so 对照。
 * - 加固链路位置：端到端验收层（设备侧冒烟）。
 * - 输入：libdemo.so（受保护实现）+ libdemo_ref.so（参考实现）。
 * - 输出：PASS/FAIL 文本 + 详细日志。
 */

// JNI 接口类型。
#include <jni.h>
// Android logcat 输出。
#include <android/log.h>
// dlopen/dlsym/dlclose。
#include <dlfcn.h>

// INT_MIN。
#include <climits>
// 组装错误文本。
#include <sstream>
// std::string。
#include <string>
// 用例列表容器。
#include <vector>

namespace {

// logcat 标签。
constexpr const char* kLogTag = "VMP_DEMO";
// 被测导出函数签名：int func(int, int)。
using BinaryFn = int (*)(int, int);
// 可选注入接口签名：把 reference so 句柄交给受保护库。
using SetReferenceSoHandleFn = void (*)(void*);
// “无固定期望值”哨兵。
constexpr int kNoExpectedOverride = INT_MIN;

// 单个测试样例。
struct SymbolCase {
    // 被测导出符号名。
    const char* symbolName;
    // 入参 a。
    int a;
    // 入参 b。
    int b;
    // 固定期望值（仅状态敏感用例使用）。
    int expectedOverride = kNoExpectedOverride;
};

// 把错误项拼接到统一错误流中。
void appendError(std::ostringstream& oss, const std::string& msg) {
    // 已有内容时先加分隔符。
    if (oss.tellp() > 0) {
        oss << " | ";
    }
    // 追加本条错误信息。
    oss << msg;
}

// 运行单个符号用例。
bool runSymbolCase(void* protectedSoHandle, void* referenceSoHandle, const SymbolCase& c, std::ostringstream& details) {
    // 1) 在受保护 so 中解析目标符号。
    // 先清空 dlerror 缓冲，避免读到旧错误。
    dlerror();
    // 查找符号地址。
    void* protectedSym = dlsym(protectedSoHandle, c.symbolName);
    // 读取本次 dlsym 错误信息。
    const char* protectedSymError = dlerror();
    // 地址为空或出现错误都视为失败。
    if (protectedSym == nullptr || protectedSymError != nullptr) {
        appendError(details, std::string("dlsym failed for ") + c.symbolName +
                                  " in protected so: " +
                                  (protectedSymError == nullptr ? "unknown" : protectedSymError));
        return false;
    }

    // 转成可调用函数指针。
    auto protectedFn = reinterpret_cast<BinaryFn>(protectedSym);
    // 期望值。
    int expected = 0;
    // 若配置了固定期望值，则直接使用。
    if (c.expectedOverride != kNoExpectedOverride) {
        // 状态敏感函数避免 reference so 内部状态漂移带来伪失败。
        expected = c.expectedOverride;
    } else {
        // 2) 从参考 so 中查同名符号并计算期望值。
        dlerror();
        void* referenceSym = dlsym(referenceSoHandle, c.symbolName);
        const char* referenceSymError = dlerror();
        if (referenceSym == nullptr || referenceSymError != nullptr) {
            appendError(details, std::string("dlsym failed for ") + c.symbolName +
                                      " in reference so: " +
                                      (referenceSymError == nullptr ? "unknown" : referenceSymError));
            return false;
        }
        auto referenceFn = reinterpret_cast<BinaryFn>(referenceSym);
        // 参考结果作为本用例期望值。
        expected = referenceFn(c.a, c.b);
    }

    // 3) 调用受保护实现并对比结果。
    const int actual = protectedFn(c.a, c.b);
    if (actual != expected) {
        // 失败时输出符号名、入参、期望值与实际值。
        std::ostringstream item;
        item << c.symbolName << "(" << c.a << "," << c.b << ") expected=" << expected << " actual=" << actual;
        appendError(details, item.str());
        return false;
    }

    // 单例成功日志。
    __android_log_print(ANDROID_LOG_INFO,
                        kLogTag,
                        "case pass: %s(%d,%d)=%d",
                        c.symbolName,
                        c.a,
                        c.b,
                        actual);
    return true;
}

// 执行整套冒烟验证并返回可展示文本。
std::string runVmpSmokeCheck() {
    // 先加载受保护库。
    // 当前 APK 中 libdemo.so 实际由 vmengine 产物重命名得到。
    void* protectedSoHandle = dlopen("libdemo.so", RTLD_NOW | RTLD_LOCAL);
    if (protectedSoHandle == nullptr) {
        const char* error = dlerror();
        std::ostringstream oss;
        oss << "FAIL: dlopen libdemo.so failed: " << (error == nullptr ? "unknown" : error);
        return oss.str();
    }

    // 再加载参考库（原始实现基线）。
    void* referenceSoHandle = dlopen("libdemo_ref.so", RTLD_NOW | RTLD_LOCAL);
    if (referenceSoHandle == nullptr) {
        const char* error = dlerror();
        std::ostringstream oss;
        oss << "FAIL: dlopen libdemo_ref.so failed: " << (error == nullptr ? "unknown" : error);
        // 失败路径及时关闭已打开句柄。
        dlclose(protectedSoHandle);
        return oss.str();
    }

    // 若受保护库提供 setter，则把 reference 句柄注入进去。
    // 这样 takeover fallback 可以回调到参考实现。
    dlerror();
    void* setterSym = dlsym(protectedSoHandle, "z_takeover_set_reference_so_handle");
    const char* setterError = dlerror();
    if (setterSym != nullptr && setterError == nullptr) {
        auto setReferenceSoHandle = reinterpret_cast<SetReferenceSoHandleFn>(setterSym);
        setReferenceSoHandle(referenceSoHandle);
    }

    // 测试集合：基础算术 -> 分支循环 -> C++对象 -> 全局状态。
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
        {"fun_static_local_table", 2, 4, 10},
        {"fun_global_struct_acc", 2, 4, 22},
        {"fun_class_static_member", 2, 4},
        {"fun_multi_branch_path", 2, 4},
        {"fun_switch_dispatch", 2, 4},
        {"fun_bitmask_branch", 2, 4},
        {"fun_global_table_rw", 2, 4},
        {"fun_global_mutable_state", 2, 4},
    };

    // 聚合失败详情。
    std::ostringstream details;
    // 全量通过标记。
    bool all_pass = true;
    // 逐用例执行，不提前中断，便于一次拿全失败点。
    for (const SymbolCase& c : cases) {
        if (!runSymbolCase(protectedSoHandle, referenceSoHandle, c, details)) {
            all_pass = false;
        }
    }

    // 释放句柄，避免资源泄漏。
    dlclose(referenceSoHandle);
    dlclose(protectedSoHandle);

    // 组织返回文本。
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
// JNI 导出名必须严格匹配 Java 包名/类名/方法名。
Java_com_example_demo_MainActivity_runVmpSmokeCheck(JNIEnv* env, jobject /*thiz*/) {
    // 执行冒烟检查。
    const std::string result = runVmpSmokeCheck();
    // 输出总结果到 logcat。
    __android_log_print(ANDROID_LOG_INFO, kLogTag, "VMP_DEMO_CHECK %s", result.c_str());
    // 把 PASS/FAIL 文本回传给 Java 层。
    return env->NewStringUTF(result.c_str());
}
