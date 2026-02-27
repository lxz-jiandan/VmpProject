// demo JNI 桥接：链接期直接依赖 libdemo.so，调用 fun_* 并把结果返回给 Java 层展示。

#include <jni.h>
#include <android/log.h>

#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#include "demo.h"

namespace {

constexpr const char* kLogTag = "VMP_DEMO";

using BinaryFn = int (*)(int, int);

struct IntCase {
    const char* name;
    BinaryFn fn;
    int a;
    int b;
    int expected;
};

bool appendIntCaseResult(std::ostringstream& oss, const IntCase& c) {
    const int value = c.fn(c.a, c.b);
    const bool pass = (value == c.expected);
    oss << std::left << std::setw(26) << c.name
        << std::right << std::setw(10) << c.expected
        << std::setw(10) << value
        << std::setw(10) << (pass ? "PASS" : "FAIL") << "\n";
    __android_log_print(
        ANDROID_LOG_INFO,
        kLogTag,
        "%s(%d,%d) expected=%d actual=%d status=%s",
        c.name,
        c.a,
        c.b,
        c.expected,
        value,
        pass ? "PASS" : "FAIL");
    return pass;
}

std::string buildProtectResultText() {
    std::ostringstream oss;
    oss << "demo protect results\n";
    oss << std::left << std::setw(26) << "function"
        << std::right << std::setw(10) << "expected"
        << std::setw(10) << "actual"
        << std::setw(10) << "status" << "\n";
    oss << "--------------------------------------------------------\n";

    const std::vector<IntCase> cases = {
        {"fun_add", fun_add, 2, 4, 6},
        {"fun_for", fun_for, 2, 4, 30},
        {"fun_for_add", fun_for_add, 2, 4, 30},
        {"fun_if_sub", fun_if_sub, 2, 4, 2},
        {"fun_countdown_muladd", fun_countdown_muladd, 2, 4, 10},
        {"fun_loop_call_mix", fun_loop_call_mix, 2, 4, 18},
        {"fun_call_chain", fun_call_chain, 2, 4, 38},
        {"fun_branch_call", fun_branch_call, 2, 4, 24},
        {"fun_cpp_string_len", fun_cpp_string_len, 2, 4, 4},
        {"fun_cpp_vector_sum", fun_cpp_vector_sum, 2, 4, 12},
        {"fun_cpp_virtual_mix", fun_cpp_virtual_mix, 2, 4, 6},
        {"fun_global_data_mix", fun_global_data_mix, 2, 4, 31},
        {"fun_static_local_table", fun_static_local_table, 2, 4, 20},
        {"fun_global_struct_acc", fun_global_struct_acc, 2, 4, 16},
        {"fun_class_static_member", fun_class_static_member, 2, 4, 20},
        {"fun_multi_branch_path", fun_multi_branch_path, 2, 4, 8},
        {"fun_switch_dispatch", fun_switch_dispatch, 2, 4, 10},
        {"fun_bitmask_branch", fun_bitmask_branch, 2, 4, -2},
        {"fun_global_table_rw", fun_global_table_rw, 2, 4, 74},
        {"fun_global_mutable_state", fun_global_mutable_state, 2, 4, 45},
    };

    int passCount = 0;
    for (const IntCase& c : cases) {
        if (appendIntCaseResult(oss, c)) {
            passCount += 1;
        }
    }
    oss << "--------------------------------------------------------\n";
    oss << "summary: " << passCount << "/" << cases.size() << " PASS\n";
    return oss.str();
}

} // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_demo_MainActivity_getProtectResults(JNIEnv* env, jobject /*thiz*/) {
    const std::string resultText = buildProtectResultText();
    return env->NewStringUTF(resultText.c_str());
}
