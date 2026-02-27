// demo JNI 桥接：链接期直接依赖 libdemo.so，调用 fun_* 并把结果返回给 Java 层展示。

#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>

#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#include "demo.h"

namespace {

constexpr const char* kLogTag = "VMP_DEMO";

using BinaryFn = int (*)(int, int);
using I64Fn = long long (*)(int, int);
using U64Fn = unsigned long long (*)(int, int);
using BoolFn = bool (*)(int, int);
using I16Fn = short (*)(int, int);
using U16Fn = unsigned short (*)(int, int);
using I8Fn = signed char (*)(int, int);
using CstrFn = const char* (*)(int, int);
using StringFn = std::string (*)(int, int);
using VectorFn = std::vector<int> (*)(int, int);

struct IntCase {
    const char* name;
    BinaryFn fn;
    int a;
    int b;
    const char* refName;
};

struct I64Case {
    const char* name;
    I64Fn fn;
    int a;
    int b;
    const char* refName;
};

struct U64Case {
    const char* name;
    U64Fn fn;
    int a;
    int b;
    const char* refName;
};

struct BoolCase {
    const char* name;
    BoolFn fn;
    int a;
    int b;
    const char* refName;
};

struct I16Case {
    const char* name;
    I16Fn fn;
    int a;
    int b;
    const char* refName;
};

struct U16Case {
    const char* name;
    U16Fn fn;
    int a;
    int b;
    const char* refName;
};

struct I8Case {
    const char* name;
    I8Fn fn;
    int a;
    int b;
    const char* refName;
};

struct CstrCase {
    const char* name;
    CstrFn fn;
    int a;
    int b;
    const char* refName;
};

struct StringCase {
    const char* name;
    StringFn fn;
    int a;
    int b;
    const char* refName;
};

struct VectorCase {
    const char* name;
    VectorFn fn;
    int a;
    int b;
    const char* refName;
};

template <typename Fn>
Fn resolveRefSymbol(const char* symbolName) {
    void* symbol = dlsym(RTLD_DEFAULT, symbolName);
    if (symbol == nullptr) {
        __android_log_print(
            ANDROID_LOG_ERROR,
            kLogTag,
            "resolve ref symbol failed: %s",
            symbolName ? symbolName : "(null)");
        return nullptr;
    }
    return reinterpret_cast<Fn>(symbol);
}

std::string makeSafeString(const char* value) {
    if (value == nullptr) {
        return "(null)";
    }
    return std::string(value);
}

std::string formatShortText(const std::string& value) {
    if (value.size() <= 14) {
        return value;
    }
    return value.substr(0, 11) + "...";
}

std::string formatVectorDigest(const std::vector<int>& values) {
    long long sum = 0;
    int xorValue = 0;
    for (int value : values) {
        sum += static_cast<long long>(value);
        xorValue ^= value;
    }
    std::ostringstream oss;
    oss << "n=" << values.size() << ",s=" << sum << ",x=" << xorValue;
    if (!values.empty()) {
        oss << ",f=" << values.front() << ",l=" << values.back();
    }
    return oss.str();
}

bool appendIntCaseResult(std::ostringstream& oss, const IntCase& c) {
    BinaryFn refFn = resolveRefSymbol<BinaryFn>(c.refName);
    if (refFn == nullptr) {
        oss << std::left << std::setw(26) << c.name
            << std::right << std::setw(18) << "N/A"
            << std::setw(18) << "N/A"
            << std::setw(10) << "FAIL" << "\n";
        return false;
    }
    const int expected = refFn(c.a, c.b);
    const int value = c.fn(c.a, c.b);
    const bool pass = (value == expected);
    oss << std::left << std::setw(26) << c.name
        << std::right << std::setw(18) << expected
        << std::setw(18) << value
        << std::setw(10) << (pass ? "PASS" : "FAIL") << "\n";
    __android_log_print(
        ANDROID_LOG_INFO,
        kLogTag,
        "%s(%d,%d) expected=%d actual=%d status=%s",
        c.name,
        c.a,
        c.b,
        expected,
        value,
        pass ? "PASS" : "FAIL");
    return pass;
}

bool appendI64CaseResult(std::ostringstream& oss, const I64Case& c) {
    I64Fn refFn = resolveRefSymbol<I64Fn>(c.refName);
    if (refFn == nullptr) {
        oss << std::left << std::setw(26) << c.name
            << std::right << std::setw(18) << "N/A"
            << std::setw(18) << "N/A"
            << std::setw(10) << "FAIL" << "\n";
        return false;
    }
    const long long expected = refFn(c.a, c.b);
    const long long value = c.fn(c.a, c.b);
    const bool pass = (value == expected);
    oss << std::left << std::setw(26) << c.name
        << std::right << std::setw(18) << expected
        << std::setw(18) << value
        << std::setw(10) << (pass ? "PASS" : "FAIL") << "\n";
    __android_log_print(
        ANDROID_LOG_INFO,
        kLogTag,
        "%s(%d,%d) expected=%lld actual=%lld status=%s",
        c.name,
        c.a,
        c.b,
        expected,
        value,
        pass ? "PASS" : "FAIL");
    return pass;
}

bool appendU64CaseResult(std::ostringstream& oss, const U64Case& c) {
    U64Fn refFn = resolveRefSymbol<U64Fn>(c.refName);
    if (refFn == nullptr) {
        oss << std::left << std::setw(26) << c.name
            << std::right << std::setw(18) << "N/A"
            << std::setw(18) << "N/A"
            << std::setw(10) << "FAIL" << "\n";
        return false;
    }
    const unsigned long long expected = refFn(c.a, c.b);
    const unsigned long long value = c.fn(c.a, c.b);
    const bool pass = (value == expected);
    oss << std::left << std::setw(26) << c.name
        << std::right << std::setw(18) << expected
        << std::setw(18) << value
        << std::setw(10) << (pass ? "PASS" : "FAIL") << "\n";
    __android_log_print(
        ANDROID_LOG_INFO,
        kLogTag,
        "%s(%d,%d) expected=%llu actual=%llu status=%s",
        c.name,
        c.a,
        c.b,
        expected,
        value,
        pass ? "PASS" : "FAIL");
    return pass;
}

bool appendBoolCaseResult(std::ostringstream& oss, const BoolCase& c) {
    BoolFn refFn = resolveRefSymbol<BoolFn>(c.refName);
    if (refFn == nullptr) {
        oss << std::left << std::setw(26) << c.name
            << std::right << std::setw(18) << "N/A"
            << std::setw(18) << "N/A"
            << std::setw(10) << "FAIL" << "\n";
        return false;
    }
    const bool expected = refFn(c.a, c.b);
    const bool value = c.fn(c.a, c.b);
    const bool pass = (value == expected);
    oss << std::left << std::setw(26) << c.name
        << std::right << std::setw(18) << (expected ? 1 : 0)
        << std::setw(18) << (value ? 1 : 0)
        << std::setw(10) << (pass ? "PASS" : "FAIL") << "\n";
    __android_log_print(
        ANDROID_LOG_INFO,
        kLogTag,
        "%s(%d,%d) expected=%d actual=%d status=%s",
        c.name,
        c.a,
        c.b,
        expected ? 1 : 0,
        value ? 1 : 0,
        pass ? "PASS" : "FAIL");
    return pass;
}

bool appendI16CaseResult(std::ostringstream& oss, const I16Case& c) {
    I16Fn refFn = resolveRefSymbol<I16Fn>(c.refName);
    if (refFn == nullptr) {
        oss << std::left << std::setw(26) << c.name
            << std::right << std::setw(18) << "N/A"
            << std::setw(18) << "N/A"
            << std::setw(10) << "FAIL" << "\n";
        return false;
    }
    const short expected = refFn(c.a, c.b);
    const short value = c.fn(c.a, c.b);
    const bool pass = (value == expected);
    oss << std::left << std::setw(26) << c.name
        << std::right << std::setw(18) << expected
        << std::setw(18) << value
        << std::setw(10) << (pass ? "PASS" : "FAIL") << "\n";
    __android_log_print(
        ANDROID_LOG_INFO,
        kLogTag,
        "%s(%d,%d) expected=%d actual=%d status=%s",
        c.name,
        c.a,
        c.b,
        static_cast<int>(expected),
        static_cast<int>(value),
        pass ? "PASS" : "FAIL");
    return pass;
}

bool appendU16CaseResult(std::ostringstream& oss, const U16Case& c) {
    U16Fn refFn = resolveRefSymbol<U16Fn>(c.refName);
    if (refFn == nullptr) {
        oss << std::left << std::setw(26) << c.name
            << std::right << std::setw(18) << "N/A"
            << std::setw(18) << "N/A"
            << std::setw(10) << "FAIL" << "\n";
        return false;
    }
    const unsigned short expected = refFn(c.a, c.b);
    const unsigned short value = c.fn(c.a, c.b);
    const bool pass = (value == expected);
    oss << std::left << std::setw(26) << c.name
        << std::right << std::setw(18) << static_cast<unsigned int>(expected)
        << std::setw(18) << static_cast<unsigned int>(value)
        << std::setw(10) << (pass ? "PASS" : "FAIL") << "\n";
    __android_log_print(
        ANDROID_LOG_INFO,
        kLogTag,
        "%s(%d,%d) expected=%u actual=%u status=%s",
        c.name,
        c.a,
        c.b,
        static_cast<unsigned int>(expected),
        static_cast<unsigned int>(value),
        pass ? "PASS" : "FAIL");
    return pass;
}

bool appendI8CaseResult(std::ostringstream& oss, const I8Case& c) {
    I8Fn refFn = resolveRefSymbol<I8Fn>(c.refName);
    if (refFn == nullptr) {
        oss << std::left << std::setw(26) << c.name
            << std::right << std::setw(18) << "N/A"
            << std::setw(18) << "N/A"
            << std::setw(10) << "FAIL" << "\n";
        return false;
    }
    const signed char expected = refFn(c.a, c.b);
    const signed char value = c.fn(c.a, c.b);
    const bool pass = (value == expected);
    oss << std::left << std::setw(26) << c.name
        << std::right << std::setw(18) << static_cast<int>(expected)
        << std::setw(18) << static_cast<int>(value)
        << std::setw(10) << (pass ? "PASS" : "FAIL") << "\n";
    __android_log_print(
        ANDROID_LOG_INFO,
        kLogTag,
        "%s(%d,%d) expected=%d actual=%d status=%s",
        c.name,
        c.a,
        c.b,
        static_cast<int>(expected),
        static_cast<int>(value),
        pass ? "PASS" : "FAIL");
    return pass;
}

bool appendCstrCaseResult(std::ostringstream& oss, const CstrCase& c) {
    CstrFn refFn = resolveRefSymbol<CstrFn>(c.refName);
    if (refFn == nullptr) {
        oss << std::left << std::setw(26) << c.name
            << std::right << std::setw(18) << "N/A"
            << std::setw(18) << "N/A"
            << std::setw(10) << "FAIL" << "\n";
        return false;
    }
    const std::string expected = makeSafeString(refFn(c.a, c.b));
    const std::string value = makeSafeString(c.fn(c.a, c.b));
    const bool pass = (value == expected);
    oss << std::left << std::setw(26) << c.name
        << std::right << std::setw(18) << formatShortText(expected)
        << std::setw(18) << formatShortText(value)
        << std::setw(10) << (pass ? "PASS" : "FAIL") << "\n";
    __android_log_print(
        ANDROID_LOG_INFO,
        kLogTag,
        "%s(%d,%d) expected=%s actual=%s status=%s",
        c.name,
        c.a,
        c.b,
        expected.c_str(),
        value.c_str(),
        pass ? "PASS" : "FAIL");
    return pass;
}

bool appendStringCaseResult(std::ostringstream& oss, const StringCase& c) {
    StringFn refFn = resolveRefSymbol<StringFn>(c.refName);
    if (refFn == nullptr) {
        oss << std::left << std::setw(26) << c.name
            << std::right << std::setw(18) << "N/A"
            << std::setw(18) << "N/A"
            << std::setw(10) << "FAIL" << "\n";
        return false;
    }
    const std::string expected = refFn(c.a, c.b);
    const std::string value = c.fn(c.a, c.b);
    const bool pass = (value == expected);
    oss << std::left << std::setw(26) << c.name
        << std::right << std::setw(18) << formatShortText(expected)
        << std::setw(18) << formatShortText(value)
        << std::setw(10) << (pass ? "PASS" : "FAIL") << "\n";
    __android_log_print(
        ANDROID_LOG_INFO,
        kLogTag,
        "%s(%d,%d) expected=%s actual=%s status=%s",
        c.name,
        c.a,
        c.b,
        expected.c_str(),
        value.c_str(),
        pass ? "PASS" : "FAIL");
    return pass;
}

bool appendVectorCaseResult(std::ostringstream& oss, const VectorCase& c) {
    VectorFn refFn = resolveRefSymbol<VectorFn>(c.refName);
    if (refFn == nullptr) {
        oss << std::left << std::setw(26) << c.name
            << std::right << std::setw(18) << "N/A"
            << std::setw(18) << "N/A"
            << std::setw(10) << "FAIL" << "\n";
        return false;
    }
    const std::vector<int> expected = refFn(c.a, c.b);
    const std::vector<int> value = c.fn(c.a, c.b);
    const bool pass = (value == expected);
    const std::string expectedDigest = formatVectorDigest(expected);
    const std::string valueDigest = formatVectorDigest(value);
    oss << std::left << std::setw(26) << c.name
        << std::right << std::setw(18) << formatShortText(expectedDigest)
        << std::setw(18) << formatShortText(valueDigest)
        << std::setw(10) << (pass ? "PASS" : "FAIL") << "\n";
    __android_log_print(
        ANDROID_LOG_INFO,
        kLogTag,
        "%s(%d,%d) expected=%s actual=%s status=%s",
        c.name,
        c.a,
        c.b,
        expectedDigest.c_str(),
        valueDigest.c_str(),
        pass ? "PASS" : "FAIL");
    return pass;
}

std::string buildProtectResultText() {
    std::ostringstream oss;
    oss << "demo protect results\n";
    oss << std::left << std::setw(26) << "function"
        << std::right << std::setw(18) << "expected"
        << std::setw(18) << "actual"
        << std::setw(10) << "status" << "\n";
    oss << "----------------------------------------------------------------------\n";

    const std::vector<IntCase> cases = {
        {"fun_add", fun_add, 2, 4, "fun_add_ref"},
        {"fun_for", fun_for, 2, 4, "fun_for_ref"},
        {"fun_for_add", fun_for_add, 2, 4, "fun_for_add_ref"},
        {"fun_if_sub", fun_if_sub, 2, 4, "fun_if_sub_ref"},
        {"fun_countdown_muladd", fun_countdown_muladd, 2, 4, "fun_countdown_muladd_ref"},
        {"fun_loop_call_mix", fun_loop_call_mix, 2, 4, "fun_loop_call_mix_ref"},
        {"fun_call_chain", fun_call_chain, 2, 4, "fun_call_chain_ref"},
        {"fun_branch_call", fun_branch_call, 2, 4, "fun_branch_call_ref"},
        {"fun_cpp_string_len", fun_cpp_string_len, 2, 4, "fun_cpp_string_len_ref"},
        {"fun_cpp_vector_sum", fun_cpp_vector_sum, 2, 4, "fun_cpp_vector_sum_ref"},
        {"fun_cpp_virtual_mix", fun_cpp_virtual_mix, 2, 4, "fun_cpp_virtual_mix_ref"},
        {"fun_div_mod_chain", fun_div_mod_chain, 2, 4, "fun_div_mod_chain_ref"},
        {"fun_shift_mix", fun_shift_mix, 2, 4, "fun_shift_mix_ref"},
        {"fun_do_while_path", fun_do_while_path, 2, 4, "fun_do_while_path_ref"},
        {"fun_nested_continue_break", fun_nested_continue_break, 2, 4, "fun_nested_continue_break_ref"},
        {"fun_indirect_call_mix", fun_indirect_call_mix, 2, 4, "fun_indirect_call_mix_ref"},
        {"fun_unsigned_compare_fold", fun_unsigned_compare_fold, 2, 4, "fun_unsigned_compare_fold_ref"},
        {"fun_local_array_walk", fun_local_array_walk, 2, 4, "fun_local_array_walk_ref"},
        {"fun_switch_fallthrough", fun_switch_fallthrough, 2, 4, "fun_switch_fallthrough_ref"},
        {"fun_short_circuit_logic", fun_short_circuit_logic, 2, 4, "fun_short_circuit_logic_ref"},
        {"fun_select_mix", fun_select_mix, 2, 4, "fun_select_mix_ref"},
        {"fun_global_data_mix", fun_global_data_mix, 2, 4, "fun_global_data_mix_ref"},
        {"fun_static_local_table", fun_static_local_table, 2, 4, "fun_static_local_table_ref"},
        {"fun_global_struct_acc", fun_global_struct_acc, 2, 4, "fun_global_struct_acc_ref"},
        {"fun_class_static_member", fun_class_static_member, 2, 4, "fun_class_static_member_ref"},
        {"fun_multi_branch_path", fun_multi_branch_path, 2, 4, "fun_multi_branch_path_ref"},
        {"fun_switch_dispatch", fun_switch_dispatch, 2, 4, "fun_switch_dispatch_ref"},
        {"fun_bitmask_branch", fun_bitmask_branch, 2, 4, "fun_bitmask_branch_ref"},
        {"fun_global_table_rw", fun_global_table_rw, 2, 4, "fun_global_table_rw_ref"},
        {"fun_global_mutable_state", fun_global_mutable_state, 2, 4, "fun_global_mutable_state_ref"},
        {"fun_flag_merge_cbz", fun_flag_merge_cbz, 2, 4, "fun_flag_merge_cbz_ref"},
        {"fun_ptr_stride_sum", fun_ptr_stride_sum, 2, 4, "fun_ptr_stride_sum_ref"},
        {"fun_fn_table_dispatch", fun_fn_table_dispatch, 2, 4, "fun_fn_table_dispatch_ref"},
        {"fun_clamp_window", fun_clamp_window, 2, 4, "fun_clamp_window_ref"},
        {"fun_switch_loop_acc", fun_switch_loop_acc, 2, 4, "fun_switch_loop_acc_ref"},
        {"fun_struct_alias_walk", fun_struct_alias_walk, 2, 4, "fun_struct_alias_walk_ref"},
        {"fun_unsigned_edge_paths", fun_unsigned_edge_paths, 2, 4, "fun_unsigned_edge_paths_ref"},
        {"fun_reverse_ptr_mix", fun_reverse_ptr_mix, 2, 4, "fun_reverse_ptr_mix_ref"},
        {"fun_guarded_chain_mix", fun_guarded_chain_mix, 2, 4, "fun_guarded_chain_mix_ref"},
        {"fun_ext_insn_mix", fun_ext_insn_mix, 2, 4, "fun_ext_insn_mix_ref"},
        {"fun_bfm_nonwrap", fun_bfm_nonwrap, 2, 4, "fun_bfm_nonwrap_ref"},
        {"fun_bfm_wrap", fun_bfm_wrap, 2, 4, "fun_bfm_wrap_ref"},
        {"fun_csinc_path", fun_csinc_path, 2, 4, "fun_csinc_path_ref"},
        {"fun_madd_msub_div", fun_madd_msub_div, 2, 4, "fun_madd_msub_div_ref"},
        {"fun_orn_bic_extr", fun_orn_bic_extr, 2, 4, "fun_orn_bic_extr_ref"},
        {"fun_mem_half_signed", fun_mem_half_signed, 2, 4, "fun_mem_half_signed_ref"},
        {"fun_atomic_u8_order", fun_atomic_u8_order, 2, 4, "fun_atomic_u8_order_ref"},
        {"fun_atomic_u16_order", fun_atomic_u16_order, 2, 4, "fun_atomic_u16_order_ref"},
        {"fun_atomic_u64_order", fun_atomic_u64_order, 2, 4, "fun_atomic_u64_order_ref"},
    };

    const std::vector<I64Case> i64Cases = {
        {"fun_ret_i64_mix", fun_ret_i64_mix, 2, 4, "fun_ret_i64_mix_ref"},
        {"fun_ret_i64_steps", fun_ret_i64_steps, 2, 4, "fun_ret_i64_steps_ref"},
    };

    const std::vector<U64Case> u64Cases = {
        {"fun_ret_u64_mix", fun_ret_u64_mix, 2, 4, "fun_ret_u64_mix_ref"},
        {"fun_ret_u64_acc", fun_ret_u64_acc, 2, 4, "fun_ret_u64_acc_ref"},
    };

    const std::vector<BoolCase> boolCases = {
        {"fun_ret_bool_gate", fun_ret_bool_gate, 2, 4, "fun_ret_bool_gate_ref"},
        {"fun_ret_bool_mix2", fun_ret_bool_mix2, 2, 4, "fun_ret_bool_mix2_ref"},
    };

    const std::vector<I16Case> i16Cases = {
        {"fun_ret_i16_pack", fun_ret_i16_pack, 2, 4, "fun_ret_i16_pack_ref"},
    };

    const std::vector<U16Case> u16Cases = {
        {"fun_ret_u16_blend", fun_ret_u16_blend, 2, 4, "fun_ret_u16_blend_ref"},
    };

    const std::vector<I8Case> i8Cases = {
        {"fun_ret_i8_wave", fun_ret_i8_wave, 2, 4, "fun_ret_i8_wave_ref"},
    };

    const std::vector<CstrCase> cstrCases = {
        {"fun_ret_cstr_pick", fun_ret_cstr_pick, 2, 4, "fun_ret_cstr_pick_ref"},
    };

    const std::vector<StringCase> stringCases = {
        {"fun_cpp_make_string", fun_cpp_make_string, 2, 4, "fun_cpp_make_string_ref"},
        {"fun_ret_std_string_mix", fun_ret_std_string_mix, 2, 4, "fun_ret_std_string_mix_ref"},
    };

    const std::vector<VectorCase> vectorCases = {
        {"fun_ret_vector_mix", fun_ret_vector_mix, 2, 4, "fun_ret_vector_mix_ref"},
    };

    int passCount = 0;
    int totalCount = 0;
    for (const IntCase& c : cases) {
        totalCount += 1;
        if (appendIntCaseResult(oss, c)) {
            passCount += 1;
        }
    }
    for (const I64Case& c : i64Cases) {
        totalCount += 1;
        if (appendI64CaseResult(oss, c)) {
            passCount += 1;
        }
    }
    for (const U64Case& c : u64Cases) {
        totalCount += 1;
        if (appendU64CaseResult(oss, c)) {
            passCount += 1;
        }
    }
    for (const BoolCase& c : boolCases) {
        totalCount += 1;
        if (appendBoolCaseResult(oss, c)) {
            passCount += 1;
        }
    }
    for (const I16Case& c : i16Cases) {
        totalCount += 1;
        if (appendI16CaseResult(oss, c)) {
            passCount += 1;
        }
    }
    for (const U16Case& c : u16Cases) {
        totalCount += 1;
        if (appendU16CaseResult(oss, c)) {
            passCount += 1;
        }
    }
    for (const I8Case& c : i8Cases) {
        totalCount += 1;
        if (appendI8CaseResult(oss, c)) {
            passCount += 1;
        }
    }
    for (const CstrCase& c : cstrCases) {
        totalCount += 1;
        if (appendCstrCaseResult(oss, c)) {
            passCount += 1;
        }
    }
    for (const StringCase& c : stringCases) {
        totalCount += 1;
        if (appendStringCaseResult(oss, c)) {
            passCount += 1;
        }
    }
    for (const VectorCase& c : vectorCases) {
        totalCount += 1;
        if (appendVectorCaseResult(oss, c)) {
            passCount += 1;
        }
    }
    oss << "----------------------------------------------------------------------\n";
    oss << "summary: " << passCount << "/" << totalCount << " PASS\n";
    return oss.str();
}

} // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_demo_MainActivity_getProtectResults(JNIEnv* env, jobject /*thiz*/) {
    const std::string resultText = buildProtectResultText();
    return env->NewStringUTF(resultText.c_str());
}
