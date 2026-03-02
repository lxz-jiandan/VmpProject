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

// 设计说明（bridge 层）：
// 1) 本文件不是业务逻辑实现，而是“回归执行器 + 结果聚合器”。
// 2) 输入侧：固定 case 表定义了函数名、参数和 ref 符号名。
// 3) 执行侧：每个 append*CaseResult 负责一个返回类型分组。
// 4) 校验侧：通过 dlsym(RTLD_DEFAULT, *_ref) 获取未加固对照实现。
// 5) 比较侧：按 expected/actual/status 三列输出统一格式文本。
// 6) 可读性：结果表宽度固定，便于终端与 UI 两端直接阅读。
// 7) 可定位性：每个用例同时输出表格行与 logcat 诊断日志。
// 8) 稳定性：单用例失败不短路，最终 summary 反映全量通过率。
// 9) 分层边界：JNI 入口只做字符串返回，不承载校验逻辑。
// 10) 维护策略：新增 fun_* 时，应在 case 表中同步补 entry。
// 11) 异常策略：ref 符号解析失败时写 N/A，避免中断整批回归。
// 12) 类型策略：整数/布尔/字符串/容器分组处理，减少 ABI 混淆。
// 13) 字符串策略：长文本做摘要，既保留信息又防止版面污染。
// 14) 容器策略：vector 输出摘要而非原文，降低日志体积。
// 15) 核心目标：快速判断“加固版本是否与对照版本语义等价”。
// 16) 演进策略：新增返回类型时，优先新增 appendXxxCaseResult 保持结构对称。
// 17) 对照策略：case 中的 refName 与符号映射显式写死，避免隐式约定失效。
// 18) 诊断策略：文本结果服务人工浏览，logcat 结果服务快速二分定位。
// 19) 可测性：所有关键路径都可通过固定参数重复触发，不依赖随机输入。
// 20) 该层只做“组织与比较”，不替代离线系统对翻译正确性的根因分析。

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

// [VMP_BRIDGE_FUNC] std::string makeSafeString(const char* value)
// - 覆盖点：统一处理空指针字符串，避免桥接展示层出现崩溃或未定义行为。
// - 实现思路：把 nullptr 映射为占位文本，确保后续比较与日志输出稳定。
// - 输入约束：仅做格式层处理，不引入业务语义分支。
// - 输出约束：输出保持可打印且长度可控，避免污染结果表结构。
// - 失败处理：该层不抛异常，尽量返回可比较的兜底文本。
// - 定位方式：所有上层 append* 都复用这些函数，便于统一行为。
// - 设计取舍：优先保证可读摘要，而不是保留完整原始文本。
std::string makeSafeString(const char* value) {
    if (value == nullptr) {
        return "(null)";
    }
    return std::string(value);
}

// [VMP_BRIDGE_FUNC] std::string formatShortText(const std::string& value)
// - 覆盖点：限制展示列宽，保证长文本不会破坏结果表格对齐。
// - 实现思路：超过阈值时截断并追加省略号，保留可读摘要用于比对。
// - 输入约束：仅做格式层处理，不引入业务语义分支。
// - 输出约束：输出保持可打印且长度可控，避免污染结果表结构。
// - 失败处理：该层不抛异常，尽量返回可比较的兜底文本。
// - 定位方式：所有上层 append* 都复用这些函数，便于统一行为。
// - 设计取舍：优先保证可读摘要，而不是保留完整原始文本。
std::string formatShortText(const std::string& value) {
    if (value.size() <= 14) {
        return value;
    }
    return value.substr(0, 11) + "...";
}

// [VMP_BRIDGE_FUNC] std::string formatVectorDigest(const std::vector<int>& values)
// - 覆盖点：将 vector 结果压缩为摘要，避免直接打印大数组造成噪声。
// - 实现思路：提取长度、求和、xor、首尾元素，兼顾信息量与可读性。
// - 输入约束：仅做格式层处理，不引入业务语义分支。
// - 输出约束：输出保持可打印且长度可控，避免污染结果表结构。
// - 失败处理：该层不抛异常，尽量返回可比较的兜底文本。
// - 定位方式：所有上层 append* 都复用这些函数，便于统一行为。
// - 设计取舍：优先保证可读摘要，而不是保留完整原始文本。
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

// [VMP_BRIDGE_FUNC] bool appendIntCaseResult(std::ostringstream& oss, const IntCase& c)
// - 覆盖点：执行单个类型用例的 expected/actual 对比，并输出统一格式行。
// - 实现思路：先通过 dlsym 获取 *_ref 基线，再调用被测函数并记录 PASS/FAIL。
// - 输入约束：参数来自固定 case 表，避免 JNI 层注入不稳定输入形态。
// - 失败处理：若 *_ref 解析失败则写入 N/A 并返回 false，但不中断总流程。
// - 定位方式：同时写表格行与 logcat，便于按函数名精确定位偏差来源。
// - 稳定性：表格列宽固定，确保文本结果可直接用于回归比对。
// - 设计取舍：每种返回类型独立处理，减少模板分支带来的可读性负担。
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

// [VMP_BRIDGE_FUNC] bool appendI64CaseResult(std::ostringstream& oss, const I64Case& c)
// - 覆盖点：执行单个类型用例的 expected/actual 对比，并输出统一格式行。
// - 实现思路：先通过 dlsym 获取 *_ref 基线，再调用被测函数并记录 PASS/FAIL。
// - 输入约束：参数来自固定 case 表，避免 JNI 层注入不稳定输入形态。
// - 失败处理：若 *_ref 解析失败则写入 N/A 并返回 false，但不中断总流程。
// - 定位方式：同时写表格行与 logcat，便于按函数名精确定位偏差来源。
// - 稳定性：表格列宽固定，确保文本结果可直接用于回归比对。
// - 设计取舍：每种返回类型独立处理，减少模板分支带来的可读性负担。
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

// [VMP_BRIDGE_FUNC] bool appendU64CaseResult(std::ostringstream& oss, const U64Case& c)
// - 覆盖点：执行单个类型用例的 expected/actual 对比，并输出统一格式行。
// - 实现思路：先通过 dlsym 获取 *_ref 基线，再调用被测函数并记录 PASS/FAIL。
// - 输入约束：参数来自固定 case 表，避免 JNI 层注入不稳定输入形态。
// - 失败处理：若 *_ref 解析失败则写入 N/A 并返回 false，但不中断总流程。
// - 定位方式：同时写表格行与 logcat，便于按函数名精确定位偏差来源。
// - 稳定性：表格列宽固定，确保文本结果可直接用于回归比对。
// - 设计取舍：每种返回类型独立处理，减少模板分支带来的可读性负担。
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

// [VMP_BRIDGE_FUNC] bool appendBoolCaseResult(std::ostringstream& oss, const BoolCase& c)
// - 覆盖点：执行单个类型用例的 expected/actual 对比，并输出统一格式行。
// - 实现思路：先通过 dlsym 获取 *_ref 基线，再调用被测函数并记录 PASS/FAIL。
// - 输入约束：参数来自固定 case 表，避免 JNI 层注入不稳定输入形态。
// - 失败处理：若 *_ref 解析失败则写入 N/A 并返回 false，但不中断总流程。
// - 定位方式：同时写表格行与 logcat，便于按函数名精确定位偏差来源。
// - 稳定性：表格列宽固定，确保文本结果可直接用于回归比对。
// - 设计取舍：每种返回类型独立处理，减少模板分支带来的可读性负担。
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

// [VMP_BRIDGE_FUNC] bool appendI16CaseResult(std::ostringstream& oss, const I16Case& c)
// - 覆盖点：执行单个类型用例的 expected/actual 对比，并输出统一格式行。
// - 实现思路：先通过 dlsym 获取 *_ref 基线，再调用被测函数并记录 PASS/FAIL。
// - 输入约束：参数来自固定 case 表，避免 JNI 层注入不稳定输入形态。
// - 失败处理：若 *_ref 解析失败则写入 N/A 并返回 false，但不中断总流程。
// - 定位方式：同时写表格行与 logcat，便于按函数名精确定位偏差来源。
// - 稳定性：表格列宽固定，确保文本结果可直接用于回归比对。
// - 设计取舍：每种返回类型独立处理，减少模板分支带来的可读性负担。
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

// [VMP_BRIDGE_FUNC] bool appendU16CaseResult(std::ostringstream& oss, const U16Case& c)
// - 覆盖点：执行单个类型用例的 expected/actual 对比，并输出统一格式行。
// - 实现思路：先通过 dlsym 获取 *_ref 基线，再调用被测函数并记录 PASS/FAIL。
// - 输入约束：参数来自固定 case 表，避免 JNI 层注入不稳定输入形态。
// - 失败处理：若 *_ref 解析失败则写入 N/A 并返回 false，但不中断总流程。
// - 定位方式：同时写表格行与 logcat，便于按函数名精确定位偏差来源。
// - 稳定性：表格列宽固定，确保文本结果可直接用于回归比对。
// - 设计取舍：每种返回类型独立处理，减少模板分支带来的可读性负担。
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

// [VMP_BRIDGE_FUNC] bool appendI8CaseResult(std::ostringstream& oss, const I8Case& c)
// - 覆盖点：执行单个类型用例的 expected/actual 对比，并输出统一格式行。
// - 实现思路：先通过 dlsym 获取 *_ref 基线，再调用被测函数并记录 PASS/FAIL。
// - 输入约束：参数来自固定 case 表，避免 JNI 层注入不稳定输入形态。
// - 失败处理：若 *_ref 解析失败则写入 N/A 并返回 false，但不中断总流程。
// - 定位方式：同时写表格行与 logcat，便于按函数名精确定位偏差来源。
// - 稳定性：表格列宽固定，确保文本结果可直接用于回归比对。
// - 设计取舍：每种返回类型独立处理，减少模板分支带来的可读性负担。
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

// [VMP_BRIDGE_FUNC] bool appendCstrCaseResult(std::ostringstream& oss, const CstrCase& c)
// - 覆盖点：执行单个类型用例的 expected/actual 对比，并输出统一格式行。
// - 实现思路：先通过 dlsym 获取 *_ref 基线，再调用被测函数并记录 PASS/FAIL。
// - 输入约束：参数来自固定 case 表，避免 JNI 层注入不稳定输入形态。
// - 失败处理：若 *_ref 解析失败则写入 N/A 并返回 false，但不中断总流程。
// - 定位方式：同时写表格行与 logcat，便于按函数名精确定位偏差来源。
// - 稳定性：表格列宽固定，确保文本结果可直接用于回归比对。
// - 设计取舍：每种返回类型独立处理，减少模板分支带来的可读性负担。
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

// [VMP_BRIDGE_FUNC] bool appendStringCaseResult(std::ostringstream& oss, const StringCase& c)
// - 覆盖点：执行单个类型用例的 expected/actual 对比，并输出统一格式行。
// - 实现思路：先通过 dlsym 获取 *_ref 基线，再调用被测函数并记录 PASS/FAIL。
// - 输入约束：参数来自固定 case 表，避免 JNI 层注入不稳定输入形态。
// - 失败处理：若 *_ref 解析失败则写入 N/A 并返回 false，但不中断总流程。
// - 定位方式：同时写表格行与 logcat，便于按函数名精确定位偏差来源。
// - 稳定性：表格列宽固定，确保文本结果可直接用于回归比对。
// - 设计取舍：每种返回类型独立处理，减少模板分支带来的可读性负担。
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

// [VMP_BRIDGE_FUNC] bool appendVectorCaseResult(std::ostringstream& oss, const VectorCase& c)
// - 覆盖点：执行单个类型用例的 expected/actual 对比，并输出统一格式行。
// - 实现思路：先通过 dlsym 获取 *_ref 基线，再调用被测函数并记录 PASS/FAIL。
// - 输入约束：参数来自固定 case 表，避免 JNI 层注入不稳定输入形态。
// - 失败处理：若 *_ref 解析失败则写入 N/A 并返回 false，但不中断总流程。
// - 定位方式：同时写表格行与 logcat，便于按函数名精确定位偏差来源。
// - 稳定性：表格列宽固定，确保文本结果可直接用于回归比对。
// - 设计取舍：每种返回类型独立处理，减少模板分支带来的可读性负担。
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

// [VMP_BRIDGE_FUNC] std::string buildProtectResultText()
// - 覆盖点：统一编排所有用例执行与汇总，形成可直接展示的回归报表。
// - 实现思路：按类型分组迭代 append*CaseResult，最终输出 PASS 统计。
// - 输入约束：用例清单在函数内显式定义，保证执行顺序与输出顺序稳定。
// - 输出约束：统一 expected/actual/status 三列，便于人工和脚本双重读取。
// - 失败处理：单用例失败不会短路，最终以 summary 呈现全量通过率。
// - 定位方式：按类型分组执行，能快速缩小到具体 ABI 或指令分组。
// - 设计取舍：可读性优先，接受少量重复代码换取调试效率。
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
        {"fun_insn_scalar_ctrl", fun_insn_scalar_ctrl, 2, 4, "fun_insn_scalar_ctrl_ref"},
        {"fun_insn_simd_mix", fun_insn_simd_mix, 2, 4, "fun_insn_simd_mix_ref"},
        {"fun_insn_fp_convert", fun_insn_fp_convert, 2, 4, "fun_insn_fp_convert_ref"},
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
// [VMP_BRIDGE_FUNC] Java_com_example_demo_MainActivity_getProtectResults(JNIEnv* env, jobject /*thiz*/)
// - 覆盖点：提供 JNI 入口，把 native 侧比对结果返回给 Java 界面层。
// - 实现思路：调用汇总函数构造文本，再通过 NewStringUTF 回传。
// - 输入约束：JNI 层不接收外部参数，确保展示文本由 native 内部完全决定。
// - 输出约束：始终返回 UTF-8 字符串，供 UI 层直接显示。
// - 失败处理：若内部比较失败也返回文本结果，不在 JNI 层抛异常。
// - 定位方式：Java 仅负责展示，问题定位仍回到 native 报表与日志。
// - 设计取舍：保持 JNI 入口极薄，减少跨层维护成本。
Java_com_example_demo_MainActivity_getProtectResults(JNIEnv* env, jobject /*thiz*/) {
    const std::string resultText = buildProtectResultText();
    return env->NewStringUTF(resultText.c_str());
}
